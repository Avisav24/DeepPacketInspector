# DPI Engine - Deep Packet Inspection System (Java)

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

> The engine is implemented in **Java** (see [`java_dpi/`](java_dpi/)). It reads PCAP files (or sniffs a live interface via Npcap), classifies traffic using TLS SNI / HTTP Host / DNS / QUIC inspection, applies blocking rules, and writes the filtered traffic to an output PCAP.

---
## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Single-threaded)](#5-the-journey-of-a-packet-single-threaded)
6. [The Journey of a Packet (Multi-threaded)](#6-the-journey-of-a-packet-multi-threaded)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP or live interface) → [DPI Engine] → Filtered Traffic (PCAP)
                                             ↓
                                      - Identifies apps (YouTube, Facebook, etc.)
                                      - Blocks based on rules
                                      - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
      or            │ - Block     │
┌─────────────┐     │ - Report    │
│ Live NIC    │ ──► └─────────────┘
│ (-i "Wi-Fi")│
└─────────────┘
```

### Two Pipelines

| Pipeline | Entry Point | Use Case |
|----------|-------------|----------|
| Single-threaded (default) | `Main.java` | Learning, small captures, live sniffing |
| Multi-threaded (`--mt` flag) | `engine/DPIEngine.java` | Production, large captures |

Both pipelines share the same components (`PcapReader`, `PacketParser`, `SNIExtractor`, `RuleManager`); the multi-threaded engine adds load balancers, fast-path worker threads, and a dedicated output writer.

### Input Modes

| Mode | How | Requirement |
|------|-----|-------------|
| Offline PCAP | `java -jar dpi.jar input.pcap output.pcap` | None (pure Java parser) |
| Live sniffing | `java -jar dpi.jar -i "Wi-Fi"` | Npcap driver + pcap4j (bundled by Maven) |

---

## 4. File Structure

```
Packet_analyzer/
├── README.md                          # This file
├── WINDOWS_SETUP.md                   # Windows install guide (JDK, Maven, Npcap)
├── generate_test_pcap.py              # Python utility that creates test data
├── test_dpi.pcap                      # Sample capture with various traffic
└── java_dpi/
    ├── pom.xml                        # Maven build (produces target/dpi.jar)
    ├── build.bat                      # Plain-javac build (produces out/dpi.jar)
    ├── README.md                      # Quick-start for the Java module
    └── src/main/java/com/dpi/
        ├── Main.java                  # ★ CLI entry point (single-threaded pipeline) ★
        ├── types/
        │   ├── AppType.java           # App enum + SNI → app classification
        │   ├── FiveTuple.java         # Flow identifier (src/dst IP+port+protocol)
        │   ├── Connection.java        # Per-flow connection state
        │   ├── PacketJob.java         # Packet wrapper for the MT pipeline
        │   ├── DPIStats.java          # AtomicLong statistics counters
        │   ├── ConnectionState.java   # NEW/ESTABLISHED/CLASSIFIED/BLOCKED/CLOSED
        │   └── PacketAction.java      # FORWARD/DROP/INSPECT/LOG_ONLY
        ├── pcap/
        │   ├── PcapReader.java        # PCAP file reader/writer (no native library)
        │   ├── LivePcapReader.java    # Live capture via pcap4j/Npcap
        │   └── RawPacket.java         # Raw packet data holder
        ├── parser/
        │   ├── PacketParser.java      # Ethernet/IP/TCP/UDP header parser
        │   └── ParsedPacket.java      # Parsed packet result
        ├── extractor/
        │   ├── SNIExtractor.java      # TLS Client Hello SNI extraction
        │   ├── HTTPHostExtractor.java # HTTP Host header extraction
        │   ├── DNSExtractor.java      # DNS query domain extraction
        │   └── QUICSNIExtractor.java  # QUIC Initial packet SNI extraction
        ├── tracker/
        │   ├── ConnectionTracker.java # Per-worker flow table
        │   └── GlobalConnectionTable.java # Aggregated stats from all workers
        ├── rules/
        │   └── RuleManager.java       # Thread-safe IP/App/Domain/Port rules
        └── engine/
            ├── DPIEngine.java         # ★ MULTI-THREADED ORCHESTRATOR ★
            ├── FastPathProcessor.java # DPI worker thread
            ├── LoadBalancer.java      # Consistent-hash packet distributor
            └── ThreadSafeQueue.java   # Bounded blocking queue
```

---

## 5. The Journey of a Packet (Single-threaded)

Let's trace a single packet through `Main.java`:

### Step 1: Read PCAP File

```java
PcapReader reader = new PcapReader();
reader.open("capture.pcap");
```

**What happens:**
1. Open the file as a stream
2. Read the 24-byte global header (magic number, version, etc.)
3. Detect endianness from the magic number and verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```java
RawPacket raw = new RawPacket();
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw header fields contain timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = included length)
3. Return `false` when no more packets (EOF)

### Step 3: Parse Protocol Headers

```java
ParsedPacket parsed = PacketParser.parse(raw);
```

**What happens (in `PacketParser.java`):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.srcIp    = "192.168.1.100"
parsed.dstIp    = "172.217.14.206"
parsed.srcPort  = 54321
parsed.dstPort  = 443
parsed.protocol = 6 (TCP)
parsed.hasTcp   = true
parsed.payloadOffset / payloadLength → where the application data lives
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4, 0x86DD = IPv6)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

*Network Byte Order:* Network protocols use big-endian (most significant byte first). The parser reads multi-byte fields manually, e.g.:
```java
int port = ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
```

### Step 4: Create Five-Tuple and Look Up Flow

```java
FiveTuple tuple = new FiveTuple(
        parsed.srcIpBytes, parsed.dstIpBytes,
        parsed.srcPort, parsed.dstPort, parsed.protocol);

Flow flow = flows.computeIfAbsent(tuple, t -> new Flow(t));
```

**What happens:**
- The flow table is a `HashMap<FiveTuple, Flow>`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```java
// For HTTPS traffic (port 443)
if (parsed.hasTcp && parsed.dstPort == 443 && parsed.payloadLength > 5) {
    Optional<String> sni = SNIExtractor.extract(
            raw.data, parsed.payloadOffset, parsed.payloadLength);
    if (sni.isPresent()) {
        flow.sni     = sni.get();                 // "www.youtube.com"
        flow.appType = AppType.fromSNI(flow.sni); // AppType.YOUTUBE
    }
}
```

**What happens (in `SNIExtractor.java`):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```java
   // In AppType.java
   public static AppType fromSNI(String sni) {
       String s = sni.toLowerCase(Locale.ROOT);
       if (s.contains("youtube")) return YOUTUBE;
       if (s.contains("facebook")) return FACEBOOK;
       // ... more patterns
   }
   ```

The same step runs `HTTPHostExtractor` on port 80 traffic (looking for the `Host:` header), classifies port 53 traffic as DNS, and falls back to port-based classification (443 → HTTPS, 80 → HTTP).

### Step 6: Check Blocking Rules

```java
flow.blocked = isBlocked(tuple.srcIp, flow.appType, flow.sni,
        blockedIPs, blockedApps, blockedDomains);
```

**What happens:**
```java
// Check IP blacklist
if (blockedIPs.contains(FiveTuple.ipToString(srcIp))) return true;

// Check app blacklist
if (blockedApps.contains(app)) return true;

// Check domain blacklist (substring match)
String lowerSNI = sni.toLowerCase(Locale.ROOT);
for (String domain : blockedDomains) {
    if (lowerSNI.contains(domain)) return true;
}

return false;
```

### Step 7: Forward or Drop

```java
if (flow.blocked) {
    dropped++;
    // Don't write to output
} else {
    forwarded++;
    PcapReader.writePacket(outputStream, raw);
}
```

### Step 8: Generate Report

After processing all packets, the engine prints total/forwarded/dropped counts, an application breakdown with percentage bars, and the list of detected SNIs/domains (see [Section 11](#11-understanding-the-output)).

---

## 6. The Journey of a Packet (Multi-threaded)

The multi-threaded engine (`DPIEngine.java`, enabled with `--mt`) adds **parallelism** for high performance:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):          hash → FP2
Packet 2 (SYN-ACK):      hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):         hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader Thread (in `DPIEngine`)

```java
while (reader.readNextPacket(raw)) {
    PacketJob job = new PacketJob(raw /* + parsed five-tuple */);

    // Hash to select Load Balancer
    int lbIdx = Math.abs(job.tuple.hashCode()) % lbs.size();

    // Push to LB's queue
    lbs.get(lbIdx).getInputQueue().push(job);
}
```

#### Step 2: Load Balancer Thread (`LoadBalancer.java`)

```java
public void run() {
    while (running) {
        PacketJob job = inputQueue.pop(100);
        if (job == null) continue;

        // Hash to select Fast Path (consistent per flow)
        int fpIdx = Math.abs(job.tuple.hashCode()) % fpQueues.size();
        fpQueues.get(fpIdx).push(job);
    }
}
```

#### Step 3: Fast Path Thread (`FastPathProcessor.java`)

```java
public void run() {
    while (running) {
        PacketJob job = inputQueue.pop(100);
        if (job == null) continue;

        // Look up flow (each FP has its own ConnectionTracker)
        Connection conn = tracker.getOrCreate(job.tuple);

        // Classify (SNI/Host/DNS/QUIC extraction)
        classify(job, conn);

        // Check rules
        if (ruleManager.isBlocked(job.tuple, conn.appType, conn.sni)) {
            stats.dropped.incrementAndGet();
        } else {
            outputHandler.accept(job);   // → output queue
        }
    }
}
```

#### Step 4: Output Writer Thread (in `DPIEngine`)

```java
private void outputThreadFunc() {
    while (running.get() || !outputQueue.isEmpty()) {
        PacketJob job = outputQueue.pop(100);
        if (job != null) {
            PcapReader.writePacket(outputStream, job.raw);
        }
    }
}
```

### Thread-Safe Queue

The glue that makes multi-threading work (`ThreadSafeQueue.java`):

```java
public class ThreadSafeQueue {

    private final LinkedBlockingQueue<PacketJob> queue;
    private volatile boolean shutdown = false;

    /** Push a packet. Blocks if the queue is full (back-pressure). */
    public void push(PacketJob job) {
        while (!shutdown) {
            if (queue.offer(job, 100, TimeUnit.MILLISECONDS)) return;
        }
    }

    /** Pop a packet, blocking until one is available or shutdown. */
    public PacketJob pop() {
        while (!shutdown || !queue.isEmpty()) {
            PacketJob job = queue.poll(100, TimeUnit.MILLISECONDS);
            if (job != null) return job;
        }
        return null;
    }
}
```

**How it works:**
- `push()`: Producer adds an item; blocks when the bounded queue is full (back-pressure)
- `pop()`: Consumer waits until an item is available, then takes it
- `LinkedBlockingQueue` handles the locking and signalling internally
- A `volatile shutdown` flag lets consumers drain the queue and exit cleanly

---

## 7. Deep Dive: Each Component

### pcap/PcapReader.java

**Purpose:** Read and write network captures saved by Wireshark — implemented in pure Java, no libpcap needed.

**Key fields it parses:**
```
Global header:  magic (0xa1b2c3d4), versionMajor/Minor, snaplen, network (1 = Ethernet)
Packet header:  tsSec, tsUsec, inclLen (bytes saved), origLen (original size)
```

**Key methods:**
- `open(filename)`: Open PCAP, validate the header, detect endianness
- `readNextPacket(raw)`: Read the next packet into a reusable `RawPacket`
- `writeGlobalHeader(out, ...)` / `writePacket(out, raw)`: Produce the output PCAP
- `close()`: Clean up

### pcap/LivePcapReader.java

**Purpose:** Capture packets in real time from a network interface using **pcap4j** (which talks to the Npcap driver on Windows). It exposes the same `readNextPacket(raw)` interface as `PcapReader`, so the rest of the pipeline doesn't care whether packets come from a file or from the wire.

### parser/PacketParser.java

**Purpose:** Extract protocol fields from raw bytes.

```java
ParsedPacket parsed = PacketParser.parse(raw);
// Ethernet → MACs, EtherType
// IP       → IPs, protocol, TTL
// TCP/UDP  → ports, payload offset/length
```

### extractor/ (SNIExtractor, HTTPHostExtractor, DNSExtractor, QUICSNIExtractor)

**Purpose:** Extract domain names from application payloads.

**For TLS (HTTPS):**
```java
Optional<String> sni = SNIExtractor.extract(payload, offset, length);
// 1. Verify TLS record header (0x16) and Client Hello (0x01)
// 2. Skip to extensions
// 3. Find SNI extension (type 0x0000)
// 4. Extract hostname string
```

**For HTTP:**
```java
Optional<String> host = HTTPHostExtractor.extract(payload, offset, length);
// 1. Verify HTTP request (GET, POST, etc.)
// 2. Search for "Host: " header
// 3. Extract value until newline
```

**For DNS:** `DNSExtractor` decodes the query name from DNS packets (port 53).

**For QUIC:** `QUICSNIExtractor` scans QUIC Initial packets (UDP 443) for the embedded TLS Client Hello.

### types/FiveTuple.java and types/AppType.java

**Purpose:** Core data structures used throughout.

```java
public final class FiveTuple {
    final byte[] srcIp;    // 4 bytes (IPv4) or 16 bytes (IPv6)
    final byte[] dstIp;
    final int    srcPort;
    final int    dstPort;
    final int    protocol;
    // equals() + hashCode() → usable as a HashMap key
}
```

```java
public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC,
    GOOGLE, FACEBOOK, YOUTUBE, TWITTER, INSTAGRAM,
    NETFLIX, AMAZON, MICROSOFT, APPLE, WHATSAPP,
    TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD,
    GITHUB, CLOUDFLARE;

    public static AppType fromSNI(String sni) { /* substring matching */ }
}
```

### rules/RuleManager.java

**Purpose:** Thread-safe store of blocking rules (IPs, apps, domains, ports) used by the multi-threaded engine. Supports loading/saving rules from a file.

### tracker/ConnectionTracker.java and tracker/GlobalConnectionTable.java

**Purpose:** Each fast-path worker owns a `ConnectionTracker` (its private flow table — no locking needed thanks to consistent hashing). `GlobalConnectionTable` aggregates statistics across all trackers for the final report.

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```java
public static Optional<String> extract(byte[] payload, int offset, int length) {
    if (!isTLSClientHello(payload, offset, length)) return Optional.empty();

    int end = offset + length;
    int pos = offset + 5;   // Skip TLS record header
    pos += 4;               // Skip handshake header: type(1) + length(3)
    pos += 34;              // Skip client_version(2) + random(32)

    // Skip Session ID
    int sessionIdLen = payload[pos] & 0xFF;
    pos += 1 + sessionIdLen;

    // Skip Cipher Suites
    int cipherSuitesLen = readUint16BE(payload, pos);
    pos += 2 + cipherSuitesLen;

    // Skip Compression Methods
    int compressionLen = payload[pos] & 0xFF;
    pos += 1 + compressionLen;

    // Read Extensions Length
    int extensionsLen = readUint16BE(payload, pos);
    pos += 2;
    int extensionsEnd = Math.min(pos + extensionsLen, end);

    // Search for SNI extension
    while (pos + 4 <= extensionsEnd) {
        int extType   = readUint16BE(payload, pos);
        int extLength = readUint16BE(payload, pos + 2);
        pos += 4;

        if (extType == 0x0000) {  // SNI!
            int sniLen = readUint16BE(payload, pos + 3);
            return Optional.of(new String(
                    payload, pos + 5, sniLen, StandardCharsets.US_ASCII));
        }
        pos += extLength;
    }
    return Optional.empty();  // SNI not found
}
```

(Every step in the real `SNIExtractor.java` also bounds-checks `pos` against `end` so malformed packets can't crash the parser.)

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `--block-ip 192.168.1.50` | All traffic from this source (IPv4 or IPv6) |
| App | `--block-app YouTube` | All YouTube connections |
| Domain | `--block-domain tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- **Java 11+** (JDK) — see [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for a step-by-step Windows guide
- **Apache Maven** (recommended) — bundles the pcap4j dependency into a fat JAR
- **Npcap** (Windows, only needed for live sniffing mode)

### Build with Maven (recommended)

```cmd
cd java_dpi
mvn clean package -DskipTests
```

Produces the executable fat JAR at `java_dpi\target\dpi.jar`.

### Build with build.bat (no Maven)

```cmd
cd java_dpi
build.bat
```

Produces `java_dpi\out\dpi.jar`. Note: this JAR does not bundle pcap4j, so it supports **offline PCAP analysis only** (no live sniffing).

### Running

**Basic usage (offline analysis):**
```cmd
java -jar target\dpi.jar test_dpi.pcap output.pcap
```

**Live sniffing (requires Npcap):**
```cmd
java -jar target\dpi.jar -i "Wi-Fi"
```

**With blocking:**
```cmd
java -jar target\dpi.jar test_dpi.pcap output.pcap ^
    --block-app YouTube ^
    --block-app TikTok ^
    --block-ip 192.168.1.50 ^
    --block-domain facebook
```

**Multi-threaded engine:**
```cmd
java -jar target\dpi.jar input.pcap output.pcap --mt
```

### Command-line Options

| Option | Description |
|--------|-------------|
| `-i <interface>` | Capture from a live interface instead of a file |
| `--block-ip <ip>` | Block traffic from a source IP (IPv4 or IPv6) |
| `--block-app <app>` | Block an application (YouTube, Facebook, etc.) |
| `--block-domain <domain>` | Block a domain (substring match against SNI/Host) |
| `--verbose` | Print every packet decision |
| `--mt` | Use the multi-threaded engine (`DPIEngine`) |

**Available app names:** Unknown, HTTP, HTTPS, DNS, TLS, QUIC, Google, Facebook, YouTube, Twitter/X, Instagram, Netflix, Amazon, Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare

### Creating Test Data

```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.1 (Java)                    ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[DPI] Processing packets...

[BLOCKED] 192.168.1.100 -> 142.250.185.206 (YouTube: www.youtube.com)

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:              77                               ║
║ Forwarded:                  69                               ║
║ Dropped:                     8                               ║
║ Active Flows:               25                               ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION BREAKDOWN                     ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                    ║
║ Unknown              16  20.8% ####                          ║
║ YouTube               4   5.2% #                             ║
║ DNS                   4   5.2% #                             ║
║ Facebook              3   3.9%                               ║
║ ...                                                          ║
╚══════════════════════════════════════════════════════════════╝

[Detected Applications/Domains]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub

Output written to: output.pcap
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Rules | Which blocking rules are active |
| Total Packets | Packets read from the input file / interface |
| Forwarded | Packets written to the output file |
| Dropped | Packets blocked (not written) |
| Active Flows | Number of distinct 5-tuple flows seen |
| Application Breakdown | Traffic classification results |
| Detected Applications/Domains | Actual domain names found via SNI/Host/DNS |

The multi-threaded engine (`--mt`) additionally prints per-thread statistics (packets dispatched per LB, packets processed per FP).

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
   ```java
   // In AppType.java — add an enum constant and a pattern in fromSNI()
   if (s.contains("twitch")) return TWITCH;
   ```

2. **Add Bandwidth Throttling**
   ```java
   // Instead of DROP, delay packets
   if (shouldThrottle(flow)) {
       Thread.sleep(10);
   }
   ```

3. **Add a Live Statistics Dashboard**
   ```java
   // Separate thread printing stats every second
   ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
   scheduler.scheduleAtFixedRate(this::printStats, 1, 1, TimeUnit.SECONDS);
   ```

4. **Expose the rules file / port blocking on the CLI** — `RuleManager` already supports port rules and load/save from file; wiring `--block-port`, `--rules`, and `--save-rules` into `Main.java`'s argument parser is a natural next step.

---

## Related Documents

- [WINDOWS_SETUP.md](WINDOWS_SETUP.md) — installing JDK, Maven, and Npcap on Windows
- [java_dpi/README.md](java_dpi/README.md) — quick-start and module-level reference
