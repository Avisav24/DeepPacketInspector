# DPI Engine — Java Port

> A complete, faithful Java port of the C++ DPI (Deep Packet Inspection) engine.

---

## Quick Start

### Build with Maven (recommended)

Maven bundles the pcap4j dependency into an executable fat JAR, which is required for live sniffing:

```bat
cd java_dpi
mvn clean package -DskipTests
```

Output: `target\dpi.jar`

### Build with build.bat (no Maven)

```bat
cd java_dpi
build.bat
```

Output: `out\dpi.jar` — **offline PCAP analysis only** (pcap4j is not bundled, so live sniffing is unavailable).

Or manually:
```powershell
# Compile
$files = Get-ChildItem -Recurse -Filter "*.java" src\main\java | Select -ExpandProperty FullName
[IO.File]::WriteAllText("out\sources.txt", ($files -join "`n"), [Text.Encoding]::ASCII)
javac -d out "@out\sources.txt"

# Package
jar cfm out\dpi.jar out\MANIFEST.MF -C out com
```

### Run
```bat
REM Offline PCAP analysis
java -jar target\dpi.jar <input.pcap> <output.pcap> [options]

REM Live interface sniffing (requires Npcap)
java -jar target\dpi.jar -i <interface> [options]
```

---

## Usage Examples

```bat
REM Analyze traffic, forward everything
java -jar target\dpi.jar capture.pcap filtered.pcap

REM Block YouTube
java -jar target\dpi.jar capture.pcap filtered.pcap --block-app YouTube

REM Block multiple apps + a domain + an IP
java -jar target\dpi.jar capture.pcap filtered.pcap ^
  --block-app YouTube ^
  --block-app Discord ^
  --block-domain facebook ^
  --block-ip 192.168.1.50

REM Verbose mode (prints every packet decision)
java -jar target\dpi.jar capture.pcap filtered.pcap --verbose

REM Live sniffing from a network interface (requires Npcap)
java -jar target\dpi.jar -i "Wi-Fi" --block-app YouTube

REM Multi-threaded engine (LB/FP pipeline)
java -jar target\dpi.jar capture.pcap filtered.pcap --mt
```

---

## Supported Options

| Option | Description |
|--------|-------------|
| `-i <interface>` | Capture from a live network interface instead of a file |
| `--block-app <name>` | Block by application name |
| `--block-ip <ip>` | Block by source IP address (IPv4 or IPv6) |
| `--block-domain <domain>` | Block by domain (substring match) |
| `--verbose` | Show per-packet decisions |
| `--mt` | Use the multi-threaded engine (`DPIEngine`) |

**Available app names:** Unknown, HTTP, HTTPS, DNS, TLS, QUIC, Google, Facebook, YouTube, Twitter/X, Instagram, Netflix, Amazon, Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare

---

## Project Structure

```
java_dpi/
├── build.bat                         # Windows build script
├── pom.xml                           # Maven build (if Maven is installed)
└── src/main/java/com/dpi/
    ├── Main.java                     # CLI entry point (single-threaded pipeline)
    ├── types/
    │   ├── AppType.java              # App enum + SNI classification logic
    │   ├── FiveTuple.java            # Flow identifier (src/dst IP+port+protocol)
    │   ├── Connection.java           # Per-flow connection state
    │   ├── PacketJob.java            # Packet wrapper for pipeline
    │   ├── DPIStats.java             # AtomicLong statistics counters
    │   ├── ConnectionState.java      # NEW/ESTABLISHED/CLASSIFIED/BLOCKED/CLOSED
    │   └── PacketAction.java         # FORWARD/DROP/INSPECT/LOG_ONLY
    ├── pcap/
    │   ├── PcapReader.java           # PCAP file reader (no external library)
    │   ├── LivePcapReader.java       # Live interface capture (pcap4j/Npcap)
    │   └── RawPacket.java            # Raw packet data holder
    ├── parser/
    │   ├── PacketParser.java         # Ethernet/IPv4/TCP/UDP header parser
    │   └── ParsedPacket.java         # Parsed packet result
    ├── extractor/
    │   ├── SNIExtractor.java         # TLS Client Hello SNI extraction
    │   ├── HTTPHostExtractor.java    # HTTP Host header extraction
    │   ├── DNSExtractor.java         # DNS query domain extraction
    │   └── QUICSNIExtractor.java     # QUIC Initial packet SNI extraction
    ├── tracker/
    │   ├── ConnectionTracker.java    # Per-FP flow table
    │   └── GlobalConnectionTable.java # Aggregated stats from all FPs
    ├── rules/
    │   └── RuleManager.java          # Thread-safe IP/App/Domain/Port rules
    └── engine/
        ├── DPIEngine.java            # Multi-threaded orchestrator
        ├── FastPathProcessor.java    # DPI worker thread
        ├── LoadBalancer.java         # Consistent-hash packet distributor
        └── ThreadSafeQueue.java      # Bounded blocking queue
```

---

## How It Works

```
PCAP File
    │
    ▼
PcapReader          ← Reads raw bytes, handles endian swap, no libpcap needed
    │
    ▼
PacketParser        ← Parses Ethernet → IPv4 → TCP/UDP headers
    │
    ▼
SNI/HTTP/DNS        ← Inspects payload bytes to identify the app
Extractors
    │
    ▼
ConnectionTracker   ← Maintains per-flow state table (HashMap)
    │
    ▼
RuleManager         ← Checks IP, app, domain, port blocking rules
    │
    ├── DROP   →  (packet discarded)
    └── FORWARD → PcapReader.writePacket → output.pcap
```

---

## Detection Capabilities

| Traffic Type | Detection Method |
|---|---|
| HTTPS | TLS SNI from Client Hello |
| HTTP | `Host:` header parsing |
| DNS | DNS query format detection |
| QUIC | QUIC Initial packet scan |
| Port-based | Port 80 → HTTP, 443 → HTTPS fallback |

---

## Requirements

- **Java 11+** (tested on Java 25)
- Offline PCAP analysis needs no native libraries (pure-Java parser)
- Live sniffing (`-i`) requires **pcap4j** (bundled by the Maven build) and the **Npcap** driver on Windows — see [../WINDOWS_SETUP.md](../WINDOWS_SETUP.md)
