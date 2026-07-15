# DPI Engine — Java Port

> A complete, faithful Java port of the C++ DPI (Deep Packet Inspection) engine.

---

## Quick Start

### Build
```bat
cd java_dpi
build.bat
```

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
java -jar out\dpi.jar <input.pcap> <output.pcap> [options]
```

---

## Usage Examples

```bat
# Analyze traffic, forward everything
java -jar out\dpi.jar capture.pcap filtered.pcap

# Block YouTube
java -jar out\dpi.jar capture.pcap filtered.pcap --block-app YouTube

# Block multiple apps + a domain + an IP
java -jar out\dpi.jar capture.pcap filtered.pcap ^
  --block-app YouTube ^
  --block-app Discord ^
  --block-domain facebook ^
  --block-ip 192.168.1.50

# Verbose mode (prints every packet decision)
java -jar out\dpi.jar capture.pcap filtered.pcap --verbose
```

---

## Supported Blocking Options

| Option | Description |
|--------|-------------|
| `--block-app <name>` | Block by application name |
| `--block-ip <ip>` | Block by source IP address |
| `--block-domain <domain>` | Block by domain (substring match) |
| `--verbose` | Show per-packet decisions |

**Available app names:** Unknown, HTTP, HTTPS, DNS, TLS, QUIC, Google, Facebook, YouTube, Twitter/X, Instagram, Netflix, Amazon, Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare

---

## Project Structure

```
java_dpi/
├── build.bat                         # Windows build script
├── pom.xml                           # Maven build (if Maven is installed)
└── src/main/java/com/dpi/
    ├── Main.java                     # CLI entry point (mirrors main_working.cpp)
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
- No external dependencies
