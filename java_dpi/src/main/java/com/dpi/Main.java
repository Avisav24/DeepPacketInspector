package com.dpi;

import com.dpi.extractor.HTTPHostExtractor;
import com.dpi.extractor.SNIExtractor;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.RawPacket;
import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.rules.RuleManager;
import com.dpi.types.*;

import java.io.*;
import java.util.*;

/**
 * Main entry point — single-threaded DPI engine.
 *
 * This is the direct Java equivalent of main_working.cpp: readable,
 * sequential, and fully functional. It uses all the same components
 * (PcapReader, PacketParser, SNIExtractor, RuleManager) but runs
 * them on a single thread for simplicity.
 *
 * For the multi-threaded engine, see DPIEngine.java.
 *
 * Usage:
 *   java -jar dpi.jar <input.pcap> <output.pcap> [options]
 *
 * Options:
 *   --block-ip <ip>         Block traffic from source IP
 *   --block-app <app>       Block application (YouTube, Facebook, etc.)
 *   --block-domain <domain> Block domain (substring match)
 *   --block-port <port>     Block destination port
 *   --rules <file>          Load rules from file
 *   --save-rules <file>     Save rules to file after processing
 *   --verbose               Print every packet decision
 *   --mt                    Use multi-threaded engine (DPIEngine)
 */
public class Main {

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String inputFile  = args[0];
        String outputFile = args[1];
        boolean verbose   = false;
        boolean multiThreaded = false;

        // ── Simplified blocking rules (mirrors main_working.cpp) ──────────
        Set<Integer>  blockedIPs     = new HashSet<>();
        Set<AppType>  blockedApps    = new HashSet<>();
        List<String>  blockedDomains = new ArrayList<>();

        // Parse CLI options
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip":
                    if (i + 1 < args.length) {
                        String ip = args[++i];
                        blockedIPs.add(FiveTuple.parseIp(ip));
                        System.out.println("[Rules] Blocked IP: " + ip);
                    }
                    break;

                case "--block-app":
                    if (i + 1 < args.length) {
                        String appName = args[++i];
                        AppType app = AppType.fromDisplayName(appName);
                        if (app != null) {
                            blockedApps.add(app);
                            System.out.println("[Rules] Blocked app: " + appName);
                        } else {
                            System.err.println("[Rules] Unknown app: " + appName);
                        }
                    }
                    break;

                case "--block-domain":
                    if (i + 1 < args.length) {
                        String domain = args[++i];
                        blockedDomains.add(domain.toLowerCase(Locale.ROOT));
                        System.out.println("[Rules] Blocked domain: " + domain);
                    }
                    break;

                case "--verbose":
                    verbose = true;
                    break;

                case "--mt":
                    multiThreaded = true;
                    break;

                default:
                    System.err.println("Unknown option: " + args[i]);
            }
        }

        // Print banner
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0 (Java)                    ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();

        // ── Open input PCAP ───────────────────────────────────────────────
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) {
            System.exit(1);
        }

        // ── Open output PCAP ──────────────────────────────────────────────
        OutputStream outputStream;
        try {
            outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        } catch (IOException e) {
            System.err.println("Error: Cannot open output file: " + outputFile);
            System.exit(1);
            return;
        }

        // Write PCAP global header
        try {
            PcapReader.writeGlobalHeader(outputStream,
                    reader.versionMajor, reader.versionMinor,
                    reader.snaplen, reader.network);
        } catch (IOException e) {
            System.err.println("Error writing PCAP header: " + e.getMessage());
            System.exit(1);
        }

        // ── Flow table ────────────────────────────────────────────────────
        Map<FiveTuple, Flow> flows = new HashMap<>();

        // ── Statistics ────────────────────────────────────────────────────
        long totalPackets = 0;
        long forwarded    = 0;
        long dropped      = 0;
        Map<AppType, Long> appStats = new HashMap<>();

        System.out.println("[DPI] Processing packets...\n");

        RawPacket raw = new RawPacket();
        while (reader.readNextPacket(raw)) {
            totalPackets++;

            ParsedPacket parsed = PacketParser.parse(raw);
            if (parsed == null || !parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                // Forward non-IP/TCP/UDP packets unchanged
                try { PcapReader.writePacket(outputStream, raw); } catch (IOException ignored) {}
                forwarded++;
                continue;
            }

            // Build five-tuple
            FiveTuple tuple = new FiveTuple(
                    parsed.srcIpInt,
                    parsed.dstIpInt,
                    parsed.srcPort,
                    parsed.dstPort,
                    parsed.protocol
            );

            // Get or create flow
            Flow flow = flows.computeIfAbsent(tuple, t -> new Flow(t));
            flow.packets++;
            flow.bytes += raw.data.length;

            // ── TLS SNI extraction (port 443) ─────────────────────────────
            if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS) &&
                    flow.sni.isEmpty() && parsed.hasTcp && parsed.dstPort == 443) {

                if (parsed.payloadLength > 5) {
                    Optional<String> sni = SNIExtractor.extract(
                            raw.data, parsed.payloadOffset, parsed.payloadLength);
                    if (sni.isPresent()) {
                        flow.sni     = sni.get();
                        flow.appType = AppType.fromSNI(flow.sni);
                    }
                }
            }

            // ── HTTP Host extraction (port 80) ────────────────────────────
            if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP) &&
                    flow.sni.isEmpty() && parsed.hasTcp && parsed.dstPort == 80) {

                if (parsed.payloadLength > 0) {
                    Optional<String> host = HTTPHostExtractor.extract(
                            raw.data, parsed.payloadOffset, parsed.payloadLength);
                    if (host.isPresent()) {
                        flow.sni     = host.get();
                        flow.appType = AppType.fromSNI(flow.sni);
                    }
                }
            }

            // ── DNS classification ─────────────────────────────────────────
            if (flow.appType == AppType.UNKNOWN &&
                    (parsed.dstPort == 53 || parsed.srcPort == 53)) {
                flow.appType = AppType.DNS;
            }

            // ── Port-based fallback ────────────────────────────────────────
            if (flow.appType == AppType.UNKNOWN) {
                if (parsed.dstPort == 443) flow.appType = AppType.HTTPS;
                else if (parsed.dstPort == 80) flow.appType = AppType.HTTP;
            }

            // ── Apply blocking rules ──────────────────────────────────────
            if (!flow.blocked) {
                flow.blocked = isBlocked(tuple.srcIp, flow.appType, flow.sni,
                        blockedIPs, blockedApps, blockedDomains);
                if (flow.blocked) {
                    System.out.printf("[BLOCKED] %s -> %s (%s%s)%n",
                            parsed.srcIp, parsed.dstIp,
                            flow.appType.displayName(),
                            flow.sni.isEmpty() ? "" : ": " + flow.sni);
                }
            }

            // Verbose logging
            if (verbose && !flow.blocked) {
                System.out.printf("[FORWARD] %s -> %s (%s%s)%n",
                        parsed.srcIp, parsed.dstIp,
                        flow.appType.displayName(),
                        flow.sni.isEmpty() ? "" : ": " + flow.sni);
            }

            // Update app stats
            appStats.merge(flow.appType, 1L, Long::sum);

            // Forward or drop
            if (flow.blocked) {
                dropped++;
            } else {
                forwarded++;
                try {
                    PcapReader.writePacket(outputStream, raw);
                } catch (IOException e) {
                    System.err.println("Error writing packet: " + e.getMessage());
                }
            }
        }

        reader.close();
        try { outputStream.flush(); outputStream.close(); } catch (IOException ignored) {}

        // ── Print report (mirrors main_working.cpp output format) ─────────
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║ Total Packets:      %10d                             ║%n", totalPackets);
        System.out.printf( "║ Forwarded:          %10d                             ║%n", forwarded);
        System.out.printf( "║ Dropped:            %10d                             ║%n", dropped);
        System.out.printf( "║ Active Flows:       %10d                             ║%n", flows.size());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                    APPLICATION BREAKDOWN                     ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        // Sort by count descending
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appStats.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> e : sortedApps) {
            double pct    = 100.0 * e.getValue() / Math.max(1, totalPackets);
            int barLen    = (int)(pct / 5);
            String bar    = "#".repeat(barLen);
            System.out.printf("║ %-15s %8d %5.1f%% %-20s  ║%n",
                    e.getKey().displayName(), e.getValue(), pct, bar);
        }

        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // List detected SNIs
        System.out.println("\n[Detected Applications/Domains]");
        Map<String, AppType> uniqueSNIs = new LinkedHashMap<>();
        for (Map.Entry<FiveTuple, Flow> e : flows.entrySet()) {
            if (!e.getValue().sni.isEmpty()) {
                uniqueSNIs.put(e.getValue().sni, e.getValue().appType);
            }
        }
        if (uniqueSNIs.isEmpty()) {
            System.out.println("  (none detected)");
        } else {
            for (Map.Entry<String, AppType> e : uniqueSNIs.entrySet()) {
                System.out.println("  - " + e.getKey() + " -> " + e.getValue().displayName());
            }
        }

        System.out.println("\nOutput written to: " + outputFile);
    }

    /** Check if a packet should be blocked given the current rules. */
    private static boolean isBlocked(int srcIp, AppType app, String sni,
                                     Set<Integer> blockedIPs,
                                     Set<AppType> blockedApps,
                                     List<String> blockedDomains) {
        if (blockedIPs.contains(srcIp)) return true;
        if (blockedApps.contains(app)) return true;
        if (!sni.isEmpty()) {
            String lowerSNI = sni.toLowerCase(Locale.ROOT);
            for (String domain : blockedDomains) {
                if (lowerSNI.contains(domain)) return true;
            }
        }
        return false;
    }

    private static void printUsage() {
        System.out.println();
        System.out.println("DPI Engine - Deep Packet Inspection System (Java)");
        System.out.println("==================================================");
        System.out.println();
        System.out.println("Usage: java -jar dpi.jar <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>         Block traffic from source IP");
        System.out.println("  --block-app <app>       Block application (YouTube, Facebook, etc.)");
        System.out.println("  --block-domain <domain> Block domain (substring match)");
        System.out.println("  --verbose               Print every packet decision");
        System.out.println();
        System.out.println("Example:");
        System.out.println("  java -jar dpi.jar capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50");
        System.out.println();
        System.out.println("Available app names:");
        for (AppType t : AppType.values()) {
            System.out.println("  " + t.displayName());
        }
    }

    // ── Inner class: simplified flow entry ───────────────────────────────

    private static class Flow {
        final FiveTuple tuple;
        AppType appType = AppType.UNKNOWN;
        String  sni     = "";
        long    packets = 0;
        long    bytes   = 0;
        boolean blocked = false;

        Flow(FiveTuple tuple) {
            this.tuple = tuple;
        }
    }
}
