package com.dpi.engine;

import com.dpi.pcap.PcapReader;
import com.dpi.pcap.RawPacket;
import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.rules.RuleManager;
import com.dpi.tracker.GlobalConnectionTable;
import com.dpi.types.*;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DPI Engine — main orchestrator for the multi-threaded pipeline.
 *
 * Architecture (mirrors dpi_engine.h / dpi_mt.cpp):
 *
 *   PcapReader → [LB Threads] → [FP Threads] → [Output Writer]
 *
 *   - Reader reads packets and hashes them to LB threads.
 *   - LB threads hash flows to FP threads (consistent per flow).
 *   - FP threads inspect payloads, track connections, apply rules.
 *   - Output writer drains the forwarded packets and writes them to output PCAP.
 *
 * Maps to DPIEngine in dpi_engine.h / dpi_engine.cpp.
 */
public class DPIEngine {

    // ── Configuration ────────────────────────────────────────────────────
    public static class Config {
        public int    numLoadBalancers = 2;
        public int    fpsPerLB        = 2;
        public int    queueSize       = 10_000;
        public String rulesFile       = null;
        public boolean verbose        = false;
    }

    private final Config config;

    // ── Shared components ─────────────────────────────────────────────────
    private final RuleManager          ruleManager;
    private final GlobalConnectionTable connTable;

    // ── Thread pools ──────────────────────────────────────────────────────
    private final List<FastPathProcessor> fps = new ArrayList<>();
    private final List<LoadBalancer>      lbs = new ArrayList<>();

    // ── Output ────────────────────────────────────────────────────────────
    private final ThreadSafeQueue outputQueue  = new ThreadSafeQueue(10_000);
    private OutputStream          outputStream = null;
    private Thread                outputThread;

    // ── Statistics ────────────────────────────────────────────────────────
    private final DPIStats stats = new DPIStats();

    // ── Control ───────────────────────────────────────────────────────────
    private final AtomicBoolean running            = new AtomicBoolean(false);
    private final AtomicBoolean processingComplete = new AtomicBoolean(false);

    public DPIEngine(Config config) {
        this.config      = config;
        this.ruleManager = new RuleManager();
        this.connTable   = new GlobalConnectionTable(config.numLoadBalancers * config.fpsPerLB);
    }

    /**
     * Initialize all threads and queues.
     */
    public boolean initialize() {
        int totalFPs = config.numLoadBalancers * config.fpsPerLB;

        // Create FP processors
        for (int i = 0; i < totalFPs; i++) {
            final int fpId = i;
            FastPathProcessor fp = new FastPathProcessor(fpId, ruleManager, this::handleOutput);
            fps.add(fp);
            connTable.registerTracker(fpId, fp.getConnectionTracker());
        }

        // Create LB threads, each owning a slice of FP queues
        for (int lbId = 0; lbId < config.numLoadBalancers; lbId++) {
            int fpStart = lbId * config.fpsPerLB;
            List<ThreadSafeQueue> myFpQueues = new ArrayList<>();
            for (int j = 0; j < config.fpsPerLB; j++) {
                myFpQueues.add(fps.get(fpStart + j).getInputQueue());
            }
            LoadBalancer lb = new LoadBalancer(lbId, myFpQueues, fpStart);
            lbs.add(lb);
        }

        if (config.rulesFile != null) {
            ruleManager.loadRules(config.rulesFile);
        }

        return true;
    }

    /**
     * Start all background threads.
     */
    public void start() {
        running.set(true);

        // Start output writer thread
        outputThread = new Thread(this::outputThreadFunc, "OutputWriter");
        outputThread.setDaemon(false);
        outputThread.start();

        // Start FP threads
        for (FastPathProcessor fp : fps) fp.start();

        // Start LB threads
        for (LoadBalancer lb : lbs) lb.start();
    }

    /**
     * Stop all threads gracefully.
     */
    public void stop() {
        running.set(false);

        // Signal LBs and FPs to drain and stop
        for (LoadBalancer lb : lbs) lb.stop();
        for (FastPathProcessor fp : fps) fp.stop();

        // Wait for FPs to finish
        for (FastPathProcessor fp : fps) {
            try { fp.join(); } catch (InterruptedException ignored) {}
        }

        // Drain output queue then stop
        outputQueue.shutdown();
        if (outputThread != null) {
            try { outputThread.join(5000); } catch (InterruptedException ignored) {}
        }
    }

    /**
     * Process an input PCAP file and write forwarded packets to output PCAP.
     */
    public boolean processFile(String inputFile, String outputFile) {
        // Open output file
        try {
            outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        } catch (IOException e) {
            System.err.println("Error: Cannot open output file: " + outputFile);
            return false;
        }

        // Open input PCAP
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) {
            return false;
        }

        // Write PCAP global header to output
        try {
            PcapReader.writeGlobalHeader(outputStream,
                    reader.versionMajor, reader.versionMinor,
                    reader.snaplen, reader.network);
        } catch (IOException e) {
            System.err.println("Error writing output PCAP header: " + e.getMessage());
            return false;
        }

        start();
        System.out.println("[DPI] Processing packets...");

        RawPacket raw = new RawPacket();
        int packetId  = 0;

        while (reader.readNextPacket(raw)) {
            packetId++;
            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(raw.data.length);

            // Parse packet
            ParsedPacket parsed = PacketParser.parse(raw);
            if (parsed == null || !parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                // Forward non-IP/non-TCP/UDP packets as-is
                stats.forwardedPackets.incrementAndGet();
                writeOutputPacketDirect(raw);
                continue;
            }

            // Count by protocol
            if (parsed.hasTcp)      stats.tcpPackets.incrementAndGet();
            else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();
            else                    stats.otherPackets.incrementAndGet();

            // Build PacketJob
            PacketJob job = new PacketJob();
            job.packetId       = packetId;
            job.tsSec          = raw.tsSec;
            job.tsUsec         = raw.tsUsec;
            job.data           = raw.data;
            job.payloadOffset  = parsed.payloadOffset;
            job.payloadLength  = parsed.payloadLength;
            job.tcpFlags       = parsed.tcpFlags;
            job.tuple = new FiveTuple(
                    parsed.srcIpBytes,
                    parsed.dstIpBytes,
                    parsed.srcPort,
                    parsed.dstPort,
                    parsed.protocol
            );

            // Dispatch to LB (hash to select load balancer)
            dispatchToLB(job);
        }

        reader.close();
        processingComplete.set(true);

        // Let pipeline drain
        stop();

        try {
            outputStream.flush();
            outputStream.close();
        } catch (IOException ignored) {}

        return true;
    }

    /**
     * Dispatch a packet to the appropriate LB based on flow hash.
     */
    private void dispatchToLB(PacketJob job) {
        int lbIndex = Math.abs(job.tuple.hashCode()) % lbs.size();
        lbs.get(lbIndex).getInputQueue().push(job);
    }

    /**
     * Called by FP threads with packet action decisions.
     */
    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.FORWARD || action == PacketAction.LOG_ONLY) {
            stats.forwardedPackets.incrementAndGet();
            outputQueue.push(job);
        } else {
            stats.droppedPackets.incrementAndGet();
        }
    }

    /**
     * Output writer thread — drains the output queue and writes to PCAP.
     */
    private void outputThreadFunc() {
        while (!outputQueue.isShutdown() || !outputQueue.isEmpty()) {
            PacketJob job = outputQueue.pop(100);
            if (job == null) continue;
            writeJobToOutput(job);
        }
        // Drain any remaining
        PacketJob job;
        while ((job = outputQueue.pop(0)) != null) {
            writeJobToOutput(job);
        }
    }

    private synchronized void writeJobToOutput(PacketJob job) {
        if (outputStream == null) return;
        try {
            RawPacket pkt = new RawPacket();
            pkt.tsSec   = job.tsSec;
            pkt.tsUsec  = job.tsUsec;
            pkt.inclLen = job.data.length;
            pkt.origLen = job.data.length;
            pkt.data    = job.data;
            PcapReader.writePacket(outputStream, pkt);
        } catch (IOException e) {
            System.err.println("Error writing packet to output: " + e.getMessage());
        }
    }

    /** Write a raw packet directly to output (bypasses FP pipeline). */
    private synchronized void writeOutputPacketDirect(RawPacket raw) {
        if (outputStream == null) return;
        try {
            PcapReader.writePacket(outputStream, raw);
        } catch (IOException e) {
            System.err.println("Error writing packet to output: " + e.getMessage());
        }
    }

    // ── Rule management API ──────────────────────────────────────────────

    public void blockIP(String ip)         { ruleManager.blockIP(ip); }
    public void unblockIP(String ip)       { ruleManager.unblockIP(ip); }
    public void blockApp(AppType app)      { ruleManager.blockApp(app); }
    public void blockApp(String appName) {
        AppType app = AppType.fromDisplayName(appName);
        if (app != null) ruleManager.blockApp(app);
        else System.err.println("[DPI] Unknown app: " + appName);
    }
    public void unblockApp(AppType app)    { ruleManager.unblockApp(app); }
    public void blockDomain(String domain) { ruleManager.blockDomain(domain); }
    public void unblockDomain(String d)   { ruleManager.unblockDomain(d); }
    public boolean loadRules(String f)     { return ruleManager.loadRules(f); }
    public boolean saveRules(String f)     { return ruleManager.saveRules(f); }

    // ── Accessors ────────────────────────────────────────────────────────

    public DPIStats getStats()             { return stats; }
    public RuleManager getRuleManager()    { return ruleManager; }
    public Config getConfig()              { return config; }
    public boolean isRunning()             { return running.get(); }
    public GlobalConnectionTable getConnectionTable() { return connTable; }
}
