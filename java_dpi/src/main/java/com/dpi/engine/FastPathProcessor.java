package com.dpi.engine;

import com.dpi.extractor.*;
import com.dpi.rules.RuleManager;
import com.dpi.tracker.ConnectionTracker;
import com.dpi.types.*;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Fast Path Processor — the DPI worker thread.
 *
 * Responsibilities per packet:
 *   1. Look up or create connection entry
 *   2. Perform payload inspection (TLS SNI, HTTP Host, DNS)
 *   3. Classify the connection (YouTube, Facebook, etc.)
 *   4. Apply blocking rules
 *   5. Forward or drop the packet via the output callback
 *
 * Each FP thread owns its own ConnectionTracker, so no locking is needed there.
 * The RuleManager is shared (read-only concurrent access is lock-safe).
 *
 * Maps to FastPathProcessor in fast_path.h / fast_path.cpp.
 */
public class FastPathProcessor implements Runnable {

    private final int fpId;
    private final ThreadSafeQueue inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;

    /** Called when a packet should be forwarded or dropped. */
    private final BiConsumer<PacketJob, PacketAction> outputCallback;

    // Statistics
    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped   = new AtomicLong(0);
    private final AtomicLong sniExtractions   = new AtomicLong(0);

    private volatile boolean running = false;
    private Thread thread;

    public FastPathProcessor(int fpId,
                             RuleManager ruleManager,
                             BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId           = fpId;
        this.inputQueue     = new ThreadSafeQueue(10_000);
        this.connTracker    = new ConnectionTracker(fpId);
        this.ruleManager    = ruleManager;
        this.outputCallback = outputCallback;
    }

    public void start() {
        running = true;
        thread = new Thread(this, "FP-" + fpId);
        thread.setDaemon(false);
        thread.start();
    }

    public void stop() {
        running = false;
        inputQueue.shutdown();
    }

    public void join() throws InterruptedException {
        if (thread != null) thread.join(5000);
    }

    @Override
    public void run() {
        while (running || !inputQueue.isEmpty()) {
            PacketJob job = inputQueue.pop(100);
            if (job == null) continue;

            PacketAction action = processPacket(job);

            if (action == PacketAction.FORWARD || action == PacketAction.LOG_ONLY) {
                packetsForwarded.incrementAndGet();
            } else {
                packetsDropped.incrementAndGet();
            }

            outputCallback.accept(job, action);
            packetsProcessed.incrementAndGet();
        }
    }

    /**
     * Main DPI decision logic for a single packet.
     */
    private PacketAction processPacket(PacketJob job) {
        // Get or create the connection entry for this flow
        Connection conn = connTracker.getOrCreateConnection(job.tuple);

        // If already decided (blocked or forwarded connection), apply cached decision
        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        // Update connection statistics
        connTracker.updateConnection(conn, job.data.length, true);

        // Inspect payload if the connection is not yet fully classified
        if (conn.state == ConnectionState.NEW ||
            conn.state == ConnectionState.ESTABLISHED ||
            (conn.state == ConnectionState.CLASSIFIED &&
             (conn.appType == AppType.UNKNOWN || conn.appType == AppType.HTTPS) &&
             conn.sni.isEmpty())) {

            inspectPayload(job, conn);
        }

        // Update TCP state
        if (job.tcpFlags != 0) {
            updateTCPState(conn, job.tcpFlags);
        }

        // Apply rules
        return checkRules(job, conn);
    }

    /**
     * Inspect packet payload: try SNI, HTTP Host, DNS extraction.
     */
    private void inspectPayload(PacketJob job, Connection conn) {
        byte[] data = job.data;
        int pOff    = job.payloadOffset;
        int pLen    = job.payloadLength;

        if (pLen <= 0 || pOff + pLen > data.length) return;

        // ── TLS SNI (port 443) ────────────────────────────────────────────
        if ((conn.appType == AppType.UNKNOWN || conn.appType == AppType.HTTPS) &&
                conn.sni.isEmpty() && job.tuple.dstPort == 443) {

            Optional<String> sni = SNIExtractor.extract(data, pOff, pLen);
            if (sni.isPresent()) {
                String sniVal = sni.get();
                AppType app   = AppType.fromSNI(sniVal);
                connTracker.classifyConnection(conn, app, sniVal);
                sniExtractions.incrementAndGet();
                return;
            }
        }

        // ── HTTP Host header (port 80) ────────────────────────────────────
        if ((conn.appType == AppType.UNKNOWN || conn.appType == AppType.HTTP) &&
                conn.sni.isEmpty() && job.tuple.dstPort == 80) {

            Optional<String> host = HTTPHostExtractor.extract(data, pOff, pLen);
            if (host.isPresent()) {
                AppType app = AppType.fromSNI(host.get());
                connTracker.classifyConnection(conn, app, host.get());
                return;
            }
        }

        // ── DNS (port 53) ─────────────────────────────────────────────────
        if (conn.appType == AppType.UNKNOWN &&
                (job.tuple.dstPort == 53 || job.tuple.srcPort == 53)) {
            connTracker.classifyConnection(conn, AppType.DNS, "");
            return;
        }

        // ── Port-based fallback ───────────────────────────────────────────
        if (conn.appType == AppType.UNKNOWN) {
            if (job.tuple.dstPort == 443) {
                connTracker.classifyConnection(conn, AppType.HTTPS, "");
            } else if (job.tuple.dstPort == 80) {
                connTracker.classifyConnection(conn, AppType.HTTP, "");
            } else if (conn.state == ConnectionState.NEW) {
                conn.state = ConnectionState.ESTABLISHED;
            }
        }
    }

    /**
     * Apply blocking rules to a packet.
     */
    private PacketAction checkRules(PacketJob job, Connection conn) {
        RuleManager.BlockReason reason = ruleManager.shouldBlock(
                job.tuple.srcIp,
                job.tuple.dstPort,
                conn.appType,
                conn.sni
        );

        if (reason != null) {
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    /**
     * Update TCP connection state flags.
     */
    private void updateTCPState(Connection conn, int flags) {
        // TCP flags: SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04
        if ((flags & 0x02) != 0) conn.synSeen = true;
        if ((flags & 0x12) == 0x12) conn.synAckSeen = true; // SYN+ACK
        if ((flags & 0x01) != 0) { // FIN
            conn.finSeen = true;
            conn.state = ConnectionState.CLOSED;
        }
        if ((flags & 0x04) != 0) { // RST
            conn.state = ConnectionState.CLOSED;
        }
        if (conn.synSeen && conn.synAckSeen && conn.state == ConnectionState.NEW) {
            conn.state = ConnectionState.ESTABLISHED;
        }
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    public ThreadSafeQueue getInputQueue()        { return inputQueue; }
    public ConnectionTracker getConnectionTracker() { return connTracker; }
    public int getId()                             { return fpId; }
    public boolean isRunning()                     { return running; }

    public long getPacketsProcessed() { return packetsProcessed.get(); }
    public long getPacketsForwarded() { return packetsForwarded.get(); }
    public long getPacketsDropped()   { return packetsDropped.get(); }
    public long getSniExtractions()   { return sniExtractions.get(); }
}
