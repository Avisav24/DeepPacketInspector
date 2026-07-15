package com.dpi.tracker;

import com.dpi.types.*;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Tracks connection/flow state for packets processed by a single FP thread.
 * Since the load balancer hashes packets to the same FP per flow, no locking
 * is needed inside this class — it is never accessed by more than one thread.
 *
 * Maps to ConnectionTracker in connection_tracker.h / connection_tracker.cpp.
 */
public class ConnectionTracker {

    private final int fpId;
    private final int maxConnections;

    /** Main flow table: FiveTuple -> Connection */
    private final HashMap<FiveTuple, Connection> connections;

    private long totalSeen       = 0;
    private long classifiedCount = 0;
    private long blockedCount    = 0;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId           = fpId;
        this.maxConnections = maxConnections;
        this.connections    = new HashMap<>(maxConnections * 2);
    }

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    /**
     * Get an existing connection or create a new one for this five-tuple.
     */
    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection(tuple);
        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    /**
     * Get an existing connection, or null if not found.
     * Also checks the reverse tuple for bidirectional matching.
     */
    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;
        return connections.get(tuple.reverse());
    }

    /**
     * Update packet/byte counters on a connection.
     */
    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.lastSeen = Instant.now();
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    /**
     * Mark a connection as classified with a detected app type and SNI.
     */
    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni     = (sni != null) ? sni : "";
            conn.state   = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    /**
     * Mark a connection as blocked (all future packets should be dropped).
     */
    public void blockConnection(Connection conn) {
        if (conn == null) return;
        conn.state  = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    /**
     * Mark a connection as closed.
     */
    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    /**
     * Remove connections that haven't been seen for longer than the timeout,
     * and connections in CLOSED state.
     *
     * @param timeoutSeconds Inactivity timeout in seconds.
     * @return Number of connections removed.
     */
    public int cleanupStale(long timeoutSeconds) {
        Instant cutoff = Instant.now().minus(Duration.ofSeconds(timeoutSeconds));
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Connection conn = it.next().getValue();
            if (conn.state == ConnectionState.CLOSED || conn.lastSeen.isBefore(cutoff)) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    /** Return all current connections (snapshot). */
    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    /** Active connection count. */
    public int getActiveCount() {
        return connections.size();
    }

    public long getTotalSeen()       { return totalSeen; }
    public long getClassifiedCount() { return classifiedCount; }
    public long getBlockedCount()    { return blockedCount; }

    /** Remove all connections. */
    public void clear() {
        connections.clear();
    }

    /** Iterate all connections with a callback. */
    public void forEach(java.util.function.Consumer<Connection> callback) {
        connections.values().forEach(callback);
    }

    /** Evict the oldest (least-recently-seen) connection to make room. */
    private void evictOldest() {
        if (connections.isEmpty()) return;
        FiveTuple oldestKey = null;
        Instant oldestTime  = Instant.MAX;
        for (Map.Entry<FiveTuple, Connection> e : connections.entrySet()) {
            if (e.getValue().lastSeen.isBefore(oldestTime)) {
                oldestTime = e.getValue().lastSeen;
                oldestKey  = e.getKey();
            }
        }
        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }
}
