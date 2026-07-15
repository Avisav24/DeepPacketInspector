package com.dpi.tracker;

import com.dpi.types.AppType;
import com.dpi.types.Connection;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Aggregates statistics from all per-FP ConnectionTrackers.
 * Thread-safe for reading from a reporting thread while FP threads modify their own trackers.
 *
 * Maps to GlobalConnectionTable in connection_tracker.h / connection_tracker.cpp.
 */
public class GlobalConnectionTable {

    private final List<ConnectionTracker> trackers;

    public GlobalConnectionTable(int numFPs) {
        // CopyOnWriteArrayList is safe for concurrent iteration + rare writes
        trackers = new CopyOnWriteArrayList<>();
        for (int i = 0; i < numFPs; i++) {
            trackers.add(null);
        }
    }

    /**
     * Register a tracker for a given FP ID.
     */
    public void registerTracker(int fpId, ConnectionTracker tracker) {
        if (fpId >= 0 && fpId < trackers.size()) {
            ((CopyOnWriteArrayList<ConnectionTracker>) trackers).set(fpId, tracker);
        }
    }

    /**
     * Aggregate statistics across all FP trackers.
     */
    public GlobalStats getGlobalStats() {
        GlobalStats stats = new GlobalStats();
        Map<String, Integer> domainCounts = new HashMap<>();

        for (ConnectionTracker tracker : trackers) {
            if (tracker == null) continue;

            stats.totalActiveConnections  += tracker.getActiveCount();
            stats.totalConnectionsSeen    += tracker.getTotalSeen();

            tracker.forEach(conn -> {
                // App distribution
                stats.appDistribution.merge(conn.appType, 1, Integer::sum);
                // Domain counts
                if (conn.sni != null && !conn.sni.isEmpty()) {
                    domainCounts.merge(conn.sni, 1, Integer::sum);
                }
            });
        }

        // Top 20 domains
        List<Map.Entry<String, Integer>> domainList = new ArrayList<>(domainCounts.entrySet());
        domainList.sort((a, b) -> b.getValue() - a.getValue());
        int take = Math.min(20, domainList.size());
        for (int i = 0; i < take; i++) {
            stats.topDomains.add(Map.entry(domainList.get(i).getKey(), domainList.get(i).getValue()));
        }

        return stats;
    }

    /**
     * Generate a formatted report string.
     */
    public String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder sb = new StringBuilder();

        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append(  "║               CONNECTION STATISTICS REPORT                    ║\n");
        sb.append(  "╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Active Connections:     %10d                          ║%n",
                stats.totalActiveConnections));
        sb.append(String.format("║ Total Connections Seen: %10d                          ║%n",
                stats.totalConnectionsSeen));

        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION BREAKDOWN                      ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        long total = stats.appDistribution.values().stream().mapToLong(Integer::longValue).sum();
        List<Map.Entry<AppType, Integer>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
        sortedApps.sort((a, b) -> b.getValue() - a.getValue());

        for (Map.Entry<AppType, Integer> e : sortedApps) {
            double pct = total > 0 ? (100.0 * e.getValue() / total) : 0;
            sb.append(String.format("║ %-20s %10d (%5.1f%%)           ║%n",
                    e.getKey().displayName(), e.getValue(), pct));
        }

        if (!stats.topDomains.isEmpty()) {
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║                      TOP DOMAINS                             ║\n");
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            for (Map.Entry<String, Integer> e : stats.topDomains) {
                String domain = e.getKey();
                if (domain.length() > 35) domain = domain.substring(0, 32) + "...";
                sb.append(String.format("║ %-40s %10d           ║%n", domain, e.getValue()));
            }
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    /** Aggregated statistics data class. */
    public static class GlobalStats {
        public long totalActiveConnections = 0;
        public long totalConnectionsSeen   = 0;
        public Map<AppType, Integer> appDistribution = new HashMap<>();
        public List<Map.Entry<String, Integer>> topDomains = new ArrayList<>();
    }
}
