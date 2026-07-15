package com.dpi.rules;

import com.dpi.types.AppType;
import com.dpi.types.FiveTuple;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.*;

/**
 * Thread-safe rule manager for blocking traffic by IP, App, Domain, and Port.
 * Uses ReadWriteLock to allow concurrent reads from multiple FP threads while
 * supporting exclusive writes from the main/control thread.
 *
 * Maps to RuleManager in rule_manager.h / rule_manager.cpp.
 */
public class RuleManager {

    // ── IP blocking ────────────────────────────────────────────────────────
    private final ReadWriteLock ipLock     = new ReentrantReadWriteLock();
    private final Set<Integer>  blockedIPs = new HashSet<>();

    // ── App blocking ───────────────────────────────────────────────────────
    private final ReadWriteLock appLock     = new ReentrantReadWriteLock();
    private final Set<AppType>  blockedApps = new HashSet<>();

    // ── Domain blocking ────────────────────────────────────────────────────
    private final ReadWriteLock domainLock     = new ReentrantReadWriteLock();
    private final Set<String>   blockedDomains  = new HashSet<>();
    private final List<String>  domainPatterns  = new ArrayList<>(); // wildcard patterns

    // ── Port blocking ──────────────────────────────────────────────────────
    private final ReadWriteLock portLock     = new ReentrantReadWriteLock();
    private final Set<Integer>  blockedPorts = new HashSet<>();

    // ====================================================================
    // IP Blocking
    // ====================================================================

    public void blockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIPs.add(ip);
            System.out.println("[RuleManager] Blocked IP: " + FiveTuple.ipToString(ip));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public void blockIP(String ipStr) {
        blockIP(FiveTuple.parseIp(ipStr));
    }

    public void unblockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIPs.remove(ip);
            System.out.println("[RuleManager] Unblocked IP: " + FiveTuple.ipToString(ip));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public void unblockIP(String ipStr) {
        unblockIP(FiveTuple.parseIp(ipStr));
    }

    public boolean isIPBlocked(int ip) {
        ipLock.readLock().lock();
        try {
            return blockedIPs.contains(ip);
        } finally {
            ipLock.readLock().unlock();
        }
    }

    public List<String> getBlockedIPs() {
        ipLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (int ip : blockedIPs) result.add(FiveTuple.ipToString(ip));
            return result;
        } finally {
            ipLock.readLock().unlock();
        }
    }

    // ====================================================================
    // App Blocking
    // ====================================================================

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
            System.out.println("[RuleManager] Blocked app: " + app.displayName());
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.remove(app);
            System.out.println("[RuleManager] Unblocked app: " + app.displayName());
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appLock.readLock().unlock();
        }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try {
            return new ArrayList<>(blockedApps);
        } finally {
            appLock.readLock().unlock();
        }
    }

    // ====================================================================
    // Domain Blocking
    // ====================================================================

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
            System.out.println("[RuleManager] Blocked domain: " + domain);
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.remove(domain);
            } else {
                blockedDomains.remove(domain);
            }
            System.out.println("[RuleManager] Unblocked domain: " + domain);
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(domain)) return true;
            String lower = domain.toLowerCase(Locale.ROOT);
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lower, pattern.toLowerCase(Locale.ROOT))) return true;
            }
            return false;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    /**
     * Wildcard domain pattern matching.
     * "*.example.com" matches "www.example.com" and "example.com".
     */
    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.startsWith("*.") && pattern.length() >= 2) {
            String suffix = pattern.substring(1); // ".example.com"
            if (domain.endsWith(suffix)) return true;
            // Also match the bare domain (example.com)
            if (domain.equals(pattern.substring(2))) return true;
        }
        return false;
    }

    // ====================================================================
    // Port Blocking
    // ====================================================================

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port);
            System.out.println("[RuleManager] Blocked port: " + port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.remove(port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            portLock.readLock().unlock();
        }
    }

    // ====================================================================
    // Combined Check
    // ====================================================================

    /**
     * Check if a packet should be blocked based on all current rules.
     *
     * @return A BlockReason if blocked, or null if the packet should be allowed.
     */
    public BlockReason shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (isIPBlocked(srcIp)) {
            return new BlockReason(BlockReason.Type.IP, FiveTuple.ipToString(srcIp));
        }
        if (isPortBlocked(dstPort)) {
            return new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort));
        }
        if (app != null && isAppBlocked(app)) {
            return new BlockReason(BlockReason.Type.APP, app.displayName());
        }
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return new BlockReason(BlockReason.Type.DOMAIN, domain);
        }
        return null;
    }

    /** Reason why a packet was blocked. */
    public static class BlockReason {
        public enum Type { IP, APP, DOMAIN, PORT }
        public final Type   type;
        public final String detail;

        public BlockReason(Type type, String detail) {
            this.type   = type;
            this.detail = detail;
        }

        @Override public String toString() {
            return type + ":" + detail;
        }
    }

    // ====================================================================
    // Persistence
    // ====================================================================

    /** Save all current rules to a file. */
    public boolean saveRules(String filename) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(filename))) {
            pw.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIPs()) pw.println(ip);

            pw.println();
            pw.println("[BLOCKED_APPS]");
            for (AppType app : getBlockedApps()) pw.println(app.displayName());

            pw.println();
            pw.println("[BLOCKED_DOMAINS]");
            for (String d : getBlockedDomains()) pw.println(d);

            pw.println();
            pw.println("[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try {
                for (int p : blockedPorts) pw.println(p);
            } finally {
                portLock.readLock().unlock();
            }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Failed to save rules: " + e.getMessage());
            return false;
        }
    }

    /** Load rules from a file (same format as saveRules). */
    public boolean loadRules(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            String section = "";
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) {
                    section = line;
                    continue;
                }
                switch (section) {
                    case "[BLOCKED_IPS]":
                        blockIP(line);
                        break;
                    case "[BLOCKED_APPS]":
                        AppType app = AppType.fromDisplayName(line);
                        if (app != null) blockApp(app);
                        break;
                    case "[BLOCKED_DOMAINS]":
                        blockDomain(line);
                        break;
                    case "[BLOCKED_PORTS]":
                        try { blockPort(Integer.parseInt(line)); } catch (NumberFormatException ignored) {}
                        break;
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Failed to load rules: " + e.getMessage());
            return false;
        }
    }

    /** Clear all rules. */
    public void clearAll() {
        ipLock.writeLock().lock();     try { blockedIPs.clear();     } finally { ipLock.writeLock().unlock(); }
        appLock.writeLock().lock();    try { blockedApps.clear();    } finally { appLock.writeLock().unlock(); }
        domainLock.writeLock().lock(); try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }
        portLock.writeLock().lock();   try { blockedPorts.clear();   } finally { portLock.writeLock().unlock(); }
        System.out.println("[RuleManager] All rules cleared");
    }

    /** Rule count statistics. */
    public RuleStats getStats() {
        return new RuleStats(
            blockedIPs.size(),
            blockedApps.size(),
            blockedDomains.size() + domainPatterns.size(),
            blockedPorts.size()
        );
    }

    public static class RuleStats {
        public final int blockedIPs;
        public final int blockedApps;
        public final int blockedDomains;
        public final int blockedPorts;
        RuleStats(int ips, int apps, int domains, int ports) {
            blockedIPs = ips; blockedApps = apps; blockedDomains = domains; blockedPorts = ports;
        }
    }
}
