package com.dpi.types;

import java.util.Objects;

/**
 * Five-tuple that uniquely identifies a network connection/flow.
 * Maps to the FiveTuple struct in types.h.
 *
 * IPs are stored as int (Java has no unsigned int) — use Integer.toUnsignedLong()
 * when doing arithmetic comparisons.
 * Ports and protocol are stored as int with only the lower bits used.
 */
public final class FiveTuple {

    public final int srcIp;      // 32-bit IPv4 address (network byte order)
    public final int dstIp;      // 32-bit IPv4 address (network byte order)
    public final int srcPort;    // 0–65535
    public final int dstPort;    // 0–65535
    public final int protocol;   // TCP=6, UDP=17

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    /** Create the reverse tuple (for bidirectional flow matching). */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple other = (FiveTuple) o;
        return srcIp    == other.srcIp    &&
               dstIp    == other.dstIp    &&
               srcPort  == other.srcPort  &&
               dstPort  == other.dstPort  &&
               protocol == other.protocol;
    }

    @Override
    public int hashCode() {
        // Mirrors the C++ FiveTupleHash — boost-style hash combining
        long h = 0;
        h = combine(h, Integer.toUnsignedLong(srcIp));
        h = combine(h, Integer.toUnsignedLong(dstIp));
        h = combine(h, srcPort & 0xFFFFL);
        h = combine(h, dstPort & 0xFFFFL);
        h = combine(h, protocol & 0xFFL);
        return (int)(h ^ (h >>> 32));
    }

    private static long combine(long h, long value) {
        h ^= value + 0x9e3779b9L + (h << 6) + (h >>> 2);
        return h;
    }

    /** Format as "src_ip:src_port -> dst_ip:dst_port (PROTO)". */
    @Override
    public String toString() {
        return ipToString(srcIp) + ":" + srcPort +
               " -> " +
               ipToString(dstIp) + ":" + dstPort +
               " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
    }

    /** Convert a 32-bit IP int (in network byte order) to dotted-decimal. */
    public static String ipToString(int ip) {
        // Network byte order: byte 0 is most significant
        return ((ip >>> 0) & 0xFF) + "." +
               ((ip >>> 8) & 0xFF) + "." +
               ((ip >>> 16) & 0xFF) + "." +
               ((ip >>> 24) & 0xFF);
    }

    /**
     * Parse a dotted-decimal IP string into a 32-bit int.
     * Stored in "little-endian" order matching the C++ implementation
     * (first octet in lowest byte).
     */
    public static int parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return 0;
        try {
            int result = 0;
            for (int i = 0; i < 4; i++) {
                result |= (Integer.parseInt(parts[i]) & 0xFF) << (i * 8);
            }
            return result;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
