package com.dpi.types;

import java.util.Arrays;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Five-tuple that uniquely identifies a network connection/flow.
 *
 * Supports both IPv4 (4 bytes) and IPv6 (16 bytes).
 */
public final class FiveTuple {

    public final byte[] srcIp;   // 4 bytes for IPv4, 16 for IPv6
    public final byte[] dstIp;   // 4 bytes for IPv4, 16 for IPv6
    public final int srcPort;    // 0–65535
    public final int dstPort;    // 0–65535
    public final int protocol;   // TCP=6, UDP=17

    public FiveTuple(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort, int protocol) {
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
        return srcPort  == other.srcPort  &&
               dstPort  == other.dstPort  &&
               protocol == other.protocol &&
               Arrays.equals(srcIp, other.srcIp) &&
               Arrays.equals(dstIp, other.dstIp);
    }

    @Override
    public int hashCode() {
        long h = 0;
        h = combineBytes(h, srcIp);
        h = combineBytes(h, dstIp);
        h = combine(h, srcPort & 0xFFFFL);
        h = combine(h, dstPort & 0xFFFFL);
        h = combine(h, protocol & 0xFFL);
        return (int)(h ^ (h >>> 32));
    }

    private static long combineBytes(long h, byte[] bytes) {
        if (bytes == null) return h;
        for (byte b : bytes) {
            h = combine(h, b & 0xFFL);
        }
        return h;
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

    /** Convert a byte array IP to its string representation. */
    public static String ipToString(byte[] ip) {
        if (ip == null) return "null";
        try {
            return InetAddress.getByAddress(ip).getHostAddress();
        } catch (UnknownHostException e) {
            return "<invalid ip>";
        }
    }

    /**
     * Parse a string IP (IPv4 or IPv6) into a byte array.
     */
    public static byte[] parseIp(String ip) {
        if (ip == null || ip.isEmpty()) return null;
        try {
            return InetAddress.getByName(ip).getAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
