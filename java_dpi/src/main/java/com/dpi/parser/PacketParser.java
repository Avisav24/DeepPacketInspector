package com.dpi.parser;

import com.dpi.pcap.RawPacket;
import com.dpi.types.FiveTuple;

/**
 * Parses raw packet bytes into a structured ParsedPacket.
 * Handles Ethernet → IPv4 → TCP/UDP header chain.
 *
 * Maps to PacketParser in packet_parser.h / packet_parser.cpp.
 *
 * IMPORTANT: Java bytes are signed (-128..127). All reads use (b & 0xFF)
 * to treat them as unsigned values (0..255).
 */
public class PacketParser {

    // EtherType values
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    // Protocol numbers
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // TCP flag bits
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    /**
     * Parse a raw packet into a ParsedPacket.
     *
     * @param raw The raw packet from PcapReader.
     * @return A ParsedPacket, or null if the packet is malformed or too short.
     */
    public static ParsedPacket parse(RawPacket raw) {
        if (raw == null || raw.data == null) return null;

        ParsedPacket p = new ParsedPacket();
        p.timestampSec  = raw.tsSec;
        p.timestampUsec = raw.tsUsec;

        byte[] data = raw.data;
        int len = data.length;
        int offset = 0;

        // ── Ethernet Header (14 bytes) ─────────────────────────────────────
        if (len < 14) return null;

        p.destMac  = macToString(data, 0);
        p.srcMac   = macToString(data, 6);
        // EtherType at bytes 12-13 (big-endian)
        p.etherType = readUint16BE(data, 12);
        offset = 14;

        // ── IPv4 Header ────────────────────────────────────────────────────
        if (p.etherType == ETHERTYPE_IPV4) {
            if (len < offset + 20) return null; // Packet too short for IP header

            int versionIhl = data[offset] & 0xFF;
            p.ipVersion    = (versionIhl >> 4) & 0x0F;
            int ihl        = versionIhl & 0x0F;

            if (p.ipVersion != 4) return null; // Not IPv4

            int ipHeaderLen = ihl * 4;
            if (ipHeaderLen < 20 || len < offset + ipHeaderLen) return null;

            p.ttl      = data[offset + 8] & 0xFF;
            p.protocol = data[offset + 9] & 0xFF;

            p.srcIpBytes = new byte[4];
            p.dstIpBytes = new byte[4];
            System.arraycopy(data, offset + 12, p.srcIpBytes, 0, 4);
            System.arraycopy(data, offset + 16, p.dstIpBytes, 0, 4);
            p.srcIp = FiveTuple.ipToString(p.srcIpBytes);
            p.dstIp = FiveTuple.ipToString(p.dstIpBytes);

            p.hasIp = true;
            offset += ipHeaderLen;

        // ── IPv6 Header ────────────────────────────────────────────────────
        } else if (p.etherType == ETHERTYPE_IPV6) {
            if (len < offset + 40) return null; // IPv6 header is 40 bytes fixed

            int versionClassFlow = data[offset] & 0xFF;
            p.ipVersion = (versionClassFlow >> 4) & 0x0F;

            if (p.ipVersion != 6) return null; // Not IPv6

            p.protocol = data[offset + 6] & 0xFF; // Next Header
            p.ttl      = data[offset + 7] & 0xFF; // Hop Limit

            p.srcIpBytes = new byte[16];
            p.dstIpBytes = new byte[16];
            System.arraycopy(data, offset + 8, p.srcIpBytes, 0, 16);
            System.arraycopy(data, offset + 24, p.dstIpBytes, 0, 16);
            p.srcIp = FiveTuple.ipToString(p.srcIpBytes);
            p.dstIp = FiveTuple.ipToString(p.dstIpBytes);

            p.hasIp = true;
            p.hasIpV6 = true;
            offset += 40;

            // Simplified: If next header is an extension header (e.g. 0=Hop-by-Hop),
            // we'd need to skip it. For this basic DPI, we just assume TCP/UDP are 
            // directly next. If not, it won't match TCP/UDP and will be skipped.
        } else {
            // Not IPv4/IPv6 — return what we have
            return p;
        }

        // ── TCP Header ─────────────────────────────────────────────────────
        if (p.protocol == PROTO_TCP) {
            if (len < offset + 20) return null;

            p.srcPort   = readUint16BE(data, offset);
            p.dstPort   = readUint16BE(data, offset + 2);
            p.seqNumber = readUint32BE(data, offset + 4);
            p.ackNumber = readUint32BE(data, offset + 8);

            int dataOffset = (data[offset + 12] >> 4) & 0x0F;
            int tcpHeaderLen = dataOffset * 4;
            p.tcpFlags = data[offset + 13] & 0xFF;

            if (tcpHeaderLen < 20 || len < offset + tcpHeaderLen) return null;

            p.hasTcp = true;
            offset += tcpHeaderLen;

        // ── UDP Header ─────────────────────────────────────────────────────
        } else if (p.protocol == PROTO_UDP) {
            if (len < offset + 8) return null;

            p.srcPort = readUint16BE(data, offset);
            p.dstPort = readUint16BE(data, offset + 2);

            p.hasUdp = true;
            offset += 8;
        }

        // ── Payload ────────────────────────────────────────────────────────
        if (offset < len) {
            p.payloadOffset = offset;
            p.payloadLength = len - offset;
        }

        return p;
    }

    // ── Helper methods ────────────────────────────────────────────────────

    /** Read a 16-bit big-endian unsigned value from a byte array. */
    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /** Read a 32-bit big-endian unsigned value from a byte array (as long). */
    public static long readUint32BE(byte[] data, int offset) {
        return ((data[offset]     & 0xFFL) << 24) |
               ((data[offset + 1] & 0xFFL) << 16) |
               ((data[offset + 2] & 0xFFL) << 8)  |
               ((data[offset + 3] & 0xFFL));
    }

    /** Format a 6-byte MAC address as "aa:bb:cc:dd:ee:ff". */
    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    /** Format TCP flags as a string like "SYN ACK". */
    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_RST) != 0) sb.append("RST ");
        if ((flags & TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_URG) != 0) sb.append("URG ");
        String s = sb.toString().trim();
        return s.isEmpty() ? "none" : s;
    }

    /** Protocol number to string. */
    public static String protocolToString(int protocol) {
        switch (protocol) {
            case PROTO_ICMP: return "ICMP";
            case PROTO_TCP:  return "TCP";
            case PROTO_UDP:  return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }
}
