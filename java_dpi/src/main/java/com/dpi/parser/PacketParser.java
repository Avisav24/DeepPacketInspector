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
        if (p.etherType != ETHERTYPE_IPV4) {
            // Not IPv4 — return what we have (no transport layer)
            return p;
        }

        if (len < offset + 20) return null; // Packet too short for IP header

        int versionIhl = data[offset] & 0xFF;
        p.ipVersion    = (versionIhl >> 4) & 0x0F;
        int ihl        = versionIhl & 0x0F;

        if (p.ipVersion != 4) return null; // Not IPv4

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < 20 || len < offset + ipHeaderLen) return null;

        p.ttl      = data[offset + 8] & 0xFF;
        p.protocol = data[offset + 9] & 0xFF;

        // Source IP (bytes 12-15 of IP header)
        p.srcIpInt  = readIp(data, offset + 12);
        p.dstIpInt  = readIp(data, offset + 16);
        p.srcIp     = FiveTuple.ipToString(p.srcIpInt);
        p.dstIp     = FiveTuple.ipToString(p.dstIpInt);

        p.hasIp = true;
        offset += ipHeaderLen;

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

    /**
     * Read a 32-bit IPv4 address stored in network byte order (big-endian in the packet).
     * Returns it as an int where byte[0] is in the least-significant position —
     * matching the C++ implementation's little-endian storage.
     */
    static int readIp(byte[] data, int offset) {
        // C++ stores IP in "natural" order: first octet in lowest byte
        return  (data[offset]     & 0xFF)        |
               ((data[offset + 1] & 0xFF) << 8)  |
               ((data[offset + 2] & 0xFF) << 16) |
               ((data[offset + 3] & 0xFF) << 24);
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
