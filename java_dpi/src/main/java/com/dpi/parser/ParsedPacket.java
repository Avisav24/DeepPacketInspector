package com.dpi.parser;

/**
 * Structured packet information after parsing.
 * Maps to ParsedPacket struct in packet_parser.h.
 */
public class ParsedPacket {

    // Timestamps
    public long timestampSec;
    public long timestampUsec;

    // Ethernet layer
    public String srcMac;
    public String destMac;
    public int etherType;

    // IP layer
    public boolean hasIp      = false;
    public boolean hasIpV6    = false;
    public int     ipVersion;
    public String  srcIp;
    public String  dstIp;
    public byte[]  srcIpBytes;
    public byte[]  dstIpBytes;
    public int     protocol;  // TCP=6, UDP=17, ICMP=1
    public int     ttl;

    // Transport layer
    public boolean hasUdp     = false;
    public boolean hasTcp     = false;
    public int     srcPort;
    public int     dstPort;

    // TCP specific
    public int  tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // Payload (indices into the original data array)
    public int payloadOffset = 0;
    public int payloadLength = 0;
}
