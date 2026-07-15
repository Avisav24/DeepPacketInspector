package com.dpi.pcap;

/**
 * Represents a single raw packet read from a PCAP file.
 * Maps to the RawPacket struct in pcap_reader.h.
 */
public class RawPacket {

    /** Timestamp seconds (from PCAP packet header). */
    public long tsSec;

    /** Timestamp microseconds (from PCAP packet header). */
    public long tsUsec;

    /** Actual captured length (incl_len from PCAP packet header). */
    public int inclLen;

    /** Original packet length (orig_len — may differ from inclLen if truncated). */
    public int origLen;

    /** Raw packet bytes. Length == inclLen. */
    public byte[] data;
}
