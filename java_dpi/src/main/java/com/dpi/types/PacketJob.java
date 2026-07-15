package com.dpi.types;

/**
 * Packet wrapper passed between threads in the pipeline.
 * Maps to the PacketJob struct in types.h.
 */
public class PacketJob {

    public int packetId;
    public FiveTuple tuple;

    /** Raw packet bytes (copy of the PCAP packet data). */
    public byte[] data;

    public int ethOffset       = 0;
    public int ipOffset        = 0;
    public int transportOffset = 0;
    public int payloadOffset   = 0;
    public int payloadLength   = 0;
    public int tcpFlags        = 0;

    /** Timestamps from PCAP packet header (seconds and microseconds). */
    public long tsSec;
    public long tsUsec;

    public PacketJob() {}

    /**
     * Get a view of the payload bytes, or an empty array if none.
     */
    public byte[] getPayload() {
        if (payloadLength <= 0 || payloadOffset + payloadLength > data.length) {
            return new byte[0];
        }
        byte[] payload = new byte[payloadLength];
        System.arraycopy(data, payloadOffset, payload, 0, payloadLength);
        return payload;
    }
}
