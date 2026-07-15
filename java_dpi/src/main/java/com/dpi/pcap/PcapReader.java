package com.dpi.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads packets from a .pcap file without any external library.
 * Handles both native (little-endian) and byte-swapped (big-endian) PCAP files.
 *
 * PCAP File Format:
 *   Global Header (24 bytes)
 *   Repeated:
 *     Packet Header (16 bytes)
 *     Packet Data (packet_header.incl_len bytes)
 *
 * Maps to PcapReader in pcap_reader.h / pcap_reader.cpp.
 */
public class PcapReader implements Closeable {

    // PCAP magic numbers
    private static final long PCAP_MAGIC_NATIVE  = 0xa1b2c3d4L; // little-endian file
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L; // big-endian file

    private InputStream stream;
    private boolean needsByteSwap = false;

    // Global header fields
    public int versionMajor;
    public int versionMinor;
    public long snaplen;
    public long network;

    /**
     * Open a PCAP file for reading.
     *
     * @param filename Path to the .pcap file.
     * @return true if opened and global header is valid.
     */
    public boolean open(String filename) {
        close();
        try {
            stream = new BufferedInputStream(new FileInputStream(filename));
            return readGlobalHeader(filename);
        } catch (FileNotFoundException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }
    }

    private boolean readGlobalHeader(String filename) {
        try {
            byte[] hdr = new byte[24];
            if (!readFully(hdr)) {
                System.err.println("Error: Could not read PCAP global header");
                return false;
            }

            // Read magic number (first 4 bytes) in native byte order to detect endianness
            long magic = ((hdr[0] & 0xFFL))       |
                         ((hdr[1] & 0xFFL) << 8)  |
                         ((hdr[2] & 0xFFL) << 16) |
                         ((hdr[3] & 0xFFL) << 24);

            if (magic == PCAP_MAGIC_NATIVE) {
                needsByteSwap = false;
            } else if (magic == PCAP_MAGIC_SWAPPED) {
                needsByteSwap = true;
            } else {
                System.err.printf("Error: Invalid PCAP magic number: 0x%08X%n", magic);
                return false;
            }

            // Parse the rest of the global header (bytes 4-23)
            ByteBuffer buf = ByteBuffer.wrap(hdr, 4, 20);
            buf.order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

            versionMajor = buf.getShort() & 0xFFFF;
            versionMinor = buf.getShort() & 0xFFFF;
            buf.getInt(); // thiszone (GMT offset — ignored)
            buf.getInt(); // sigfigs  (timestamp accuracy — ignored)
            snaplen      = buf.getInt() & 0xFFFFFFFFL;
            network      = buf.getInt() & 0xFFFFFFFFL;

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + versionMajor + "." + versionMinor);
            System.out.println("  Snaplen: " + snaplen + " bytes");
            System.out.println("  Link type: " + network + (network == 1 ? " (Ethernet)" : ""));

            return true;
        } catch (Exception e) {
            System.err.println("Error reading PCAP global header: " + e.getMessage());
            return false;
        }
    }

    /**
     * Read the next packet from the file.
     *
     * @param packet Output packet to populate.
     * @return true if a packet was read, false at end-of-file or on error.
     */
    public boolean readNextPacket(RawPacket packet) {
        if (stream == null) return false;

        try {
            // Read 16-byte packet header
            byte[] phdr = new byte[16];
            if (!readFully(phdr)) {
                return false; // EOF
            }

            ByteBuffer buf = ByteBuffer.wrap(phdr);
            buf.order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

            packet.tsSec   = buf.getInt() & 0xFFFFFFFFL;
            packet.tsUsec  = buf.getInt() & 0xFFFFFFFFL;
            packet.inclLen = (int)(buf.getInt() & 0xFFFFFFFFL);
            packet.origLen = (int)(buf.getInt() & 0xFFFFFFFFL);

            // Sanity check
            if (packet.inclLen > snaplen || packet.inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + packet.inclLen);
                return false;
            }

            // Read packet data
            packet.data = new byte[packet.inclLen];
            if (!readFully(packet.data)) {
                System.err.println("Error: Could not read packet data");
                return false;
            }

            return true;

        } catch (Exception e) {
            return false; // EOF or IO error
        }
    }

    /** Read exactly buf.length bytes, returning false if EOF before that. */
    private boolean readFully(byte[] buf) {
        try {
            int offset = 0;
            while (offset < buf.length) {
                int read = stream.read(buf, offset, buf.length - offset);
                if (read < 0) return false;
                offset += read;
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public void close() {
        if (stream != null) {
            try { stream.close(); } catch (IOException ignored) {}
            stream = null;
        }
        needsByteSwap = false;
    }

    public boolean isNeedsByteSwap() {
        return needsByteSwap;
    }

    /**
     * Write a PCAP global header to an output stream (for the output file).
     * Always writes in little-endian (native) format.
     */
    public static void writeGlobalHeader(OutputStream out,
                                          int versionMajor, int versionMinor,
                                          long snaplen, long network) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) PCAP_MAGIC_NATIVE);
        buf.putShort((short) versionMajor);
        buf.putShort((short) versionMinor);
        buf.putInt(0);            // thiszone
        buf.putInt(0);            // sigfigs
        buf.putInt((int) snaplen);
        buf.putInt((int) network);
        out.write(buf.array());
    }

    /**
     * Write a single packet (header + data) to an output stream.
     */
    public static void writePacket(OutputStream out, RawPacket pkt) throws IOException {
        ByteBuffer hdr = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        hdr.putInt((int) pkt.tsSec);
        hdr.putInt((int) pkt.tsUsec);
        hdr.putInt(pkt.inclLen);
        hdr.putInt(pkt.origLen);
        out.write(hdr.array());
        out.write(pkt.data, 0, pkt.inclLen);
    }
}
