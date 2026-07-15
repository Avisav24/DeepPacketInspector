package com.dpi.pcap;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.io.Closeable;

/**
 * Reads packets from a live network interface using Pcap4J.
 */
public class LivePcapReader implements Closeable {

    private PcapHandle handle;

    /**
     * Open a network interface for live capture.
     * 
     * @param interfaceName The name of the interface (e.g., "eth0", "en0")
     * @return true if successfully opened.
     */
    public boolean open(String interfaceName) {
        try {
            PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
            if (nif == null) {
                System.err.println("Error: Interface not found: " + interfaceName);
                return false;
            }

            int snapLen = 65536;           // Capture all bytes
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 10;              // in milliseconds

            handle = nif.openLive(snapLen, mode, timeout);

            System.out.println("Opened Live Interface: " + nif.getName());
            if (nif.getDescription() != null) {
                System.out.println("  Description: " + nif.getDescription());
            }

            return true;
        } catch (PcapNativeException e) {
            System.err.println("Error opening interface: " + e.getMessage());
            return false;
        }
    }

    /**
     * Read the next packet from the live interface.
     * This method will block until a packet arrives or timeout occurs.
     * 
     * @param rawPacket Output packet to populate.
     * @return true if a packet was read, false if no packet (timeout) or error.
     */
    public boolean readNextPacket(RawPacket rawPacket) {
        if (handle == null) return false;

        try {
            Packet packet = handle.getNextPacket();
            if (packet == null) {
                return false; // Timeout
            }

            // Fill RawPacket fields
            rawPacket.data = packet.getRawData();
            rawPacket.inclLen = rawPacket.data.length;
            rawPacket.origLen = rawPacket.data.length;
            rawPacket.tsSec = handle.getTimestamp().getTime() / 1000;
            rawPacket.tsUsec = handle.getTimestamp().getNanos() / 1000;

            return true;

        } catch (NotOpenException e) {
            return false;
        }
    }

    @Override
    public void close() {
        if (handle != null) {
            handle.close();
            handle = null;
        }
    }
}
