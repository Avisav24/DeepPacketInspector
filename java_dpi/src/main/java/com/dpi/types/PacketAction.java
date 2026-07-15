package com.dpi.types;

/** What to do with a packet. Maps to PacketAction enum in types.h. */
public enum PacketAction {
    FORWARD,    // Send to internet
    DROP,       // Block/drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
}
