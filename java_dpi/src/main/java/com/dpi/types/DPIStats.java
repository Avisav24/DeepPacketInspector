package com.dpi.types;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Global engine statistics using lock-free AtomicLong counters.
 * Maps to the DPIStats struct in types.h.
 */
public class DPIStats {

    public final AtomicLong totalPackets       = new AtomicLong(0);
    public final AtomicLong totalBytes         = new AtomicLong(0);
    public final AtomicLong forwardedPackets   = new AtomicLong(0);
    public final AtomicLong droppedPackets     = new AtomicLong(0);
    public final AtomicLong tcpPackets         = new AtomicLong(0);
    public final AtomicLong udpPackets         = new AtomicLong(0);
    public final AtomicLong otherPackets       = new AtomicLong(0);
    public final AtomicLong activeConnections  = new AtomicLong(0);
}
