package com.dpi.engine;

import com.dpi.types.FiveTuple;
import com.dpi.types.PacketJob;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load Balancer thread — distributes incoming packets to Fast Path Processors.
 *
 * Uses consistent hashing on the five-tuple so that all packets belonging to
 * the same connection always go to the same FP thread. This is critical for
 * correct per-flow connection tracking and DPI.
 *
 * Maps to LoadBalancer in load_balancer.h / load_balancer.cpp.
 */
public class LoadBalancer implements Runnable {

    private final int lbId;
    private final int fpStartId;
    private final List<ThreadSafeQueue> fpQueues;

    private final ThreadSafeQueue inputQueue;
    private volatile boolean running = false;
    private Thread thread;

    // Statistics
    private final AtomicLong packetsReceived   = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);
    private final long[] perFpCounts;

    /**
     * @param lbId       ID of this load balancer (0, 1, …)
     * @param fpQueues   Input queues of the FP threads this LB serves
     * @param fpStartId  FP ID offset (for labeling — not used for routing)
     */
    public LoadBalancer(int lbId, List<ThreadSafeQueue> fpQueues, int fpStartId) {
        this.lbId      = lbId;
        this.fpQueues  = fpQueues;
        this.fpStartId = fpStartId;
        this.inputQueue  = new ThreadSafeQueue(10_000);
        this.perFpCounts = new long[fpQueues.size()];
    }

    public void start() {
        running = true;
        thread = new Thread(this, "LB-" + lbId);
        thread.setDaemon(false);
        thread.start();
    }

    public void stop() {
        running = false;
        inputQueue.shutdown();
    }

    public void join() throws InterruptedException {
        if (thread != null) thread.join(5000);
    }

    @Override
    public void run() {
        while (running || !inputQueue.isEmpty()) {
            PacketJob job = inputQueue.pop(100);
            if (job == null) continue;

            packetsReceived.incrementAndGet();

            int fpIndex = selectFP(job.tuple);
            fpQueues.get(fpIndex).push(job);

            perFpCounts[fpIndex]++;
            packetsDispatched.incrementAndGet();
        }
    }

    /**
     * Select the target FP thread index using the five-tuple hash.
     * Consistent: same flow always maps to the same FP.
     */
    private int selectFP(FiveTuple tuple) {
        // Use Java's own hashCode (which we defined to mirror the C++ boost-hash)
        int hash = tuple.hashCode();
        // Ensure positive index
        return Math.abs(hash) % fpQueues.size();
    }

    public ThreadSafeQueue getInputQueue()  { return inputQueue; }
    public int getId()                       { return lbId; }
    public boolean isRunning()               { return running; }
    public long getPacketsReceived()         { return packetsReceived.get(); }
    public long getPacketsDispatched()       { return packetsDispatched.get(); }
}
