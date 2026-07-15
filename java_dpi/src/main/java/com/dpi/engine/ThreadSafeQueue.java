package com.dpi.engine;

import com.dpi.types.PacketJob;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Thread-safe bounded queue for passing PacketJob objects between pipeline stages.
 * Wraps Java's LinkedBlockingQueue and adds a "shutdown" flag so consumer threads
 * can drain and exit cleanly.
 *
 * Maps to ThreadSafeQueue<T> in thread_safe_queue.h.
 */
public class ThreadSafeQueue {

    private final LinkedBlockingQueue<PacketJob> queue;
    private volatile boolean shutdown = false;

    public ThreadSafeQueue(int maxSize) {
        this.queue = new LinkedBlockingQueue<>(maxSize);
    }

    public ThreadSafeQueue() {
        this(10_000);
    }

    /**
     * Push a packet. Blocks if the queue is full (back-pressure).
     * Returns immediately if the queue is shut down.
     */
    public void push(PacketJob job) {
        if (shutdown) return;
        try {
            // Use offer with timeout so we can check the shutdown flag
            while (!shutdown) {
                if (queue.offer(job, 100, TimeUnit.MILLISECONDS)) return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Try to push without blocking.
     * @return true if pushed, false if queue is full or shut down.
     */
    public boolean tryPush(PacketJob job) {
        if (shutdown) return false;
        return queue.offer(job);
    }

    /**
     * Pop a packet, waiting up to timeoutMs milliseconds.
     * @return The packet, or null on timeout or shutdown.
     */
    public PacketJob pop(long timeoutMs) {
        try {
            return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * Pop a packet, blocking indefinitely until one is available or shutdown.
     */
    public PacketJob pop() {
        try {
            while (!shutdown || !queue.isEmpty()) {
                PacketJob job = queue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) return job;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return null;
    }

    /** Signal shutdown — wakes all waiting threads. */
    public void shutdown() {
        this.shutdown = true;
    }

    public boolean isShutdown() {
        return shutdown;
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }

    public int size() {
        return queue.size();
    }
}
