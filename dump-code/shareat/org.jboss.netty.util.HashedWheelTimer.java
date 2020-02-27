package org.jboss.netty.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.internal.ConcurrentIdentityHashMap;
import org.jboss.netty.util.internal.DetectionUtil;
import org.jboss.netty.util.internal.ReusableIterator;
import org.jboss.netty.util.internal.SharedResourceMisuseDetector;

public class HashedWheelTimer implements Timer {
    public static final int WORKER_STATE_INIT = 0;
    public static final int WORKER_STATE_SHUTDOWN = 2;
    public static final int WORKER_STATE_STARTED = 1;
    private static final AtomicInteger id = new AtomicInteger();
    static final InternalLogger logger = InternalLoggerFactory.getInstance(HashedWheelTimer.class);
    private static final SharedResourceMisuseDetector misuseDetector = new SharedResourceMisuseDetector(HashedWheelTimer.class);
    final ReusableIterator<HashedWheelTimeout>[] iterators;
    final ReadWriteLock lock;
    final int mask;
    volatile long startTime;
    final CountDownLatch startTimeInitialized;
    volatile long tick;
    final long tickDuration;
    final Set<HashedWheelTimeout>[] wheel;
    private final Worker worker;
    final AtomicInteger workerState;
    final Thread workerThread;

    private final class HashedWheelTimeout implements Timeout {
        private static final int ST_CANCELLED = 1;
        private static final int ST_EXPIRED = 2;
        private static final int ST_INIT = 0;
        final long deadline;
        volatile long remainingRounds;
        private final AtomicInteger state = new AtomicInteger(0);
        final int stopIndex;
        private final TimerTask task;

        HashedWheelTimeout(TimerTask task2, long deadline2) {
            this.task = task2;
            this.deadline = deadline2;
            long calculated = deadline2 / HashedWheelTimer.this.tickDuration;
            this.stopIndex = (int) (((long) HashedWheelTimer.this.mask) & Math.max(calculated, HashedWheelTimer.this.tick));
            this.remainingRounds = (calculated - HashedWheelTimer.this.tick) / ((long) HashedWheelTimer.this.wheel.length);
        }

        public Timer getTimer() {
            return HashedWheelTimer.this;
        }

        public TimerTask getTask() {
            return this.task;
        }

        public void cancel() {
            if (this.state.compareAndSet(0, 1)) {
                HashedWheelTimer.this.wheel[this.stopIndex].remove(this);
            }
        }

        public boolean isCancelled() {
            return this.state.get() == 1;
        }

        public boolean isExpired() {
            return this.state.get() != 0;
        }

        public void expire() {
            if (this.state.compareAndSet(0, 2)) {
                try {
                    this.task.run(this);
                } catch (Throwable t) {
                    if (HashedWheelTimer.logger.isWarnEnabled()) {
                        HashedWheelTimer.logger.warn("An exception was thrown by " + TimerTask.class.getSimpleName() + '.', t);
                    }
                }
            }
        }

        public String toString() {
            long remaining = (this.deadline - System.nanoTime()) + HashedWheelTimer.this.startTime;
            StringBuilder buf = new StringBuilder(192);
            buf.append(getClass().getSimpleName());
            buf.append('(');
            buf.append("deadline: ");
            if (remaining > 0) {
                buf.append(remaining);
                buf.append(" ns later");
            } else if (remaining < 0) {
                buf.append(-remaining);
                buf.append(" ns ago");
            } else {
                buf.append("now");
            }
            if (isCancelled()) {
                buf.append(", cancelled");
            }
            buf.append(", task: ");
            buf.append(getTask());
            return buf.append(')').toString();
        }
    }

    private final class Worker implements Runnable {
        Worker() {
        }

        public void run() {
            HashedWheelTimer.this.startTime = System.nanoTime();
            if (HashedWheelTimer.this.startTime == 0) {
                HashedWheelTimer.this.startTime = 1;
            }
            HashedWheelTimer.this.startTimeInitialized.countDown();
            List<HashedWheelTimeout> expiredTimeouts = new ArrayList<>();
            do {
                long deadline = waitForNextTick();
                if (deadline > 0) {
                    fetchExpiredTimeouts(expiredTimeouts, deadline);
                    notifyExpiredTimeouts(expiredTimeouts);
                }
            } while (HashedWheelTimer.this.workerState.get() == 1);
        }

        private void fetchExpiredTimeouts(List<HashedWheelTimeout> expiredTimeouts, long deadline) {
            HashedWheelTimer.this.lock.writeLock().lock();
            try {
                fetchExpiredTimeouts(expiredTimeouts, HashedWheelTimer.this.iterators[(int) (HashedWheelTimer.this.tick & ((long) HashedWheelTimer.this.mask))], deadline);
            } finally {
                HashedWheelTimer.this.tick++;
                HashedWheelTimer.this.lock.writeLock().unlock();
            }
        }

        private void fetchExpiredTimeouts(List<HashedWheelTimeout> expiredTimeouts, ReusableIterator<HashedWheelTimeout> i, long deadline) {
            i.rewind();
            while (i.hasNext()) {
                HashedWheelTimeout timeout = (HashedWheelTimeout) i.next();
                if (timeout.remainingRounds <= 0) {
                    i.remove();
                    if (timeout.deadline <= deadline) {
                        expiredTimeouts.add(timeout);
                    } else {
                        throw new Error(String.format("timeout.deadline (%d) > deadline (%d)", new Object[]{Long.valueOf(timeout.deadline), Long.valueOf(deadline)}));
                    }
                } else {
                    timeout.remainingRounds--;
                }
            }
        }

        private void notifyExpiredTimeouts(List<HashedWheelTimeout> expiredTimeouts) {
            for (int i = expiredTimeouts.size() - 1; i >= 0; i--) {
                expiredTimeouts.get(i).expire();
            }
            expiredTimeouts.clear();
        }

        private long waitForNextTick() {
            long deadline = HashedWheelTimer.this.tickDuration * (HashedWheelTimer.this.tick + 1);
            while (true) {
                long currentTime = System.nanoTime() - HashedWheelTimer.this.startTime;
                long sleepTimeMs = ((deadline - currentTime) + 999999) / 1000000;
                if (sleepTimeMs > 0) {
                    if (DetectionUtil.isWindows()) {
                        sleepTimeMs = (sleepTimeMs / 10) * 10;
                    }
                    try {
                        Thread.sleep(sleepTimeMs);
                    } catch (InterruptedException e) {
                        if (HashedWheelTimer.this.workerState.get() == 2) {
                            return Long.MIN_VALUE;
                        }
                    }
                } else if (currentTime == Long.MIN_VALUE) {
                    return -9223372036854775807L;
                } else {
                    return currentTime;
                }
            }
        }
    }

    public HashedWheelTimer() {
        this(Executors.defaultThreadFactory());
    }

    public HashedWheelTimer(long tickDuration2, TimeUnit unit) {
        this(Executors.defaultThreadFactory(), tickDuration2, unit);
    }

    public HashedWheelTimer(long tickDuration2, TimeUnit unit, int ticksPerWheel) {
        this(Executors.defaultThreadFactory(), tickDuration2, unit, ticksPerWheel);
    }

    public HashedWheelTimer(ThreadFactory threadFactory) {
        this(threadFactory, 100, TimeUnit.MILLISECONDS);
    }

    public HashedWheelTimer(ThreadFactory threadFactory, long tickDuration2, TimeUnit unit) {
        this(threadFactory, tickDuration2, unit, 512);
    }

    public HashedWheelTimer(ThreadFactory threadFactory, long tickDuration2, TimeUnit unit, int ticksPerWheel) {
        this(threadFactory, null, tickDuration2, unit, ticksPerWheel);
    }

    public HashedWheelTimer(ThreadFactory threadFactory, ThreadNameDeterminer determiner, long tickDuration2, TimeUnit unit, int ticksPerWheel) {
        this.worker = new Worker();
        this.workerState = new AtomicInteger();
        this.lock = new ReentrantReadWriteLock();
        this.startTimeInitialized = new CountDownLatch(1);
        if (threadFactory == null) {
            throw new NullPointerException("threadFactory");
        } else if (unit == null) {
            throw new NullPointerException("unit");
        } else if (tickDuration2 <= 0) {
            throw new IllegalArgumentException("tickDuration must be greater than 0: " + tickDuration2);
        } else if (ticksPerWheel <= 0) {
            throw new IllegalArgumentException("ticksPerWheel must be greater than 0: " + ticksPerWheel);
        } else {
            this.wheel = createWheel(ticksPerWheel);
            this.iterators = createIterators(this.wheel);
            this.mask = this.wheel.length - 1;
            this.tickDuration = unit.toNanos(tickDuration2);
            if (this.tickDuration >= Long.MAX_VALUE / ((long) this.wheel.length)) {
                throw new IllegalArgumentException(String.format("tickDuration: %d (expected: 0 < tickDuration in nanos < %d", new Object[]{Long.valueOf(tickDuration2), Long.valueOf(Long.MAX_VALUE / ((long) this.wheel.length))}));
            }
            this.workerThread = threadFactory.newThread(new ThreadRenamingRunnable(this.worker, "Hashed wheel timer #" + id.incrementAndGet(), determiner));
            misuseDetector.increase();
        }
    }

    private static Set<HashedWheelTimeout>[] createWheel(int ticksPerWheel) {
        if (ticksPerWheel <= 0) {
            throw new IllegalArgumentException("ticksPerWheel must be greater than 0: " + ticksPerWheel);
        } else if (ticksPerWheel > 1073741824) {
            throw new IllegalArgumentException("ticksPerWheel may not be greater than 2^30: " + ticksPerWheel);
        } else {
            Set<HashedWheelTimeout>[] wheel2 = new Set[normalizeTicksPerWheel(ticksPerWheel)];
            for (int i = 0; i < wheel2.length; i++) {
                wheel2[i] = new MapBackedSet(new ConcurrentIdentityHashMap(16, 0.95f, 4));
            }
            return wheel2;
        }
    }

    private static ReusableIterator<HashedWheelTimeout>[] createIterators(Set<HashedWheelTimeout>[] wheel2) {
        ReusableIterator<HashedWheelTimeout>[] iterators2 = new ReusableIterator[wheel2.length];
        for (int i = 0; i < wheel2.length; i++) {
            iterators2[i] = (ReusableIterator) wheel2[i].iterator();
        }
        return iterators2;
    }

    private static int normalizeTicksPerWheel(int ticksPerWheel) {
        int normalizedTicksPerWheel = 1;
        while (normalizedTicksPerWheel < ticksPerWheel) {
            normalizedTicksPerWheel <<= 1;
        }
        return normalizedTicksPerWheel;
    }

    public void start() {
        switch (this.workerState.get()) {
            case 0:
                if (this.workerState.compareAndSet(0, 1)) {
                    this.workerThread.start();
                    break;
                }
                break;
            case 1:
                break;
            case 2:
                throw new IllegalStateException("cannot be started once stopped");
            default:
                throw new Error("Invalid WorkerState");
        }
        while (this.startTime == 0) {
            try {
                this.startTimeInitialized.await();
            } catch (InterruptedException e) {
            }
        }
    }

    public Set<Timeout> stop() {
        Set<HashedWheelTimeout>[] arr$;
        if (Thread.currentThread() == this.workerThread) {
            throw new IllegalStateException(HashedWheelTimer.class.getSimpleName() + ".stop() cannot be called from " + TimerTask.class.getSimpleName());
        } else if (!this.workerState.compareAndSet(1, 2)) {
            this.workerState.set(2);
            return Collections.emptySet();
        } else {
            boolean interrupted = false;
            while (this.workerThread.isAlive()) {
                this.workerThread.interrupt();
                try {
                    this.workerThread.join(100);
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
            misuseDetector.decrease();
            Set<Timeout> unprocessedTimeouts = new HashSet<>();
            for (Set<HashedWheelTimeout> bucket : this.wheel) {
                unprocessedTimeouts.addAll(bucket);
                bucket.clear();
            }
            return Collections.unmodifiableSet(unprocessedTimeouts);
        }
    }

    public Timeout newTimeout(TimerTask task, long delay, TimeUnit unit) {
        start();
        if (task == null) {
            throw new NullPointerException("task");
        } else if (unit == null) {
            throw new NullPointerException("unit");
        } else {
            long deadline = (System.nanoTime() + unit.toNanos(delay)) - this.startTime;
            this.lock.readLock().lock();
            try {
                HashedWheelTimeout timeout = new HashedWheelTimeout(task, deadline);
                if (this.workerState.get() == 2) {
                    throw new IllegalStateException("Cannot enqueue after shutdown");
                }
                this.wheel[timeout.stopIndex].add(timeout);
                return timeout;
            } finally {
                this.lock.readLock().unlock();
            }
        }
    }
}