package org.jboss.netty.channel.socket.nio;

import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.jboss.netty.channel.socket.nio.Boss;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.ExternalResourceReleasable;
import org.jboss.netty.util.internal.ExecutorUtil;

public abstract class AbstractNioBossPool<E extends Boss> implements BossPool<E>, ExternalResourceReleasable {
    private static final int INITIALIZATION_TIMEOUT = 10;
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(AbstractNioBossPool.class);
    private final Executor bossExecutor;
    private final AtomicInteger bossIndex;
    private final Boss[] bosses;
    private volatile boolean initialized;

    /* access modifiers changed from: protected */
    public abstract E newBoss(Executor executor);

    AbstractNioBossPool(Executor bossExecutor2, int bossCount) {
        this(bossExecutor2, bossCount, true);
    }

    AbstractNioBossPool(Executor bossExecutor2, int bossCount, boolean autoInit) {
        this.bossIndex = new AtomicInteger();
        if (bossExecutor2 == null) {
            throw new NullPointerException("bossExecutor");
        } else if (bossCount <= 0) {
            throw new IllegalArgumentException("bossCount (" + bossCount + ") " + "must be a positive integer.");
        } else {
            this.bosses = new Boss[bossCount];
            this.bossExecutor = bossExecutor2;
            if (autoInit) {
                init();
            }
        }
    }

    /* access modifiers changed from: protected */
    public void init() {
        if (this.initialized) {
            throw new IllegalStateException("initialized already");
        }
        this.initialized = true;
        for (int i = 0; i < this.bosses.length; i++) {
            this.bosses[i] = newBoss(this.bossExecutor);
        }
        waitForBossThreads();
    }

    private void waitForBossThreads() {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        boolean warn = false;
        Boss[] arr$ = this.bosses;
        int len$ = arr$.length;
        int i$ = 0;
        while (true) {
            if (i$ >= len$) {
                break;
            }
            Boss boss = arr$[i$];
            if (boss instanceof AbstractNioSelector) {
                AbstractNioSelector selector = (AbstractNioSelector) boss;
                long waitTime = deadline - System.nanoTime();
                if (waitTime <= 0) {
                    try {
                        if (selector.thread == null) {
                            warn = true;
                            break;
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                } else if (!selector.startupLatch.await(waitTime, TimeUnit.NANOSECONDS)) {
                    warn = true;
                    break;
                }
            }
            i$++;
        }
        if (warn) {
            logger.warn("Failed to get all boss threads ready within 10 second(s). Make sure to specify the executor which has more threads than the requested bossCount. If unsure, use Executors.newCachedThreadPool().");
        }
    }

    public E nextBoss() {
        return this.bosses[Math.abs(this.bossIndex.getAndIncrement() % this.bosses.length)];
    }

    public void rebuildSelectors() {
        for (Boss boss : this.bosses) {
            boss.rebuildSelector();
        }
    }

    public void releaseExternalResources() {
        shutdown();
        ExecutorUtil.shutdownNow(this.bossExecutor);
    }

    public void shutdown() {
        for (Boss boss : this.bosses) {
            boss.shutdown();
        }
    }
}