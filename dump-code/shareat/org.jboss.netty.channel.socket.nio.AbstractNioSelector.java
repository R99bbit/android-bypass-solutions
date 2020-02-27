package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.ConcurrentModificationException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.ThreadNameDeterminer;
import org.jboss.netty.util.ThreadRenamingRunnable;
import org.jboss.netty.util.internal.DeadLockProofWorker;

abstract class AbstractNioSelector implements NioSelector {
    static final /* synthetic */ boolean $assertionsDisabled = (!AbstractNioSelector.class.desiredAssertionStatus());
    private static final int CLEANUP_INTERVAL = 256;
    protected static final InternalLogger logger = InternalLoggerFactory.getInstance(AbstractNioSelector.class);
    private static final AtomicInteger nextId = new AtomicInteger();
    private volatile int cancelledKeys;
    private final Executor executor;
    private final int id;
    protected volatile Selector selector;
    private volatile boolean shutdown;
    private final CountDownLatch shutdownLatch;
    final CountDownLatch startupLatch;
    private final Queue<Runnable> taskQueue;
    protected volatile Thread thread;
    protected final AtomicBoolean wakenUp;

    /* access modifiers changed from: protected */
    public abstract void close(SelectionKey selectionKey);

    /* access modifiers changed from: protected */
    public abstract Runnable createRegisterTask(Channel channel, ChannelFuture channelFuture);

    /* access modifiers changed from: protected */
    public abstract ThreadRenamingRunnable newThreadRenamingRunnable(int i, ThreadNameDeterminer threadNameDeterminer);

    /* access modifiers changed from: protected */
    public abstract void process(Selector selector2) throws IOException;

    AbstractNioSelector(Executor executor2) {
        this(executor2, null);
    }

    AbstractNioSelector(Executor executor2, ThreadNameDeterminer determiner) {
        this.id = nextId.incrementAndGet();
        this.startupLatch = new CountDownLatch(1);
        this.wakenUp = new AtomicBoolean();
        this.taskQueue = new ConcurrentLinkedQueue();
        this.shutdownLatch = new CountDownLatch(1);
        this.executor = executor2;
        openSelector(determiner);
    }

    public void register(Channel channel, ChannelFuture future) {
        registerTask(createRegisterTask(channel, future));
    }

    /* access modifiers changed from: protected */
    public final void registerTask(Runnable task) {
        this.taskQueue.add(task);
        Selector selector2 = this.selector;
        if (selector2 != null) {
            if (this.wakenUp.compareAndSet(false, true)) {
                selector2.wakeup();
            }
        } else if (this.taskQueue.remove(task)) {
            throw new RejectedExecutionException("Worker has already been shutdown");
        }
    }

    /* access modifiers changed from: protected */
    public final boolean isIoThread() {
        return Thread.currentThread() == this.thread;
    }

    public void rebuildSelector() {
        if (!isIoThread()) {
            this.taskQueue.add(new Runnable() {
                public void run() {
                    AbstractNioSelector.this.rebuildSelector();
                }
            });
            return;
        }
        Selector oldSelector = this.selector;
        if (oldSelector != null) {
            try {
                Selector newSelector = SelectorUtil.open();
                int nChannels = 0;
                loop0:
                while (true) {
                    try {
                        for (SelectionKey key : oldSelector.keys()) {
                            try {
                                if (key.channel().keyFor(newSelector) == null) {
                                    int interestOps = key.interestOps();
                                    key.cancel();
                                    key.channel().register(newSelector, interestOps, key.attachment());
                                    nChannels++;
                                }
                            } catch (Exception e) {
                                logger.warn("Failed to re-register a Channel to the new Selector,", e);
                                close(key);
                            }
                        }
                        break loop0;
                    } catch (ConcurrentModificationException e2) {
                    }
                }
                this.selector = newSelector;
                try {
                    oldSelector.close();
                } catch (Throwable t) {
                    if (logger.isWarnEnabled()) {
                        logger.warn("Failed to close the old Selector.", t);
                    }
                }
                logger.info("Migrated " + nChannels + " channel(s) to the new Selector,");
            } catch (Exception e3) {
                logger.warn("Failed to create a new Selector.", e3);
            }
        }
    }

    public void run() {
        this.thread = Thread.currentThread();
        this.startupLatch.countDown();
        int selectReturnsImmediately = 0;
        Selector selector2 = this.selector;
        if (selector2 != null) {
            long minSelectTimeout = (SelectorUtil.SELECT_TIMEOUT_NANOS * 80) / 100;
            boolean wakenupFromLoop = false;
            while (true) {
                this.wakenUp.set(false);
                try {
                    long beforeSelect = System.nanoTime();
                    int selected = select(selector2);
                    if (!SelectorUtil.EPOLL_BUG_WORKAROUND || selected != 0 || wakenupFromLoop || this.wakenUp.get()) {
                        selectReturnsImmediately = 0;
                    } else {
                        if (System.nanoTime() - beforeSelect < minSelectTimeout) {
                            boolean notConnected = false;
                            for (SelectionKey key : selector2.keys()) {
                                SelectableChannel ch = key.channel();
                                try {
                                    if (((ch instanceof DatagramChannel) && !ch.isOpen()) || ((ch instanceof SocketChannel) && !((SocketChannel) ch).isConnected())) {
                                        notConnected = true;
                                        key.cancel();
                                    }
                                } catch (CancelledKeyException e) {
                                }
                            }
                            if (notConnected) {
                                selectReturnsImmediately = 0;
                            } else {
                                selectReturnsImmediately++;
                            }
                        } else {
                            selectReturnsImmediately = 0;
                        }
                        if (selectReturnsImmediately == 1024) {
                            rebuildSelector();
                            selector2 = this.selector;
                            selectReturnsImmediately = 0;
                            wakenupFromLoop = false;
                        }
                    }
                    if (this.wakenUp.get()) {
                        wakenupFromLoop = true;
                        selector2.wakeup();
                    } else {
                        wakenupFromLoop = false;
                    }
                    this.cancelledKeys = 0;
                    processTaskQueue();
                    selector2 = this.selector;
                    if (this.shutdown) {
                        this.selector = null;
                        processTaskQueue();
                        for (SelectionKey k : selector2.keys()) {
                            close(k);
                        }
                        selector2.close();
                        this.shutdownLatch.countDown();
                        return;
                    }
                    process(selector2);
                } catch (IOException e2) {
                    logger.warn("Failed to close a selector.", e2);
                } catch (Throwable t) {
                    logger.warn("Unexpected exception in the selector loop.", t);
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e3) {
                    }
                }
            }
        }
    }

    private void openSelector(ThreadNameDeterminer determiner) {
        try {
            this.selector = SelectorUtil.open();
            try {
                DeadLockProofWorker.start(this.executor, newThreadRenamingRunnable(this.id, determiner));
                if (1 == 0) {
                    try {
                        this.selector.close();
                    } catch (Throwable t) {
                        logger.warn("Failed to close a selector.", t);
                    }
                    this.selector = null;
                }
                if ($assertionsDisabled) {
                    return;
                }
                if (this.selector == null || !this.selector.isOpen()) {
                    throw new AssertionError();
                }
                return;
            } catch (Throwable t2) {
                logger.warn("Failed to close a selector.", t2);
            }
            this.selector = null;
            throw th;
        } catch (Throwable t3) {
            throw new ChannelException("Failed to create a selector.", t3);
        }
    }

    private void processTaskQueue() {
        while (true) {
            Runnable task = this.taskQueue.poll();
            if (task != null) {
                task.run();
                try {
                    cleanUpCancelledKeys();
                } catch (IOException e) {
                }
            } else {
                return;
            }
        }
    }

    /* access modifiers changed from: protected */
    public final void increaseCancelledKeys() {
        this.cancelledKeys++;
    }

    /* access modifiers changed from: protected */
    public final boolean cleanUpCancelledKeys() throws IOException {
        if (this.cancelledKeys < 256) {
            return false;
        }
        this.cancelledKeys = 0;
        this.selector.selectNow();
        return true;
    }

    public void shutdown() {
        if (isIoThread()) {
            throw new IllegalStateException("Must not be called from a I/O-Thread to prevent deadlocks!");
        }
        Selector selector2 = this.selector;
        this.shutdown = true;
        if (selector2 != null) {
            selector2.wakeup();
        }
        try {
            this.shutdownLatch.await();
        } catch (InterruptedException e) {
            logger.error("Interrupted while wait for resources to be released #" + this.id);
            Thread.currentThread().interrupt();
        }
    }

    /* access modifiers changed from: protected */
    public int select(Selector selector2) throws IOException {
        return SelectorUtil.select(selector2);
    }
}