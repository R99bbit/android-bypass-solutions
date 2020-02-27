package org.jboss.netty.channel;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.internal.DeadLockProofWorker;

public class DefaultChannelFuture implements ChannelFuture {
    private static final Throwable CANCELLED = new Throwable();
    private static boolean disabledDeadLockCheckerOnce;
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(DefaultChannelFuture.class);
    private static volatile boolean useDeadLockChecker = true;
    private final boolean cancellable;
    private Throwable cause;
    private final Channel channel;
    private boolean done;
    private ChannelFutureListener firstListener;
    private List<ChannelFutureListener> otherListeners;
    private List<ChannelFutureProgressListener> progressListeners;
    private int waiters;

    public static boolean isUseDeadLockChecker() {
        return useDeadLockChecker;
    }

    public static void setUseDeadLockChecker(boolean useDeadLockChecker2) {
        if (!useDeadLockChecker2 && !disabledDeadLockCheckerOnce) {
            disabledDeadLockCheckerOnce = true;
            if (logger.isDebugEnabled()) {
                logger.debug("The dead lock checker in " + DefaultChannelFuture.class.getSimpleName() + " has been disabled as requested at your own risk.");
            }
        }
        useDeadLockChecker = useDeadLockChecker2;
    }

    public DefaultChannelFuture(Channel channel2, boolean cancellable2) {
        this.channel = channel2;
        this.cancellable = cancellable2;
    }

    public Channel getChannel() {
        return this.channel;
    }

    public synchronized boolean isDone() {
        return this.done;
    }

    public synchronized boolean isSuccess() {
        return this.done && this.cause == null;
    }

    public synchronized Throwable getCause() {
        Throwable th;
        if (this.cause != CANCELLED) {
            th = this.cause;
        } else {
            th = null;
        }
        return th;
    }

    public synchronized boolean isCancelled() {
        return this.cause == CANCELLED;
    }

    public void addListener(ChannelFutureListener listener) {
        if (listener == null) {
            throw new NullPointerException("listener");
        }
        boolean notifyNow = false;
        synchronized (this) {
            if (this.done) {
                notifyNow = true;
            } else {
                if (this.firstListener == null) {
                    this.firstListener = listener;
                } else {
                    if (this.otherListeners == null) {
                        this.otherListeners = new ArrayList(1);
                    }
                    this.otherListeners.add(listener);
                }
                if (listener instanceof ChannelFutureProgressListener) {
                    if (this.progressListeners == null) {
                        this.progressListeners = new ArrayList(1);
                    }
                    this.progressListeners.add((ChannelFutureProgressListener) listener);
                }
            }
        }
        if (notifyNow) {
            notifyListener(listener);
        }
    }

    public void removeListener(ChannelFutureListener listener) {
        if (listener == null) {
            throw new NullPointerException("listener");
        }
        synchronized (this) {
            if (!this.done) {
                if (listener == this.firstListener) {
                    if (this.otherListeners == null || this.otherListeners.isEmpty()) {
                        this.firstListener = null;
                    } else {
                        this.firstListener = this.otherListeners.remove(0);
                    }
                } else if (this.otherListeners != null) {
                    this.otherListeners.remove(listener);
                }
                if (listener instanceof ChannelFutureProgressListener) {
                    this.progressListeners.remove(listener);
                }
            }
        }
    }

    @Deprecated
    public ChannelFuture rethrowIfFailed() throws Exception {
        if (isDone()) {
            Throwable cause2 = getCause();
            if (cause2 != null) {
                if (cause2 instanceof Exception) {
                    throw ((Exception) cause2);
                } else if (cause2 instanceof Error) {
                    throw ((Error) cause2);
                } else {
                    throw new RuntimeException(cause2);
                }
            }
        }
        return this;
    }

    public ChannelFuture sync() throws InterruptedException {
        await();
        rethrowIfFailed0();
        return this;
    }

    public ChannelFuture syncUninterruptibly() {
        awaitUninterruptibly();
        rethrowIfFailed0();
        return this;
    }

    private void rethrowIfFailed0() {
        Throwable cause2 = getCause();
        if (cause2 != null) {
            if (cause2 instanceof RuntimeException) {
                throw ((RuntimeException) cause2);
            } else if (cause2 instanceof Error) {
                throw ((Error) cause2);
            } else {
                throw new ChannelException(cause2);
            }
        }
    }

    /* JADX INFO: finally extract failed */
    public ChannelFuture await() throws InterruptedException {
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }
        synchronized (this) {
            while (!this.done) {
                checkDeadLock();
                this.waiters++;
                try {
                    wait();
                    this.waiters--;
                } catch (Throwable th) {
                    this.waiters--;
                    throw th;
                }
            }
        }
        return this;
    }

    public boolean await(long timeout, TimeUnit unit) throws InterruptedException {
        return await0(unit.toNanos(timeout), true);
    }

    public boolean await(long timeoutMillis) throws InterruptedException {
        return await0(TimeUnit.MILLISECONDS.toNanos(timeoutMillis), true);
    }

    public ChannelFuture awaitUninterruptibly() {
        boolean interrupted = false;
        synchronized (this) {
            while (!this.done) {
                checkDeadLock();
                this.waiters++;
                try {
                    wait();
                    this.waiters--;
                } catch (InterruptedException e) {
                    interrupted = true;
                    this.waiters--;
                } catch (Throwable th) {
                    this.waiters--;
                    throw th;
                }
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
        return this;
    }

    public boolean awaitUninterruptibly(long timeout, TimeUnit unit) {
        try {
            return await0(unit.toNanos(timeout), false);
        } catch (InterruptedException e) {
            throw new InternalError();
        }
    }

    public boolean awaitUninterruptibly(long timeoutMillis) {
        try {
            return await0(TimeUnit.MILLISECONDS.toNanos(timeoutMillis), false);
        } catch (InterruptedException e) {
            throw new InternalError();
        }
    }

    private boolean await0(long timeoutNanos, boolean interruptable) throws InterruptedException {
        boolean z;
        if (!interruptable || !Thread.interrupted()) {
            long startTime = timeoutNanos <= 0 ? 0 : System.nanoTime();
            long waitTime = timeoutNanos;
            boolean interrupted = false;
            try {
                synchronized (this) {
                    if (this.done || waitTime <= 0) {
                        z = this.done;
                    } else {
                        checkDeadLock();
                        this.waiters++;
                        do {
                            try {
                                wait(waitTime / 1000000, (int) (waitTime % 1000000));
                            } catch (InterruptedException e) {
                                if (interruptable) {
                                    throw e;
                                }
                                interrupted = true;
                            } catch (Throwable th) {
                                this.waiters--;
                                throw th;
                            }
                            if (this.done) {
                                z = true;
                                this.waiters--;
                                if (interrupted) {
                                    Thread.currentThread().interrupt();
                                }
                            } else {
                                waitTime = timeoutNanos - (System.nanoTime() - startTime);
                            }
                        } while (waitTime > 0);
                        z = this.done;
                        this.waiters--;
                        if (interrupted) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
                return z;
            } finally {
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
        } else {
            throw new InterruptedException();
        }
    }

    private static void checkDeadLock() {
        if (isUseDeadLockChecker() && DeadLockProofWorker.PARENT.get() != null) {
            throw new IllegalStateException("await*() in I/O thread causes a dead lock or sudden performance drop. Use addListener() instead or call await*() from a different thread.");
        }
    }

    public boolean setSuccess() {
        boolean z = true;
        synchronized (this) {
            if (this.done) {
                z = false;
            } else {
                this.done = true;
                if (this.waiters > 0) {
                    notifyAll();
                }
                notifyListeners();
            }
        }
        return z;
    }

    public boolean setFailure(Throwable cause2) {
        boolean z = true;
        synchronized (this) {
            if (this.done) {
                z = false;
            } else {
                this.cause = cause2;
                this.done = true;
                if (this.waiters > 0) {
                    notifyAll();
                }
                notifyListeners();
            }
        }
        return z;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0020, code lost:
        notifyListeners();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:19:?, code lost:
        return true;
     */
    public boolean cancel() {
        if (!this.cancellable) {
            return false;
        }
        synchronized (this) {
            if (this.done) {
                return false;
            }
            this.cause = CANCELLED;
            this.done = true;
            if (this.waiters > 0) {
                notifyAll();
            }
        }
    }

    private void notifyListeners() {
        if (this.firstListener != null) {
            notifyListener(this.firstListener);
            this.firstListener = null;
            if (this.otherListeners != null) {
                for (ChannelFutureListener l : this.otherListeners) {
                    notifyListener(l);
                }
                this.otherListeners = null;
            }
        }
    }

    private void notifyListener(ChannelFutureListener l) {
        try {
            l.operationComplete(this);
        } catch (Throwable t) {
            if (logger.isWarnEnabled()) {
                logger.warn("An exception was thrown by " + ChannelFutureListener.class.getSimpleName() + '.', t);
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:19:0x0025, code lost:
        r8 = r11;
        r10 = r8.length;
        r9 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:0x0028, code lost:
        if (r9 >= r10) goto L_0x0038;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:21:0x002a, code lost:
        notifyProgressListener(r8[r9], r14, r16, r18);
        r9 = r9 + 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:?, code lost:
        return true;
     */
    public boolean setProgress(long amount, long current, long total) {
        synchronized (this) {
            if (this.done) {
                return false;
            }
            Collection<ChannelFutureProgressListener> progressListeners2 = this.progressListeners;
            if (progressListeners2 == null || progressListeners2.isEmpty()) {
                return true;
            }
            ChannelFutureProgressListener[] plisteners = (ChannelFutureProgressListener[]) progressListeners2.toArray(new ChannelFutureProgressListener[progressListeners2.size()]);
        }
    }

    private void notifyProgressListener(ChannelFutureProgressListener l, long amount, long current, long total) {
        try {
            l.operationProgressed(this, amount, current, total);
        } catch (Throwable t) {
            if (logger.isWarnEnabled()) {
                logger.warn("An exception was thrown by " + ChannelFutureProgressListener.class.getSimpleName() + '.', t);
            }
        }
    }
}