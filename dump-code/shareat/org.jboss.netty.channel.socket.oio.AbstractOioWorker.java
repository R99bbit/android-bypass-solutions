package org.jboss.netty.channel.socket.oio;

import java.io.IOException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.Worker;
import org.jboss.netty.channel.socket.oio.AbstractOioChannel;

abstract class AbstractOioWorker<C extends AbstractOioChannel> implements Worker {
    protected final C channel;
    private volatile boolean done;
    private final Queue<Runnable> eventQueue = new ConcurrentLinkedQueue();
    protected volatile Thread thread;

    /* access modifiers changed from: 0000 */
    public abstract boolean process() throws IOException;

    protected AbstractOioWorker(C channel2) {
        this.channel = channel2;
        channel2.worker = this;
    }

    public void run() {
        C c = this.channel;
        Thread currentThread = Thread.currentThread();
        c.workerThread = currentThread;
        this.thread = currentThread;
        while (this.channel.isOpen()) {
            synchronized (this.channel.interestOpsLock) {
                while (!this.channel.isReadable()) {
                    try {
                        this.channel.interestOpsLock.wait();
                    } catch (InterruptedException e) {
                        if (!this.channel.isOpen()) {
                            break;
                        }
                    }
                }
            }
            boolean cont = false;
            try {
                cont = process();
            } catch (Throwable th) {
                processEventQueue();
                throw th;
            }
            processEventQueue();
            if (!cont) {
                break;
            }
        }
        synchronized (this.channel.interestOpsLock) {
            this.channel.workerThread = null;
        }
        close(this.channel, Channels.succeededFuture(this.channel), true);
        this.done = true;
        processEventQueue();
    }

    static boolean isIoThread(AbstractOioChannel channel2) {
        return Thread.currentThread() == channel2.workerThread;
    }

    public void executeInIoThread(Runnable task) {
        if (Thread.currentThread() == this.thread || this.done) {
            task.run();
        } else {
            if (this.eventQueue.offer(task)) {
            }
        }
    }

    private void processEventQueue() {
        while (true) {
            Runnable task = this.eventQueue.poll();
            if (task != null) {
                task.run();
            } else {
                return;
            }
        }
    }

    /* JADX WARNING: No exception handlers in catch block: Catch:{  } */
    static void setInterestOps(AbstractOioChannel channel2, ChannelFuture future, int interestOps) {
        boolean iothread = isIoThread(channel2);
        int interestOps2 = (interestOps & -5) | (channel2.getInterestOps() & 4);
        boolean changed = false;
        try {
            if (channel2.getInterestOps() != interestOps2) {
                if ((interestOps2 & 1) != 0) {
                    channel2.setInterestOpsNow(1);
                } else {
                    channel2.setInterestOpsNow(0);
                }
                changed = true;
            }
            future.setSuccess();
            if (changed) {
                synchronized (channel2.interestOpsLock) {
                    channel2.setInterestOpsNow(interestOps2);
                    Thread currentThread = Thread.currentThread();
                    Thread workerThread = channel2.workerThread;
                    if (!(workerThread == null || currentThread == workerThread)) {
                        workerThread.interrupt();
                    }
                }
                if (iothread) {
                    Channels.fireChannelInterestChanged((Channel) channel2);
                } else {
                    Channels.fireChannelInterestChangedLater(channel2);
                }
            }
        } catch (Throwable t) {
            future.setFailure(t);
            if (iothread) {
                Channels.fireExceptionCaught((Channel) channel2, t);
            } else {
                Channels.fireExceptionCaughtLater((Channel) channel2, t);
            }
        }
    }

    static void close(AbstractOioChannel channel2, ChannelFuture future) {
        close(channel2, future, isIoThread(channel2));
    }

    private static void close(AbstractOioChannel channel2, ChannelFuture future, boolean iothread) {
        boolean connected = channel2.isConnected();
        boolean bound = channel2.isBound();
        try {
            channel2.closeSocket();
            if (channel2.setClosed()) {
                future.setSuccess();
                if (connected) {
                    Thread currentThread = Thread.currentThread();
                    synchronized (channel2.interestOpsLock) {
                        Thread workerThread = channel2.workerThread;
                        if (!(workerThread == null || currentThread == workerThread)) {
                            workerThread.interrupt();
                        }
                    }
                    if (iothread) {
                        Channels.fireChannelDisconnected((Channel) channel2);
                    } else {
                        Channels.fireChannelDisconnectedLater(channel2);
                    }
                }
                if (bound) {
                    if (iothread) {
                        Channels.fireChannelUnbound((Channel) channel2);
                    } else {
                        Channels.fireChannelUnboundLater(channel2);
                    }
                }
                if (iothread) {
                    Channels.fireChannelClosed((Channel) channel2);
                } else {
                    Channels.fireChannelClosedLater(channel2);
                }
            } else {
                future.setSuccess();
            }
        } catch (Throwable t) {
            future.setFailure(t);
            if (iothread) {
                Channels.fireExceptionCaught((Channel) channel2, t);
            } else {
                Channels.fireExceptionCaughtLater((Channel) channel2, t);
            }
        }
    }
}