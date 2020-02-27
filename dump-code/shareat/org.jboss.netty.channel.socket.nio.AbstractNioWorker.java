package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.WritableByteChannel;
import java.util.Iterator;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.Executor;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.socket.Worker;
import org.jboss.netty.util.ThreadNameDeterminer;
import org.jboss.netty.util.ThreadRenamingRunnable;

abstract class AbstractNioWorker extends AbstractNioSelector implements Worker {
    protected final SocketSendBufferPool sendBufferPool = new SocketSendBufferPool();

    /* access modifiers changed from: protected */
    public abstract boolean read(SelectionKey selectionKey);

    /* access modifiers changed from: protected */
    public abstract boolean scheduleWriteIfNecessary(AbstractNioChannel<?> abstractNioChannel);

    AbstractNioWorker(Executor executor) {
        super(executor);
    }

    AbstractNioWorker(Executor executor, ThreadNameDeterminer determiner) {
        super(executor, determiner);
    }

    public void executeInIoThread(Runnable task) {
        executeInIoThread(task, false);
    }

    public void executeInIoThread(Runnable task, boolean alwaysAsync) {
        if (alwaysAsync || !isIoThread()) {
            registerTask(task);
        } else {
            task.run();
        }
    }

    /* access modifiers changed from: protected */
    public void close(SelectionKey k) {
        AbstractNioChannel<?> ch = (AbstractNioChannel) k.attachment();
        close(ch, Channels.succeededFuture(ch));
    }

    /* access modifiers changed from: protected */
    public ThreadRenamingRunnable newThreadRenamingRunnable(int id, ThreadNameDeterminer determiner) {
        return new ThreadRenamingRunnable(this, "New I/O worker #" + id, determiner);
    }

    public void run() {
        super.run();
        this.sendBufferPool.releaseExternalResources();
    }

    /* access modifiers changed from: protected */
    public void process(Selector selector) throws IOException {
        Set<SelectionKey> selectedKeys = selector.selectedKeys();
        if (!selectedKeys.isEmpty()) {
            Iterator<SelectionKey> it = selectedKeys.iterator();
            while (it.hasNext()) {
                SelectionKey k = it.next();
                it.remove();
                try {
                    int readyOps = k.readyOps();
                    if (((readyOps & 1) == 0 && readyOps != 0) || read(k)) {
                        if ((readyOps & 4) != 0) {
                            writeFromSelectorLoop(k);
                        }
                        if (cleanUpCancelledKeys()) {
                            return;
                        }
                    }
                } catch (CancelledKeyException e) {
                    close(k);
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void writeFromUserCode(AbstractNioChannel<?> channel) {
        if (!channel.isConnected()) {
            cleanUpWriteBuffer(channel);
        } else if (!scheduleWriteIfNecessary(channel) && !channel.writeSuspended && !channel.inWriteNowLoop) {
            write0(channel);
        }
    }

    /* access modifiers changed from: 0000 */
    public void writeFromTaskLoop(AbstractNioChannel<?> ch) {
        if (!ch.writeSuspended) {
            write0(ch);
        }
    }

    /* access modifiers changed from: 0000 */
    public void writeFromSelectorLoop(SelectionKey k) {
        AbstractNioChannel<?> ch = (AbstractNioChannel) k.attachment();
        ch.writeSuspended = false;
        write0(ch);
    }

    /* JADX INFO: used method not loaded: org.jboss.netty.channel.Channels.fireExceptionCaught(org.jboss.netty.channel.Channel, java.lang.Throwable):null, types can be incorrect */
    /* JADX INFO: used method not loaded: org.jboss.netty.channel.Channels.fireWriteComplete(org.jboss.netty.channel.Channel, long):null, types can be incorrect */
    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:22:0x0064, code lost:
        if (r15 == null) goto L_0x0133;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:23:0x0066, code lost:
        r19 = r15.iterator();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x006e, code lost:
        if (r19.hasNext() == false) goto L_0x0133;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x0070, code lost:
        org.jboss.netty.channel.Channels.fireExceptionCaught((org.jboss.netty.channel.Channel) r31, (java.lang.Throwable) r19.next());
     */
    /* JADX WARNING: Code restructure failed: missing block: B:73:0x0133, code lost:
        if (r21 != false) goto L_0x0140;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:74:0x0135, code lost:
        close(r31, org.jboss.netty.channel.Channels.succeededFuture(r31));
     */
    /* JADX WARNING: Code restructure failed: missing block: B:75:0x0140, code lost:
        if (r20 == false) goto L_0x014a;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:76:0x0142, code lost:
        org.jboss.netty.channel.Channels.fireWriteComplete((org.jboss.netty.channel.Channel) r31, r28);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:77:0x014a, code lost:
        org.jboss.netty.channel.Channels.fireWriteCompleteLater(r31, r28);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:90:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:91:?, code lost:
        return;
     */
    /* JADX WARNING: Removed duplicated region for block: B:31:0x0094 A[Catch:{ AsynchronousCloseException -> 0x00ea, Throwable -> 0x00ed, all -> 0x012f, all -> 0x0152 }] */
    /* JADX WARNING: Removed duplicated region for block: B:36:0x00a8 A[Catch:{ AsynchronousCloseException -> 0x00ea, Throwable -> 0x00ed, all -> 0x012f, all -> 0x0152 }] */
    /* JADX WARNING: Removed duplicated region for block: B:81:0x00d1 A[SYNTHETIC] */
    /* JADX WARNING: Removed duplicated region for block: B:87:0x00a2 A[EDGE_INSN: B:87:0x00a2->B:34:0x00a2 ?: BREAK  
    EDGE_INSN: B:87:0x00a2->B:34:0x00a2 ?: BREAK  , SYNTHETIC] */
    public void write0(AbstractNioChannel<?> channel) {
        List list;
        SendBuffer buf;
        ChannelFuture future;
        ChannelFuture future2;
        SendBuffer buf2;
        List list2;
        int i;
        boolean open = true;
        boolean addOpWrite = false;
        boolean removeOpWrite = false;
        boolean iothread = isIoThread(channel);
        long writtenBytes = 0;
        SocketSendBufferPool sendBufferPool2 = this.sendBufferPool;
        WritableByteChannel ch = (WritableByteChannel) channel.channel;
        Queue<MessageEvent> writeBuffer = channel.writeBufferQueue;
        int writeSpinCount = channel.getConfig().getWriteSpinCount();
        synchronized (channel.writeLock) {
            try {
                channel.inWriteNowLoop = true;
                list = null;
                while (true) {
                    MessageEvent evt = channel.currentWriteEvent;
                    buf = null;
                    future = null;
                    if (evt == null) {
                        MessageEvent evt2 = writeBuffer.poll();
                        channel.currentWriteEvent = evt2;
                        if (evt2 == null) {
                            removeOpWrite = true;
                            channel.writeSuspended = false;
                            break;
                        }
                        future2 = evt2.getFuture();
                        buf2 = sendBufferPool2.acquire(evt2.getMessage());
                        channel.currentWriteBuffer = buf2;
                        long localWrittenBytes = 0;
                        i = writeSpinCount;
                        while (true) {
                            if (i > 0) {
                                break;
                            }
                            localWrittenBytes = buf2.transferTo(ch);
                            if (localWrittenBytes == 0) {
                                if (buf2.finished()) {
                                    break;
                                }
                                i--;
                            } else {
                                writtenBytes += localWrittenBytes;
                                break;
                            }
                        }
                        if (!buf2.finished()) {
                            buf2.release();
                            channel.currentWriteEvent = null;
                            channel.currentWriteBuffer = null;
                            future2.setSuccess();
                            list2 = list;
                            list = list2;
                        } else {
                            addOpWrite = true;
                            channel.writeSuspended = true;
                            if (writtenBytes > 0) {
                                future2.setProgress(localWrittenBytes, buf2.writtenBytes(), buf2.totalBytes());
                            }
                        }
                    } else {
                        future2 = evt.getFuture();
                        buf2 = channel.currentWriteBuffer;
                        long localWrittenBytes2 = 0;
                        i = writeSpinCount;
                        while (true) {
                            if (i > 0) {
                            }
                            i--;
                        }
                        if (!buf2.finished()) {
                        }
                    }
                }
                channel.inWriteNowLoop = false;
                if (open) {
                    if (addOpWrite) {
                        setOpWrite(channel);
                    } else if (removeOpWrite) {
                        clearOpWrite(channel);
                    }
                }
            } catch (AsynchronousCloseException e) {
                list2 = list;
            } catch (Throwable th) {
                th = th;
                throw th;
            }
        }
    }

    static boolean isIoThread(AbstractNioChannel<?> channel) {
        return Thread.currentThread() == channel.worker.thread;
    }

    /* access modifiers changed from: protected */
    public void setOpWrite(AbstractNioChannel<?> channel) {
        SelectionKey key = channel.channel.keyFor(this.selector);
        if (key != null) {
            if (!key.isValid()) {
                close(key);
                return;
            }
            int interestOps = channel.getRawInterestOps();
            if ((interestOps & 4) == 0) {
                int interestOps2 = interestOps | 4;
                key.interestOps(interestOps2);
                channel.setRawInterestOpsNow(interestOps2);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void clearOpWrite(AbstractNioChannel<?> channel) {
        SelectionKey key = channel.channel.keyFor(this.selector);
        if (key != null) {
            if (!key.isValid()) {
                close(key);
                return;
            }
            int interestOps = channel.getRawInterestOps();
            if ((interestOps & 4) != 0) {
                int interestOps2 = interestOps & -5;
                key.interestOps(interestOps2);
                channel.setRawInterestOpsNow(interestOps2);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void close(AbstractNioChannel<?> channel, ChannelFuture future) {
        boolean connected = channel.isConnected();
        boolean bound = channel.isBound();
        boolean iothread = isIoThread(channel);
        try {
            channel.channel.close();
            increaseCancelledKeys();
            if (channel.setClosed()) {
                future.setSuccess();
                if (connected) {
                    if (iothread) {
                        Channels.fireChannelDisconnected((Channel) channel);
                    } else {
                        Channels.fireChannelDisconnectedLater(channel);
                    }
                }
                if (bound) {
                    if (iothread) {
                        Channels.fireChannelUnbound((Channel) channel);
                    } else {
                        Channels.fireChannelUnboundLater(channel);
                    }
                }
                cleanUpWriteBuffer(channel);
                if (iothread) {
                    Channels.fireChannelClosed((Channel) channel);
                } else {
                    Channels.fireChannelClosedLater(channel);
                }
            } else {
                future.setSuccess();
            }
        } catch (Throwable t) {
            future.setFailure(t);
            if (iothread) {
                Channels.fireExceptionCaught((Channel) channel, t);
            } else {
                Channels.fireExceptionCaughtLater((Channel) channel, t);
            }
        }
    }

    /* JADX INFO: used method not loaded: org.jboss.netty.channel.Channels.fireExceptionCaught(org.jboss.netty.channel.Channel, java.lang.Throwable):null, types can be incorrect */
    /* JADX INFO: used method not loaded: org.jboss.netty.channel.Channels.fireExceptionCaughtLater(org.jboss.netty.channel.Channel, java.lang.Throwable):null, types can be incorrect */
    /* JADX WARNING: Code restructure failed: missing block: B:17:0x0039, code lost:
        if (r3 == false) goto L_?;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:19:0x003f, code lost:
        if (isIoThread(r8) == false) goto L_0x006c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:0x0041, code lost:
        org.jboss.netty.channel.Channels.fireExceptionCaught((org.jboss.netty.channel.Channel) r8, r1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:0x006c, code lost:
        org.jboss.netty.channel.Channels.fireExceptionCaughtLater((org.jboss.netty.channel.Channel) r8, r1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:44:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:45:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:46:?, code lost:
        return;
     */
    protected static void cleanUpWriteBuffer(AbstractNioChannel<?> channel) {
        Throwable th;
        Throwable cause;
        Exception cause2 = null;
        boolean fireExceptionCaught = false;
        synchronized (channel.writeLock) {
            MessageEvent evt = channel.currentWriteEvent;
            if (evt != null) {
                if (channel.isOpen()) {
                    cause2 = new NotYetConnectedException();
                } else {
                    cause2 = new ClosedChannelException();
                }
                ChannelFuture future = evt.getFuture();
                if (channel.currentWriteBuffer != null) {
                    channel.currentWriteBuffer.release();
                    channel.currentWriteBuffer = null;
                }
                channel.currentWriteEvent = null;
                future.setFailure(cause2);
                fireExceptionCaught = true;
            }
            Queue<MessageEvent> writeBuffer = channel.writeBufferQueue;
            while (true) {
                try {
                    th = cause2;
                    MessageEvent evt2 = writeBuffer.poll();
                    if (evt2 == null) {
                        break;
                    }
                    if (th == null) {
                        if (channel.isOpen()) {
                            cause = new NotYetConnectedException();
                        } else {
                            cause = new ClosedChannelException();
                        }
                        fireExceptionCaught = true;
                    } else {
                        cause = th;
                    }
                    try {
                        evt2.getFuture().setFailure(cause2);
                    } catch (Throwable th2) {
                        th = th2;
                        throw th;
                    }
                } catch (Throwable th3) {
                    th = th3;
                    Throwable th4 = th;
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void setInterestOps(final AbstractNioChannel<?> channel, final ChannelFuture future, final int interestOps) {
        boolean iothread = isIoThread(channel);
        if (!iothread) {
            channel.getPipeline().execute(new Runnable() {
                public void run() {
                    AbstractNioWorker.this.setInterestOps(channel, future, interestOps);
                }
            });
            return;
        }
        boolean changed = false;
        try {
            Selector selector = this.selector;
            SelectionKey key = channel.channel.keyFor(selector);
            int newInterestOps = (interestOps & -5) | (channel.getRawInterestOps() & 4);
            if (key == null || selector == null) {
                if (channel.getRawInterestOps() != newInterestOps) {
                    changed = true;
                }
                channel.setRawInterestOpsNow(newInterestOps);
                future.setSuccess();
                if (!changed) {
                    return;
                }
                if (iothread) {
                    Channels.fireChannelInterestChanged((Channel) channel);
                } else {
                    Channels.fireChannelInterestChangedLater(channel);
                }
            } else {
                if (channel.getRawInterestOps() != newInterestOps) {
                    key.interestOps(newInterestOps);
                    if (Thread.currentThread() != this.thread && this.wakenUp.compareAndSet(false, true)) {
                        selector.wakeup();
                    }
                    channel.setRawInterestOpsNow(newInterestOps);
                }
                future.setSuccess();
                if (0 != 0) {
                    Channels.fireChannelInterestChanged((Channel) channel);
                }
            }
        } catch (CancelledKeyException e) {
            ClosedChannelException cce = new ClosedChannelException();
            future.setFailure(cce);
            Channels.fireExceptionCaught((Channel) channel, (Throwable) cce);
        } catch (Throwable t) {
            future.setFailure(t);
            Channels.fireExceptionCaught((Channel) channel, t);
        }
    }
}