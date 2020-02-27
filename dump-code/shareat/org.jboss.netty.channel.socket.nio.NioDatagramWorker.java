package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.Queue;
import java.util.concurrent.Executor;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.ReceiveBufferSizePredictor;

public class NioDatagramWorker extends AbstractNioWorker {
    private final SocketReceiveBufferAllocator bufferAllocator = new SocketReceiveBufferAllocator();

    private final class ChannelRegistionTask implements Runnable {
        private final NioDatagramChannel channel;
        private final ChannelFuture future;

        ChannelRegistionTask(NioDatagramChannel channel2, ChannelFuture future2) {
            this.channel = channel2;
            this.future = future2;
        }

        public void run() {
            if (this.channel.getLocalAddress() == null) {
                if (this.future != null) {
                    this.future.setFailure(new ClosedChannelException());
                }
                NioDatagramWorker.this.close(this.channel, Channels.succeededFuture(this.channel));
                return;
            }
            try {
                this.channel.getDatagramChannel().register(NioDatagramWorker.this.selector, this.channel.getRawInterestOps(), this.channel);
                if (this.future != null) {
                    this.future.setSuccess();
                }
            } catch (IOException e) {
                if (this.future != null) {
                    this.future.setFailure(e);
                }
                NioDatagramWorker.this.close(this.channel, Channels.succeededFuture(this.channel));
                if (!(e instanceof ClosedChannelException)) {
                    throw new ChannelException("Failed to register a socket to the selector.", e);
                }
            }
        }
    }

    public /* bridge */ /* synthetic */ void executeInIoThread(Runnable x0) {
        super.executeInIoThread(x0);
    }

    public /* bridge */ /* synthetic */ void executeInIoThread(Runnable x0, boolean x1) {
        super.executeInIoThread(x0, x1);
    }

    public /* bridge */ /* synthetic */ void rebuildSelector() {
        super.rebuildSelector();
    }

    public /* bridge */ /* synthetic */ void register(Channel x0, ChannelFuture x1) {
        super.register(x0, x1);
    }

    public /* bridge */ /* synthetic */ void shutdown() {
        super.shutdown();
    }

    NioDatagramWorker(Executor executor) {
        super(executor);
    }

    /* access modifiers changed from: protected */
    public boolean read(SelectionKey key) {
        NioDatagramChannel channel = (NioDatagramChannel) key.attachment();
        ReceiveBufferSizePredictor predictor = channel.getConfig().getReceiveBufferSizePredictor();
        ChannelBufferFactory bufferFactory = channel.getConfig().getBufferFactory();
        DatagramChannel nioChannel = (DatagramChannel) key.channel();
        ByteBuffer byteBuffer = this.bufferAllocator.get(predictor.nextReceiveBufferSize()).order(bufferFactory.getDefaultOrder());
        boolean failure = true;
        SocketAddress remoteAddress = null;
        try {
            remoteAddress = nioChannel.receive(byteBuffer);
            failure = false;
        } catch (ClosedChannelException e) {
        } catch (Throwable t) {
            Channels.fireExceptionCaught((Channel) channel, t);
        }
        if (remoteAddress != null) {
            byteBuffer.flip();
            int readBytes = byteBuffer.remaining();
            if (readBytes > 0) {
                predictor.previousReceiveBufferSize(readBytes);
                ChannelBuffer buffer = bufferFactory.getBuffer(readBytes);
                buffer.setBytes(0, byteBuffer);
                buffer.writerIndex(readBytes);
                predictor.previousReceiveBufferSize(readBytes);
                Channels.fireMessageReceived((Channel) channel, (Object) buffer, remoteAddress);
            }
        }
        if (!failure) {
            return true;
        }
        key.cancel();
        close(channel, Channels.succeededFuture(channel));
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean scheduleWriteIfNecessary(AbstractNioChannel<?> channel) {
        Thread workerThread = this.thread;
        if (workerThread != null && Thread.currentThread() == workerThread) {
            return false;
        }
        if (channel.writeTaskInTaskQueue.compareAndSet(false, true)) {
            registerTask(channel.writeTask);
        }
        return true;
    }

    static void disconnect(NioDatagramChannel channel, ChannelFuture future) {
        boolean connected = channel.isConnected();
        boolean iothread = isIoThread(channel);
        try {
            channel.getDatagramChannel().disconnect();
            future.setSuccess();
            if (!connected) {
                return;
            }
            if (iothread) {
                Channels.fireChannelDisconnected((Channel) channel);
            } else {
                Channels.fireChannelDisconnectedLater(channel);
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

    /* access modifiers changed from: protected */
    public Runnable createRegisterTask(Channel channel, ChannelFuture future) {
        return new ChannelRegistionTask((NioDatagramChannel) channel, future);
    }

    public void writeFromUserCode(AbstractNioChannel<?> channel) {
        if (!channel.isBound()) {
            cleanUpWriteBuffer(channel);
        } else if (!scheduleWriteIfNecessary(channel) && !channel.writeSuspended && !channel.inWriteNowLoop) {
            write0(channel);
        }
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Removed duplicated region for block: B:22:0x0074 A[Catch:{ AsynchronousCloseException -> 0x00ad, Throwable -> 0x00e3 }] */
    /* JADX WARNING: Removed duplicated region for block: B:40:0x00be A[Catch:{ AsynchronousCloseException -> 0x00ad, Throwable -> 0x00e3 }] */
    public void write0(AbstractNioChannel<?> channel) {
        SendBuffer buf;
        long localWrittenBytes;
        SocketAddress raddr;
        boolean addOpWrite = false;
        boolean removeOpWrite = false;
        long writtenBytes = 0;
        SocketSendBufferPool sendBufferPool = this.sendBufferPool;
        DatagramChannel ch = ((NioDatagramChannel) channel).getDatagramChannel();
        Queue<MessageEvent> writeBuffer = channel.writeBufferQueue;
        int writeSpinCount = channel.getConfig().getWriteSpinCount();
        synchronized (channel.writeLock) {
            channel.inWriteNowLoop = true;
            while (true) {
                MessageEvent evt = channel.currentWriteEvent;
                if (evt == null) {
                    evt = writeBuffer.poll();
                    channel.currentWriteEvent = evt;
                    if (evt == null) {
                        removeOpWrite = true;
                        channel.writeSuspended = false;
                        break;
                    }
                    buf = sendBufferPool.acquire(evt.getMessage());
                    channel.currentWriteBuffer = buf;
                    localWrittenBytes = 0;
                    try {
                        raddr = evt.getRemoteAddress();
                        if (raddr == null) {
                            int i = writeSpinCount;
                            while (true) {
                                if (i <= 0) {
                                    break;
                                }
                                localWrittenBytes = buf.transferTo(ch, raddr);
                                if (localWrittenBytes == 0) {
                                    if (buf.finished()) {
                                        break;
                                    }
                                    i--;
                                } else {
                                    writtenBytes += localWrittenBytes;
                                    break;
                                }
                            }
                        } else {
                            int i2 = writeSpinCount;
                            while (true) {
                                if (i2 <= 0) {
                                    break;
                                }
                                localWrittenBytes = buf.transferTo(ch);
                                if (localWrittenBytes == 0) {
                                    if (buf.finished()) {
                                        break;
                                    }
                                    i2--;
                                } else {
                                    writtenBytes += localWrittenBytes;
                                    break;
                                }
                            }
                        }
                        if (localWrittenBytes > 0 && !buf.finished()) {
                            addOpWrite = true;
                            channel.writeSuspended = true;
                            break;
                        }
                        buf.release();
                        ChannelFuture future = evt.getFuture();
                        channel.currentWriteEvent = null;
                        channel.currentWriteBuffer = null;
                        future.setSuccess();
                    } catch (AsynchronousCloseException e) {
                    } catch (Throwable t) {
                        buf.release();
                        ChannelFuture future2 = evt.getFuture();
                        channel.currentWriteEvent = null;
                        channel.currentWriteBuffer = null;
                        future2.setFailure(t);
                        Channels.fireExceptionCaught((Channel) channel, t);
                    }
                } else {
                    buf = channel.currentWriteBuffer;
                    localWrittenBytes = 0;
                    raddr = evt.getRemoteAddress();
                    if (raddr == null) {
                    }
                    if (localWrittenBytes > 0) {
                    }
                    buf.release();
                    ChannelFuture future3 = evt.getFuture();
                    channel.currentWriteEvent = null;
                    channel.currentWriteBuffer = null;
                    future3.setSuccess();
                }
            }
            channel.inWriteNowLoop = false;
            if (addOpWrite) {
                setOpWrite(channel);
            } else if (removeOpWrite) {
                clearOpWrite(channel);
            }
        }
        Channels.fireWriteComplete((Channel) channel, writtenBytes);
    }

    public void run() {
        super.run();
        this.bufferAllocator.releaseExternalResources();
    }
}