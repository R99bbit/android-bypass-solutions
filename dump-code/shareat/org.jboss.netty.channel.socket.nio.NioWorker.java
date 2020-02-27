package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Executor;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.ReceiveBufferSizePredictor;
import org.jboss.netty.util.ThreadNameDeterminer;

public class NioWorker extends AbstractNioWorker {
    private final SocketReceiveBufferAllocator recvBufferPool = new SocketReceiveBufferAllocator();

    private final class RegisterTask implements Runnable {
        private final NioSocketChannel channel;
        private final ChannelFuture future;
        private final boolean server;

        RegisterTask(NioSocketChannel channel2, ChannelFuture future2, boolean server2) {
            this.channel = channel2;
            this.future = future2;
            this.server = server2;
        }

        public void run() {
            SocketAddress localAddress = this.channel.getLocalAddress();
            SocketAddress remoteAddress = this.channel.getRemoteAddress();
            if (localAddress == null || remoteAddress == null) {
                if (this.future != null) {
                    this.future.setFailure(new ClosedChannelException());
                }
                NioWorker.this.close(this.channel, Channels.succeededFuture(this.channel));
                return;
            }
            try {
                if (this.server) {
                    ((SocketChannel) this.channel.channel).configureBlocking(false);
                }
                ((SocketChannel) this.channel.channel).register(NioWorker.this.selector, this.channel.getRawInterestOps(), this.channel);
                if (this.future != null) {
                    this.channel.setConnected();
                    this.future.setSuccess();
                }
                if (this.server || !((NioClientSocketChannel) this.channel).boundManually) {
                    Channels.fireChannelBound((Channel) this.channel, localAddress);
                }
                Channels.fireChannelConnected((Channel) this.channel, remoteAddress);
            } catch (IOException e) {
                if (this.future != null) {
                    this.future.setFailure(e);
                }
                NioWorker.this.close(this.channel, Channels.succeededFuture(this.channel));
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

    public NioWorker(Executor executor) {
        super(executor);
    }

    public NioWorker(Executor executor, ThreadNameDeterminer determiner) {
        super(executor, determiner);
    }

    /* access modifiers changed from: protected */
    public boolean read(SelectionKey k) {
        SocketChannel ch = (SocketChannel) k.channel();
        NioSocketChannel channel = (NioSocketChannel) k.attachment();
        ReceiveBufferSizePredictor predictor = channel.getConfig().getReceiveBufferSizePredictor();
        int predictedRecvBufSize = predictor.nextReceiveBufferSize();
        ChannelBufferFactory bufferFactory = channel.getConfig().getBufferFactory();
        int ret = 0;
        int readBytes = 0;
        boolean failure = true;
        ByteBuffer bb = this.recvBufferPool.get(predictedRecvBufSize).order(bufferFactory.getDefaultOrder());
        do {
            try {
                ret = ch.read(bb);
                if (ret <= 0) {
                    break;
                }
                readBytes += ret;
            } catch (ClosedChannelException e) {
            } catch (Throwable t) {
                Channels.fireExceptionCaught((Channel) channel, t);
            }
        } while (bb.hasRemaining());
        failure = false;
        if (readBytes > 0) {
            bb.flip();
            ChannelBuffer buffer = bufferFactory.getBuffer(readBytes);
            buffer.setBytes(0, bb);
            buffer.writerIndex(readBytes);
            predictor.previousReceiveBufferSize(readBytes);
            Channels.fireMessageReceived((Channel) channel, (Object) buffer);
        }
        if (ret >= 0 && !failure) {
            return true;
        }
        k.cancel();
        close(channel, Channels.succeededFuture(channel));
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean scheduleWriteIfNecessary(AbstractNioChannel<?> channel) {
        if (Thread.currentThread() == this.thread) {
            return false;
        }
        if (!channel.writeTaskInTaskQueue.compareAndSet(false, true)) {
            return true;
        }
        registerTask(channel.writeTask);
        return true;
    }

    /* access modifiers changed from: protected */
    public Runnable createRegisterTask(Channel channel, ChannelFuture future) {
        return new RegisterTask((NioSocketChannel) channel, future, !(channel instanceof NioClientSocketChannel));
    }

    public void run() {
        super.run();
        this.recvBufferPool.releaseExternalResources();
    }
}