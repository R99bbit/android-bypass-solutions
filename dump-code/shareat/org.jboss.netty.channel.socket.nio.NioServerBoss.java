package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.Executor;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelSink;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.util.ThreadNameDeterminer;
import org.jboss.netty.util.ThreadRenamingRunnable;

public final class NioServerBoss extends AbstractNioSelector implements Boss {

    private final class RegisterTask implements Runnable {
        private final NioServerSocketChannel channel;
        private final ChannelFuture future;
        private final SocketAddress localAddress;

        public RegisterTask(NioServerSocketChannel channel2, ChannelFuture future2, SocketAddress localAddress2) {
            this.channel = channel2;
            this.future = future2;
            this.localAddress = localAddress2;
        }

        public void run() {
            NioServerBoss nioServerBoss;
            NioServerSocketChannel nioServerSocketChannel;
            ChannelFuture channelFuture;
            boolean bound = false;
            try {
                this.channel.socket.socket().bind(this.localAddress, this.channel.getConfig().getBacklog());
                bound = true;
                this.future.setSuccess();
                Channels.fireChannelBound((Channel) this.channel, (SocketAddress) this.channel.getLocalAddress());
                this.channel.socket.register(NioServerBoss.this.selector, 16, this.channel);
                if (1 == 0 && 1 != 0) {
                    nioServerBoss = NioServerBoss.this;
                    nioServerSocketChannel = this.channel;
                    channelFuture = this.future;
                    nioServerBoss.close(nioServerSocketChannel, channelFuture);
                }
            } catch (Throwable th) {
                if (0 == 0 && bound) {
                    NioServerBoss.this.close(this.channel, this.future);
                }
                throw th;
            }
        }
    }

    public /* bridge */ /* synthetic */ void rebuildSelector() {
        super.rebuildSelector();
    }

    public /* bridge */ /* synthetic */ void register(Channel x0, ChannelFuture x1) {
        super.register(x0, x1);
    }

    public /* bridge */ /* synthetic */ void run() {
        super.run();
    }

    public /* bridge */ /* synthetic */ void shutdown() {
        super.shutdown();
    }

    NioServerBoss(Executor bossExecutor) {
        super(bossExecutor);
    }

    NioServerBoss(Executor bossExecutor, ThreadNameDeterminer determiner) {
        super(bossExecutor, determiner);
    }

    /* access modifiers changed from: 0000 */
    public void bind(NioServerSocketChannel channel, ChannelFuture future, SocketAddress localAddress) {
        registerTask(new RegisterTask(channel, future, localAddress));
    }

    /* access modifiers changed from: protected */
    public void close(SelectionKey k) {
        NioServerSocketChannel ch = (NioServerSocketChannel) k.attachment();
        close(ch, Channels.succeededFuture(ch));
    }

    /* access modifiers changed from: 0000 */
    public void close(NioServerSocketChannel channel, ChannelFuture future) {
        boolean bound = channel.isBound();
        try {
            channel.socket.close();
            increaseCancelledKeys();
            if (channel.setClosed()) {
                future.setSuccess();
                if (bound) {
                    Channels.fireChannelUnbound((Channel) channel);
                }
                Channels.fireChannelClosed((Channel) channel);
                return;
            }
            future.setSuccess();
        } catch (Throwable t) {
            future.setFailure(t);
            Channels.fireExceptionCaught((Channel) channel, t);
        }
    }

    /* access modifiers changed from: protected */
    public void process(Selector selector) {
        Set<SelectionKey> selectedKeys = selector.selectedKeys();
        if (!selectedKeys.isEmpty()) {
            Iterator<SelectionKey> it = selectedKeys.iterator();
            while (it.hasNext()) {
                SelectionKey k = it.next();
                it.remove();
                NioServerSocketChannel channel = (NioServerSocketChannel) k.attachment();
                while (true) {
                    try {
                        SocketChannel acceptedSocket = channel.socket.accept();
                        if (acceptedSocket == null) {
                            break;
                        }
                        registerAcceptedChannel(channel, acceptedSocket, this.thread);
                    } catch (CancelledKeyException e) {
                        k.cancel();
                        channel.close();
                    } catch (SocketTimeoutException | ClosedChannelException e2) {
                    } catch (Throwable t) {
                        if (logger.isWarnEnabled()) {
                            logger.warn("Failed to accept a connection.", t);
                        }
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e3) {
                        }
                    }
                }
            }
        }
    }

    private static void registerAcceptedChannel(NioServerSocketChannel parent, SocketChannel acceptedSocket, Thread currentThread) {
        try {
            ChannelSink sink = parent.getPipeline().getSink();
            NioWorker worker = (NioWorker) parent.workerPool.nextWorker();
            worker.register(new NioAcceptedSocketChannel(parent.getFactory(), parent.getConfig().getPipelineFactory().getPipeline(), parent, sink, acceptedSocket, worker, currentThread), null);
        } catch (Exception e) {
            if (logger.isWarnEnabled()) {
                logger.warn("Failed to initialize an accepted socket.", e);
            }
            try {
                acceptedSocket.close();
            } catch (IOException e2) {
                if (logger.isWarnEnabled()) {
                    logger.warn("Failed to close a partially accepted socket.", e2);
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public int select(Selector selector) throws IOException {
        return selector.select();
    }

    /* access modifiers changed from: protected */
    public ThreadRenamingRunnable newThreadRenamingRunnable(int id, ThreadNameDeterminer determiner) {
        return new ThreadRenamingRunnable(this, "New I/O server boss #" + id, determiner);
    }

    /* access modifiers changed from: protected */
    public Runnable createRegisterTask(Channel channel, ChannelFuture future) {
        return new RegisterTask((NioServerSocketChannel) channel, future, null);
    }
}