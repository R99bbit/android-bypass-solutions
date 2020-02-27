package org.jboss.netty.channel.socket.nio;

import java.net.ConnectException;
import java.net.SocketAddress;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SocketChannel;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelState;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

class NioClientSocketPipelineSink extends AbstractNioChannelSink {
    static final /* synthetic */ boolean $assertionsDisabled = (!NioClientSocketPipelineSink.class.desiredAssertionStatus());
    static final InternalLogger logger = InternalLoggerFactory.getInstance(NioClientSocketPipelineSink.class);
    private final BossPool<NioClientBoss> bossPool;

    NioClientSocketPipelineSink(BossPool<NioClientBoss> bossPool2) {
        this.bossPool = bossPool2;
    }

    public void eventSunk(ChannelPipeline pipeline, ChannelEvent e) throws Exception {
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent event = (ChannelStateEvent) e;
            NioClientSocketChannel channel = (NioClientSocketChannel) event.getChannel();
            ChannelFuture future = event.getFuture();
            ChannelState state = event.getState();
            Object value = event.getValue();
            switch (state) {
                case OPEN:
                    if (Boolean.FALSE.equals(value)) {
                        channel.worker.close(channel, future);
                        return;
                    }
                    return;
                case BOUND:
                    if (value != null) {
                        bind(channel, future, (SocketAddress) value);
                        return;
                    } else {
                        channel.worker.close(channel, future);
                        return;
                    }
                case CONNECTED:
                    if (value != null) {
                        connect(channel, future, (SocketAddress) value);
                        return;
                    } else {
                        channel.worker.close(channel, future);
                        return;
                    }
                case INTEREST_OPS:
                    channel.worker.setInterestOps(channel, future, ((Integer) value).intValue());
                    return;
                default:
                    return;
            }
        } else if (e instanceof MessageEvent) {
            MessageEvent event2 = (MessageEvent) e;
            NioSocketChannel channel2 = (NioSocketChannel) event2.getChannel();
            boolean offered = channel2.writeBufferQueue.offer(event2);
            if ($assertionsDisabled || offered) {
                channel2.worker.writeFromUserCode(channel2);
                return;
            }
            throw new AssertionError();
        }
    }

    private static void bind(NioClientSocketChannel channel, ChannelFuture future, SocketAddress localAddress) {
        try {
            ((SocketChannel) channel.channel).socket().bind(localAddress);
            channel.boundManually = true;
            channel.setBound();
            future.setSuccess();
            Channels.fireChannelBound((Channel) channel, (SocketAddress) channel.getLocalAddress());
        } catch (Throwable t) {
            future.setFailure(t);
            Channels.fireExceptionCaught((Channel) channel, t);
        }
    }

    private void connect(NioClientSocketChannel channel, final ChannelFuture cf, SocketAddress remoteAddress) {
        channel.requestedRemoteAddress = remoteAddress;
        try {
            if (((SocketChannel) channel.channel).connect(remoteAddress)) {
                channel.worker.register(channel, cf);
                return;
            }
            channel.getCloseFuture().addListener(new ChannelFutureListener() {
                public void operationComplete(ChannelFuture f) throws Exception {
                    if (!cf.isDone()) {
                        cf.setFailure(new ClosedChannelException());
                    }
                }
            });
            cf.addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
            channel.connectFuture = cf;
            nextBoss().register(channel, cf);
        } catch (Throwable th) {
            t = th;
            if (t instanceof ConnectException) {
                Throwable newT = new ConnectException(t.getMessage() + ": " + remoteAddress);
                newT.setStackTrace(t.getStackTrace());
                t = newT;
            }
            cf.setFailure(t);
            Channels.fireExceptionCaught((Channel) channel, t);
            channel.worker.close(channel, Channels.succeededFuture(channel));
        }
    }

    private NioClientBoss nextBoss() {
        return (NioClientBoss) this.bossPool.nextBoss();
    }
}