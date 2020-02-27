package org.jboss.netty.channel.socket.nio;

import java.net.SocketAddress;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelState;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.MessageEvent;

class NioServerSocketPipelineSink extends AbstractNioChannelSink {
    static final /* synthetic */ boolean $assertionsDisabled = (!NioServerSocketPipelineSink.class.desiredAssertionStatus());

    NioServerSocketPipelineSink() {
    }

    public void eventSunk(ChannelPipeline pipeline, ChannelEvent e) throws Exception {
        Channel channel = e.getChannel();
        if (channel instanceof NioServerSocketChannel) {
            handleServerSocket(e);
        } else if (channel instanceof NioSocketChannel) {
            handleAcceptedSocket(e);
        }
    }

    private static void handleServerSocket(ChannelEvent e) {
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent event = (ChannelStateEvent) e;
            NioServerSocketChannel channel = (NioServerSocketChannel) event.getChannel();
            ChannelFuture future = event.getFuture();
            ChannelState state = event.getState();
            Object value = event.getValue();
            switch (state) {
                case OPEN:
                    if (Boolean.FALSE.equals(value)) {
                        ((NioServerBoss) channel.boss).close(channel, future);
                        return;
                    }
                    return;
                case BOUND:
                    if (value != null) {
                        ((NioServerBoss) channel.boss).bind(channel, future, (SocketAddress) value);
                        return;
                    } else {
                        ((NioServerBoss) channel.boss).close(channel, future);
                        return;
                    }
                default:
                    return;
            }
        }
    }

    private static void handleAcceptedSocket(ChannelEvent e) {
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent event = (ChannelStateEvent) e;
            NioSocketChannel channel = (NioSocketChannel) event.getChannel();
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
                case CONNECTED:
                    if (value == null) {
                        channel.worker.close(channel, future);
                        return;
                    }
                    return;
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
}