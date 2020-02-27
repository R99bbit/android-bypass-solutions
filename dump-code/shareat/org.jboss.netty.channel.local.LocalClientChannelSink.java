package org.jboss.netty.channel.local;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketAddress;
import org.jboss.netty.channel.AbstractChannelSink;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelState;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

final class LocalClientChannelSink extends AbstractChannelSink {
    static final /* synthetic */ boolean $assertionsDisabled = (!LocalClientChannelSink.class.desiredAssertionStatus());
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(LocalClientChannelSink.class);

    LocalClientChannelSink() {
    }

    public void eventSunk(ChannelPipeline pipeline, ChannelEvent e) throws Exception {
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent event = (ChannelStateEvent) e;
            DefaultLocalChannel channel = (DefaultLocalChannel) event.getChannel();
            ChannelFuture future = event.getFuture();
            ChannelState state = event.getState();
            Object value = event.getValue();
            switch (state) {
                case OPEN:
                    if (Boolean.FALSE.equals(value)) {
                        channel.closeNow(future);
                        return;
                    }
                    return;
                case BOUND:
                    if (value != null) {
                        bind(channel, future, (LocalAddress) value);
                        return;
                    } else {
                        channel.closeNow(future);
                        return;
                    }
                case CONNECTED:
                    if (value != null) {
                        connect(channel, future, (LocalAddress) value);
                        return;
                    } else {
                        channel.closeNow(future);
                        return;
                    }
                case INTEREST_OPS:
                    future.setSuccess();
                    return;
                default:
                    return;
            }
        } else if (e instanceof MessageEvent) {
            MessageEvent event2 = (MessageEvent) e;
            DefaultLocalChannel channel2 = (DefaultLocalChannel) event2.getChannel();
            boolean offered = channel2.writeBuffer.offer(event2);
            if ($assertionsDisabled || offered) {
                channel2.flushWriteBuffer();
                return;
            }
            throw new AssertionError();
        }
    }

    private static void bind(DefaultLocalChannel channel, ChannelFuture future, LocalAddress localAddress) {
        try {
            if (!LocalChannelRegistry.register(localAddress, channel)) {
                throw new ChannelException("address already in use: " + localAddress);
            }
            channel.setBound();
            channel.localAddress = localAddress;
            future.setSuccess();
            Channels.fireChannelBound((Channel) channel, (SocketAddress) localAddress);
        } catch (Throwable t) {
            LocalChannelRegistry.unregister(localAddress);
            future.setFailure(t);
            Channels.fireExceptionCaught((Channel) channel, t);
        }
    }

    private void connect(DefaultLocalChannel channel, ChannelFuture future, LocalAddress remoteAddress) {
        Channel remoteChannel = LocalChannelRegistry.getChannel(remoteAddress);
        if (!(remoteChannel instanceof DefaultLocalServerChannel)) {
            future.setFailure(new ConnectException("connection refused: " + remoteAddress));
            return;
        }
        DefaultLocalServerChannel serverChannel = (DefaultLocalServerChannel) remoteChannel;
        try {
            ChannelPipeline pipeline = serverChannel.getConfig().getPipelineFactory().getPipeline();
            future.setSuccess();
            DefaultLocalChannel acceptedChannel = new DefaultLocalChannel(serverChannel, serverChannel.getFactory(), pipeline, this, channel);
            channel.pairedChannel = acceptedChannel;
            if (!channel.isBound()) {
                bind(channel, Channels.succeededFuture(channel), new LocalAddress((String) LocalAddress.EPHEMERAL));
            }
            channel.remoteAddress = serverChannel.getLocalAddress();
            channel.setConnected();
            Channels.fireChannelConnected((Channel) channel, (SocketAddress) serverChannel.getLocalAddress());
            acceptedChannel.localAddress = serverChannel.getLocalAddress();
            try {
                acceptedChannel.setBound();
                Channels.fireChannelBound((Channel) acceptedChannel, (SocketAddress) channel.getRemoteAddress());
                acceptedChannel.remoteAddress = channel.getLocalAddress();
                acceptedChannel.setConnected();
                Channels.fireChannelConnected((Channel) acceptedChannel, (SocketAddress) channel.getLocalAddress());
                channel.flushWriteBuffer();
                acceptedChannel.flushWriteBuffer();
            } catch (IOException e) {
                throw new Error(e);
            }
        } catch (Exception e2) {
            future.setFailure(e2);
            Channels.fireExceptionCaught((Channel) channel, (Throwable) e2);
            if (logger.isWarnEnabled()) {
                logger.warn("Failed to initialize an accepted socket.", e2);
            }
        }
    }
}