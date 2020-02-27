package org.jboss.netty.channel.local;

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

final class LocalServerChannelSink extends AbstractChannelSink {
    static final /* synthetic */ boolean $assertionsDisabled = (!LocalServerChannelSink.class.desiredAssertionStatus());

    LocalServerChannelSink() {
    }

    public void eventSunk(ChannelPipeline pipeline, ChannelEvent e) throws Exception {
        Channel channel = e.getChannel();
        if (channel instanceof DefaultLocalServerChannel) {
            handleServerChannel(e);
        } else if (channel instanceof DefaultLocalChannel) {
            handleAcceptedChannel(e);
        }
    }

    private static void handleServerChannel(ChannelEvent e) {
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent event = (ChannelStateEvent) e;
            DefaultLocalServerChannel channel = (DefaultLocalServerChannel) event.getChannel();
            ChannelFuture future = event.getFuture();
            ChannelState state = event.getState();
            Object value = event.getValue();
            switch (state) {
                case OPEN:
                    if (Boolean.FALSE.equals(value)) {
                        close(channel, future);
                        return;
                    }
                    return;
                case BOUND:
                    if (value != null) {
                        bind(channel, future, (LocalAddress) value);
                        return;
                    } else {
                        close(channel, future);
                        return;
                    }
                default:
                    return;
            }
        }
    }

    private static void handleAcceptedChannel(ChannelEvent e) {
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
                case CONNECTED:
                    if (value == null) {
                        channel.closeNow(future);
                        return;
                    }
                    return;
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

    private static void bind(DefaultLocalServerChannel channel, ChannelFuture future, LocalAddress localAddress) {
        try {
            if (!LocalChannelRegistry.register(localAddress, channel)) {
                throw new ChannelException("address already in use: " + localAddress);
            } else if (!channel.bound.compareAndSet(false, true)) {
                throw new ChannelException((String) "already bound");
            } else {
                channel.localAddress = localAddress;
                future.setSuccess();
                Channels.fireChannelBound((Channel) channel, (SocketAddress) localAddress);
            }
        } catch (Throwable t) {
            LocalChannelRegistry.unregister(localAddress);
            future.setFailure(t);
            Channels.fireExceptionCaught((Channel) channel, t);
        }
    }

    private static void close(DefaultLocalServerChannel channel, ChannelFuture future) {
        try {
            if (channel.setClosed()) {
                future.setSuccess();
                LocalAddress localAddress = channel.localAddress;
                if (channel.bound.compareAndSet(true, false)) {
                    channel.localAddress = null;
                    LocalChannelRegistry.unregister(localAddress);
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
}