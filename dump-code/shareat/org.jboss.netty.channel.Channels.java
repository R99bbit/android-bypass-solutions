package org.jboss.netty.channel;

import java.net.SocketAddress;
import java.util.Map.Entry;
import org.jboss.netty.util.internal.ConversionUtil;

public final class Channels {
    public static ChannelPipeline pipeline() {
        return new DefaultChannelPipeline();
    }

    public static ChannelPipeline pipeline(ChannelHandler... handlers) {
        if (handlers == null) {
            throw new NullPointerException("handlers");
        }
        ChannelPipeline newPipeline = pipeline();
        for (int i = 0; i < handlers.length; i++) {
            ChannelHandler h = handlers[i];
            if (h == null) {
                break;
            }
            newPipeline.addLast(ConversionUtil.toString(i), h);
        }
        return newPipeline;
    }

    public static ChannelPipeline pipeline(ChannelPipeline pipeline) {
        ChannelPipeline newPipeline = pipeline();
        for (Entry<String, ChannelHandler> e : pipeline.toMap().entrySet()) {
            newPipeline.addLast(e.getKey(), e.getValue());
        }
        return newPipeline;
    }

    public static ChannelPipelineFactory pipelineFactory(final ChannelPipeline pipeline) {
        return new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() {
                return Channels.pipeline(pipeline);
            }
        };
    }

    public static ChannelFuture future(Channel channel) {
        return future(channel, false);
    }

    public static ChannelFuture future(Channel channel, boolean cancellable) {
        return new DefaultChannelFuture(channel, cancellable);
    }

    public static ChannelFuture succeededFuture(Channel channel) {
        if (channel instanceof AbstractChannel) {
            return ((AbstractChannel) channel).getSucceededFuture();
        }
        return new SucceededChannelFuture(channel);
    }

    public static ChannelFuture failedFuture(Channel channel, Throwable cause) {
        return new FailedChannelFuture(channel, cause);
    }

    public static void fireChannelOpen(Channel channel) {
        if (channel.getParent() != null) {
            fireChildChannelStateChanged(channel.getParent(), channel);
        }
        channel.getPipeline().sendUpstream(new UpstreamChannelStateEvent(channel, ChannelState.OPEN, Boolean.TRUE));
    }

    public static void fireChannelOpen(ChannelHandlerContext ctx) {
        ctx.sendUpstream(new UpstreamChannelStateEvent(ctx.getChannel(), ChannelState.OPEN, Boolean.TRUE));
    }

    public static void fireChannelBound(Channel channel, SocketAddress localAddress) {
        channel.getPipeline().sendUpstream(new UpstreamChannelStateEvent(channel, ChannelState.BOUND, localAddress));
    }

    public static void fireChannelBound(ChannelHandlerContext ctx, SocketAddress localAddress) {
        ctx.sendUpstream(new UpstreamChannelStateEvent(ctx.getChannel(), ChannelState.BOUND, localAddress));
    }

    public static void fireChannelConnected(Channel channel, SocketAddress remoteAddress) {
        channel.getPipeline().sendUpstream(new UpstreamChannelStateEvent(channel, ChannelState.CONNECTED, remoteAddress));
    }

    public static void fireChannelConnected(ChannelHandlerContext ctx, SocketAddress remoteAddress) {
        ctx.sendUpstream(new UpstreamChannelStateEvent(ctx.getChannel(), ChannelState.CONNECTED, remoteAddress));
    }

    public static void fireMessageReceived(Channel channel, Object message) {
        fireMessageReceived(channel, message, (SocketAddress) null);
    }

    public static void fireMessageReceived(Channel channel, Object message, SocketAddress remoteAddress) {
        channel.getPipeline().sendUpstream(new UpstreamMessageEvent(channel, message, remoteAddress));
    }

    public static void fireMessageReceived(ChannelHandlerContext ctx, Object message) {
        ctx.sendUpstream(new UpstreamMessageEvent(ctx.getChannel(), message, null));
    }

    public static void fireMessageReceived(ChannelHandlerContext ctx, Object message, SocketAddress remoteAddress) {
        ctx.sendUpstream(new UpstreamMessageEvent(ctx.getChannel(), message, remoteAddress));
    }

    public static ChannelFuture fireWriteCompleteLater(final Channel channel, final long amount) {
        return channel.getPipeline().execute(new Runnable() {
            public void run() {
                Channels.fireWriteComplete(channel, amount);
            }
        });
    }

    public static void fireWriteComplete(Channel channel, long amount) {
        if (amount != 0) {
            channel.getPipeline().sendUpstream(new DefaultWriteCompletionEvent(channel, amount));
        }
    }

    public static void fireWriteComplete(ChannelHandlerContext ctx, long amount) {
        ctx.sendUpstream(new DefaultWriteCompletionEvent(ctx.getChannel(), amount));
    }

    public static ChannelFuture fireChannelInterestChangedLater(final Channel channel) {
        return channel.getPipeline().execute(new Runnable() {
            public void run() {
                Channels.fireChannelInterestChanged(channel);
            }
        });
    }

    public static void fireChannelInterestChanged(Channel channel) {
        channel.getPipeline().sendUpstream(new UpstreamChannelStateEvent(channel, ChannelState.INTEREST_OPS, Integer.valueOf(1)));
    }

    public static void fireChannelInterestChanged(ChannelHandlerContext ctx) {
        ctx.sendUpstream(new UpstreamChannelStateEvent(ctx.getChannel(), ChannelState.INTEREST_OPS, Integer.valueOf(1)));
    }

    public static ChannelFuture fireChannelDisconnectedLater(final Channel channel) {
        return channel.getPipeline().execute(new Runnable() {
            public void run() {
                Channels.fireChannelDisconnected(channel);
            }
        });
    }

    public static void fireChannelDisconnected(Channel channel) {
        channel.getPipeline().sendUpstream(new UpstreamChannelStateEvent(channel, ChannelState.CONNECTED, null));
    }

    public static void fireChannelDisconnected(ChannelHandlerContext ctx) {
        ctx.sendUpstream(new UpstreamChannelStateEvent(ctx.getChannel(), ChannelState.CONNECTED, null));
    }

    public static ChannelFuture fireChannelUnboundLater(final Channel channel) {
        return channel.getPipeline().execute(new Runnable() {
            public void run() {
                Channels.fireChannelUnbound(channel);
            }
        });
    }

    public static void fireChannelUnbound(Channel channel) {
        channel.getPipeline().sendUpstream(new UpstreamChannelStateEvent(channel, ChannelState.BOUND, null));
    }

    public static void fireChannelUnbound(ChannelHandlerContext ctx) {
        ctx.sendUpstream(new UpstreamChannelStateEvent(ctx.getChannel(), ChannelState.BOUND, null));
    }

    public static ChannelFuture fireChannelClosedLater(final Channel channel) {
        return channel.getPipeline().execute(new Runnable() {
            public void run() {
                Channels.fireChannelClosed(channel);
            }
        });
    }

    public static void fireChannelClosed(Channel channel) {
        channel.getPipeline().sendUpstream(new UpstreamChannelStateEvent(channel, ChannelState.OPEN, Boolean.FALSE));
        if (channel.getParent() != null) {
            fireChildChannelStateChanged(channel.getParent(), channel);
        }
    }

    public static void fireChannelClosed(ChannelHandlerContext ctx) {
        ctx.sendUpstream(new UpstreamChannelStateEvent(ctx.getChannel(), ChannelState.OPEN, Boolean.FALSE));
    }

    public static ChannelFuture fireExceptionCaughtLater(final Channel channel, final Throwable cause) {
        return channel.getPipeline().execute(new Runnable() {
            public void run() {
                Channels.fireExceptionCaught(channel, cause);
            }
        });
    }

    public static ChannelFuture fireExceptionCaughtLater(final ChannelHandlerContext ctx, final Throwable cause) {
        return ctx.getPipeline().execute(new Runnable() {
            public void run() {
                Channels.fireExceptionCaught(ctx, cause);
            }
        });
    }

    public static void fireExceptionCaught(Channel channel, Throwable cause) {
        channel.getPipeline().sendUpstream(new DefaultExceptionEvent(channel, cause));
    }

    public static void fireExceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.sendUpstream(new DefaultExceptionEvent(ctx.getChannel(), cause));
    }

    private static void fireChildChannelStateChanged(Channel channel, Channel childChannel) {
        channel.getPipeline().sendUpstream(new DefaultChildChannelStateEvent(channel, childChannel));
    }

    public static ChannelFuture bind(Channel channel, SocketAddress localAddress) {
        if (localAddress == null) {
            throw new NullPointerException("localAddress");
        }
        ChannelFuture future = future(channel);
        channel.getPipeline().sendDownstream(new DownstreamChannelStateEvent(channel, future, ChannelState.BOUND, localAddress));
        return future;
    }

    public static void bind(ChannelHandlerContext ctx, ChannelFuture future, SocketAddress localAddress) {
        if (localAddress == null) {
            throw new NullPointerException("localAddress");
        }
        ctx.sendDownstream(new DownstreamChannelStateEvent(ctx.getChannel(), future, ChannelState.BOUND, localAddress));
    }

    public static void unbind(ChannelHandlerContext ctx, ChannelFuture future) {
        ctx.sendDownstream(new DownstreamChannelStateEvent(ctx.getChannel(), future, ChannelState.BOUND, null));
    }

    public static ChannelFuture unbind(Channel channel) {
        ChannelFuture future = future(channel);
        channel.getPipeline().sendDownstream(new DownstreamChannelStateEvent(channel, future, ChannelState.BOUND, null));
        return future;
    }

    public static ChannelFuture connect(Channel channel, SocketAddress remoteAddress) {
        if (remoteAddress == null) {
            throw new NullPointerException("remoteAddress");
        }
        ChannelFuture future = future(channel, true);
        channel.getPipeline().sendDownstream(new DownstreamChannelStateEvent(channel, future, ChannelState.CONNECTED, remoteAddress));
        return future;
    }

    public static void connect(ChannelHandlerContext ctx, ChannelFuture future, SocketAddress remoteAddress) {
        if (remoteAddress == null) {
            throw new NullPointerException("remoteAddress");
        }
        ctx.sendDownstream(new DownstreamChannelStateEvent(ctx.getChannel(), future, ChannelState.CONNECTED, remoteAddress));
    }

    public static ChannelFuture write(Channel channel, Object message) {
        return write(channel, message, (SocketAddress) null);
    }

    public static void write(ChannelHandlerContext ctx, ChannelFuture future, Object message) {
        write(ctx, future, message, null);
    }

    public static ChannelFuture write(Channel channel, Object message, SocketAddress remoteAddress) {
        ChannelFuture future = future(channel);
        channel.getPipeline().sendDownstream(new DownstreamMessageEvent(channel, future, message, remoteAddress));
        return future;
    }

    public static void write(ChannelHandlerContext ctx, ChannelFuture future, Object message, SocketAddress remoteAddress) {
        ctx.sendDownstream(new DownstreamMessageEvent(ctx.getChannel(), future, message, remoteAddress));
    }

    public static ChannelFuture setInterestOps(Channel channel, int interestOps) {
        validateInterestOps(interestOps);
        int interestOps2 = filterDownstreamInterestOps(interestOps);
        ChannelFuture future = future(channel);
        channel.getPipeline().sendDownstream(new DownstreamChannelStateEvent(channel, future, ChannelState.INTEREST_OPS, Integer.valueOf(interestOps2)));
        return future;
    }

    public static void setInterestOps(ChannelHandlerContext ctx, ChannelFuture future, int interestOps) {
        validateInterestOps(interestOps);
        ctx.sendDownstream(new DownstreamChannelStateEvent(ctx.getChannel(), future, ChannelState.INTEREST_OPS, Integer.valueOf(filterDownstreamInterestOps(interestOps))));
    }

    public static ChannelFuture disconnect(Channel channel) {
        ChannelFuture future = future(channel);
        channel.getPipeline().sendDownstream(new DownstreamChannelStateEvent(channel, future, ChannelState.CONNECTED, null));
        return future;
    }

    public static void disconnect(ChannelHandlerContext ctx, ChannelFuture future) {
        ctx.sendDownstream(new DownstreamChannelStateEvent(ctx.getChannel(), future, ChannelState.CONNECTED, null));
    }

    public static ChannelFuture close(Channel channel) {
        ChannelFuture future = channel.getCloseFuture();
        channel.getPipeline().sendDownstream(new DownstreamChannelStateEvent(channel, future, ChannelState.OPEN, Boolean.FALSE));
        return future;
    }

    public static void close(ChannelHandlerContext ctx, ChannelFuture future) {
        ctx.sendDownstream(new DownstreamChannelStateEvent(ctx.getChannel(), future, ChannelState.OPEN, Boolean.FALSE));
    }

    private static void validateInterestOps(int interestOps) {
        switch (interestOps) {
            case 0:
            case 1:
            case 4:
            case 5:
                return;
            default:
                throw new IllegalArgumentException("Invalid interestOps: " + interestOps);
        }
    }

    private static int filterDownstreamInterestOps(int interestOps) {
        return interestOps & -5;
    }

    private Channels() {
    }
}