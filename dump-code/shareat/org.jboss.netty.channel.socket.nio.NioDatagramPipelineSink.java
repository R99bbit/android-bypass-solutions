package org.jboss.netty.channel.socket.nio;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelState;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;

class NioDatagramPipelineSink extends AbstractNioChannelSink {
    static final /* synthetic */ boolean $assertionsDisabled = (!NioDatagramPipelineSink.class.desiredAssertionStatus());
    private final WorkerPool<NioDatagramWorker> workerPool;

    NioDatagramPipelineSink(WorkerPool<NioDatagramWorker> workerPool2) {
        this.workerPool = workerPool2;
    }

    public void eventSunk(ChannelPipeline pipeline, ChannelEvent e) throws Exception {
        NioDatagramChannel channel = (NioDatagramChannel) e.getChannel();
        ChannelFuture future = e.getFuture();
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent stateEvent = (ChannelStateEvent) e;
            ChannelState state = stateEvent.getState();
            Object value = stateEvent.getValue();
            switch (state) {
                case OPEN:
                    if (Boolean.FALSE.equals(value)) {
                        channel.worker.close(channel, future);
                        return;
                    }
                    return;
                case BOUND:
                    if (value != null) {
                        bind(channel, future, (InetSocketAddress) value);
                        return;
                    } else {
                        channel.worker.close(channel, future);
                        return;
                    }
                case CONNECTED:
                    if (value != null) {
                        connect(channel, future, (InetSocketAddress) value);
                        return;
                    } else {
                        NioDatagramWorker.disconnect(channel, future);
                        return;
                    }
                case INTEREST_OPS:
                    channel.worker.setInterestOps(channel, future, ((Integer) value).intValue());
                    return;
                default:
                    return;
            }
        } else if (e instanceof MessageEvent) {
            boolean offered = channel.writeBufferQueue.offer((MessageEvent) e);
            if ($assertionsDisabled || offered) {
                channel.worker.writeFromUserCode(channel);
                return;
            }
            throw new AssertionError();
        }
    }

    private static void close(NioDatagramChannel channel, ChannelFuture future) {
        try {
            channel.getDatagramChannel().socket().close();
            if (channel.setClosed()) {
                future.setSuccess();
                if (channel.isBound()) {
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

    private static void bind(NioDatagramChannel channel, ChannelFuture future, InetSocketAddress address) {
        boolean bound = false;
        try {
            channel.getDatagramChannel().socket().bind(address);
            bound = true;
            future.setSuccess();
            Channels.fireChannelBound((Channel) channel, (SocketAddress) address);
            channel.worker.register(channel, null);
            if (1 != 0 || 1 == 0) {
                return;
            }
        } catch (Throwable th) {
            if (0 == 0 && bound) {
                close(channel, future);
            }
            throw th;
        }
        close(channel, future);
    }

    private static void connect(NioDatagramChannel channel, ChannelFuture future, InetSocketAddress remoteAddress) {
        AbstractNioWorker abstractNioWorker;
        boolean bound = channel.isBound();
        future.addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
        channel.remoteAddress = null;
        try {
            channel.getDatagramChannel().connect(remoteAddress);
            future.setSuccess();
            if (!bound) {
                Channels.fireChannelBound((Channel) channel, (SocketAddress) channel.getLocalAddress());
            }
            Channels.fireChannelConnected((Channel) channel, (SocketAddress) channel.getRemoteAddress());
            if (!bound) {
                channel.worker.register(channel, future);
            }
            if (1 != 0 && 1 == 0) {
                abstractNioWorker = channel.worker;
                abstractNioWorker.close(channel, future);
            }
        } catch (Throwable th) {
            if (0 != 0 && 0 == 0) {
                channel.worker.close(channel, future);
            }
            throw th;
        }
    }

    /* access modifiers changed from: 0000 */
    public NioDatagramWorker nextWorker() {
        return (NioDatagramWorker) this.workerPool.nextWorker();
    }
}