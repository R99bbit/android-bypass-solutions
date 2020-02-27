package org.jboss.netty.channel.socket.oio;

import java.net.SocketAddress;
import java.util.concurrent.Executor;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelState;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.util.ThreadNameDeterminer;
import org.jboss.netty.util.ThreadRenamingRunnable;
import org.jboss.netty.util.internal.DeadLockProofWorker;

class OioDatagramPipelineSink extends AbstractOioChannelSink {
    private final ThreadNameDeterminer determiner;
    private final Executor workerExecutor;

    OioDatagramPipelineSink(Executor workerExecutor2, ThreadNameDeterminer determiner2) {
        this.workerExecutor = workerExecutor2;
        this.determiner = determiner2;
    }

    public void eventSunk(ChannelPipeline pipeline, ChannelEvent e) throws Exception {
        OioDatagramChannel channel = (OioDatagramChannel) e.getChannel();
        ChannelFuture future = e.getFuture();
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent stateEvent = (ChannelStateEvent) e;
            ChannelState state = stateEvent.getState();
            Object value = stateEvent.getValue();
            switch (state) {
                case OPEN:
                    if (Boolean.FALSE.equals(value)) {
                        AbstractOioWorker.close(channel, future);
                        return;
                    }
                    return;
                case BOUND:
                    if (value != null) {
                        bind(channel, future, (SocketAddress) value);
                        return;
                    } else {
                        AbstractOioWorker.close(channel, future);
                        return;
                    }
                case CONNECTED:
                    if (value != null) {
                        connect(channel, future, (SocketAddress) value);
                        return;
                    } else {
                        OioDatagramWorker.disconnect(channel, future);
                        return;
                    }
                case INTEREST_OPS:
                    AbstractOioWorker.setInterestOps(channel, future, ((Integer) value).intValue());
                    return;
                default:
                    return;
            }
        } else if (e instanceof MessageEvent) {
            MessageEvent evt = (MessageEvent) e;
            OioDatagramWorker.write(channel, future, evt.getMessage(), evt.getRemoteAddress());
        }
    }

    private void bind(OioDatagramChannel channel, ChannelFuture future, SocketAddress localAddress) {
        boolean bound = false;
        try {
            channel.socket.bind(localAddress);
            bound = true;
            future.setSuccess();
            Channels.fireChannelBound((Channel) channel, (SocketAddress) channel.getLocalAddress());
            DeadLockProofWorker.start(this.workerExecutor, new ThreadRenamingRunnable(new OioDatagramWorker(channel), "Old I/O datagram worker (" + channel + ')', this.determiner));
            if (1 == 0 || 1 != 0) {
                return;
            }
        } catch (Throwable th) {
            if (bound && 0 == 0) {
                AbstractOioWorker.close(channel, future);
            }
            throw th;
        }
        AbstractOioWorker.close(channel, future);
    }

    private void connect(OioDatagramChannel channel, ChannelFuture future, SocketAddress remoteAddress) {
        boolean bound = channel.isBound();
        boolean connected = false;
        future.addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
        channel.remoteAddress = null;
        try {
            channel.socket.connect(remoteAddress);
            connected = true;
            future.setSuccess();
            if (!bound) {
                Channels.fireChannelBound((Channel) channel, (SocketAddress) channel.getLocalAddress());
            }
            Channels.fireChannelConnected((Channel) channel, (SocketAddress) channel.getRemoteAddress());
            String threadName = "Old I/O datagram worker (" + channel + ')';
            if (!bound) {
                DeadLockProofWorker.start(this.workerExecutor, new ThreadRenamingRunnable(new OioDatagramWorker(channel), threadName, this.determiner));
            } else {
                Thread workerThread = channel.workerThread;
                if (workerThread != null) {
                    try {
                        workerThread.setName(threadName);
                    } catch (SecurityException e) {
                    }
                }
            }
            if (1 == 0 || 1 != 0) {
                return;
            }
        } catch (Throwable th) {
            if (connected && 0 == 0) {
                AbstractOioWorker.close(channel, future);
            }
            throw th;
        }
        AbstractOioWorker.close(channel, future);
    }
}