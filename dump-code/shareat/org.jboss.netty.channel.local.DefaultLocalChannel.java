package org.jboss.netty.channel.local;

import java.nio.channels.ClosedChannelException;
import java.nio.channels.NotYetConnectedException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import org.jboss.netty.channel.AbstractChannel;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelConfig;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelSink;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.DefaultChannelConfig;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.util.internal.ThreadLocalBoolean;

final class DefaultLocalChannel extends AbstractChannel implements LocalChannel {
    private static final int ST_BOUND = 1;
    private static final int ST_CLOSED = -1;
    private static final int ST_CONNECTED = 2;
    private static final int ST_OPEN = 0;
    private final ChannelConfig config;
    private final ThreadLocalBoolean delivering = new ThreadLocalBoolean();
    volatile LocalAddress localAddress;
    volatile DefaultLocalChannel pairedChannel;
    volatile LocalAddress remoteAddress;
    final AtomicInteger state = new AtomicInteger(0);
    final Queue<MessageEvent> writeBuffer = new ConcurrentLinkedQueue();

    DefaultLocalChannel(LocalServerChannel parent, ChannelFactory factory, ChannelPipeline pipeline, ChannelSink sink, DefaultLocalChannel pairedChannel2) {
        super(parent, factory, pipeline, sink);
        this.pairedChannel = pairedChannel2;
        this.config = new DefaultChannelConfig();
        getCloseFuture().addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture future) throws Exception {
                DefaultLocalChannel.this.state.set(-1);
            }
        });
        Channels.fireChannelOpen((Channel) this);
    }

    public ChannelConfig getConfig() {
        return this.config;
    }

    public boolean isOpen() {
        return this.state.get() >= 0;
    }

    public boolean isBound() {
        return this.state.get() >= 1;
    }

    public boolean isConnected() {
        return this.state.get() == 2;
    }

    /* access modifiers changed from: 0000 */
    public void setBound() throws ClosedChannelException {
        if (!this.state.compareAndSet(0, 1)) {
            switch (this.state.get()) {
                case -1:
                    throw new ClosedChannelException();
                default:
                    throw new ChannelException((String) "already bound");
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void setConnected() {
        if (this.state.get() != -1) {
            this.state.set(2);
        }
    }

    /* access modifiers changed from: protected */
    public boolean setClosed() {
        return super.setClosed();
    }

    public LocalAddress getLocalAddress() {
        return this.localAddress;
    }

    public LocalAddress getRemoteAddress() {
        return this.remoteAddress;
    }

    /* access modifiers changed from: 0000 */
    public void closeNow(ChannelFuture future) {
        LocalAddress localAddress2 = this.localAddress;
        try {
            if (setClosed()) {
                DefaultLocalChannel pairedChannel2 = this.pairedChannel;
                if (pairedChannel2 != null) {
                    this.pairedChannel = null;
                    Channels.fireChannelDisconnected((Channel) this);
                    Channels.fireChannelUnbound((Channel) this);
                }
                Channels.fireChannelClosed((Channel) this);
                if (pairedChannel2 == null || !pairedChannel2.setClosed()) {
                    future.setSuccess();
                    if (localAddress2 == null || getParent() != null) {
                    }
                } else {
                    if (pairedChannel2.pairedChannel != null) {
                        pairedChannel2.pairedChannel = null;
                        Channels.fireChannelDisconnected((Channel) pairedChannel2);
                        Channels.fireChannelUnbound((Channel) pairedChannel2);
                    }
                    Channels.fireChannelClosed((Channel) pairedChannel2);
                    future.setSuccess();
                    if (localAddress2 == null || getParent() != null) {
                    }
                }
            }
        } finally {
            future.setSuccess();
            if (localAddress2 != null && getParent() == null) {
                LocalChannelRegistry.unregister(localAddress2);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void flushWriteBuffer() {
        Exception cause;
        DefaultLocalChannel pairedChannel2 = this.pairedChannel;
        if (pairedChannel2 == null) {
            if (isOpen()) {
                cause = new NotYetConnectedException();
            } else {
                cause = new ClosedChannelException();
            }
            while (true) {
                MessageEvent e = this.writeBuffer.poll();
                if (e != null) {
                    e.getFuture().setFailure(cause);
                    Channels.fireExceptionCaught((Channel) this, (Throwable) cause);
                } else {
                    return;
                }
            }
        } else if (pairedChannel2.isConnected() && !((Boolean) this.delivering.get()).booleanValue()) {
            this.delivering.set(Boolean.valueOf(true));
            while (true) {
                try {
                    MessageEvent e2 = this.writeBuffer.poll();
                    if (e2 != null) {
                        Channels.fireMessageReceived((Channel) pairedChannel2, e2.getMessage());
                        e2.getFuture().setSuccess();
                        Channels.fireWriteComplete((Channel) this, 1);
                    } else {
                        return;
                    }
                } finally {
                    this.delivering.set(Boolean.valueOf(false));
                }
            }
        }
    }
}