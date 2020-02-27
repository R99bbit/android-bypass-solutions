package org.jboss.netty.handler.codec.embedder;

import java.lang.reflect.Array;
import java.util.ConcurrentModificationException;
import java.util.LinkedList;
import java.util.Queue;
import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineException;
import org.jboss.netty.channel.ChannelSink;
import org.jboss.netty.channel.ChannelUpstreamHandler;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.DefaultChannelPipeline;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;

abstract class AbstractCodecEmbedder<E> implements CodecEmbedder<E> {
    private final Channel channel;
    private final ChannelPipeline pipeline;
    final Queue<Object> productQueue;
    private final EmbeddedChannelSink sink;

    private static final class EmbeddedChannelPipeline extends DefaultChannelPipeline {
        EmbeddedChannelPipeline() {
        }

        /* access modifiers changed from: protected */
        public void notifyHandlerException(ChannelEvent e, Throwable t) {
            while ((t instanceof ChannelPipelineException) && t.getCause() != null) {
                t = t.getCause();
            }
            if (t instanceof CodecEmbedderException) {
                throw ((CodecEmbedderException) t);
            }
            throw new CodecEmbedderException(t);
        }
    }

    private final class EmbeddedChannelSink implements ChannelSink, ChannelUpstreamHandler {
        static final /* synthetic */ boolean $assertionsDisabled = (!AbstractCodecEmbedder.class.desiredAssertionStatus());

        EmbeddedChannelSink() {
        }

        public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent e) {
            handleEvent(e);
        }

        public void eventSunk(ChannelPipeline pipeline, ChannelEvent e) {
            handleEvent(e);
        }

        private void handleEvent(ChannelEvent e) {
            if (e instanceof MessageEvent) {
                boolean offered = AbstractCodecEmbedder.this.productQueue.offer(((MessageEvent) e).getMessage());
                if (!$assertionsDisabled && !offered) {
                    throw new AssertionError();
                }
            } else if (e instanceof ExceptionEvent) {
                throw new CodecEmbedderException(((ExceptionEvent) e).getCause());
            }
        }

        public void exceptionCaught(ChannelPipeline pipeline, ChannelEvent e, ChannelPipelineException cause) throws Exception {
            Throwable actualCause = cause.getCause();
            if (actualCause == 0) {
                actualCause = cause;
            }
            throw new CodecEmbedderException(actualCause);
        }

        public ChannelFuture execute(ChannelPipeline pipeline, Runnable task) {
            try {
                task.run();
                return Channels.succeededFuture(pipeline.getChannel());
            } catch (Throwable t) {
                return Channels.failedFuture(pipeline.getChannel(), t);
            }
        }
    }

    protected AbstractCodecEmbedder(ChannelHandler... handlers) {
        this.sink = new EmbeddedChannelSink<>();
        this.productQueue = new LinkedList();
        this.pipeline = new EmbeddedChannelPipeline();
        configurePipeline(handlers);
        this.channel = new EmbeddedChannel(this.pipeline, this.sink);
        fireInitialEvents();
    }

    protected AbstractCodecEmbedder(ChannelBufferFactory bufferFactory, ChannelHandler... handlers) {
        this(handlers);
        getChannel().getConfig().setBufferFactory(bufferFactory);
    }

    private void fireInitialEvents() {
        Channels.fireChannelOpen(this.channel);
        Channels.fireChannelBound(this.channel, this.channel.getLocalAddress());
        Channels.fireChannelConnected(this.channel, this.channel.getRemoteAddress());
    }

    private void configurePipeline(ChannelHandler... handlers) {
        if (handlers == null) {
            throw new NullPointerException("handlers");
        } else if (handlers.length == 0) {
            throw new IllegalArgumentException("handlers should contain at least one " + ChannelHandler.class.getSimpleName() + '.');
        } else {
            for (int i = 0; i < handlers.length; i++) {
                if (handlers[i] == null) {
                    throw new NullPointerException("handlers[" + i + ']');
                }
                this.pipeline.addLast(String.valueOf(i), handlers[i]);
            }
            this.pipeline.addLast("SINK", this.sink);
        }
    }

    public boolean finish() {
        Channels.close(this.channel);
        Channels.fireChannelDisconnected(this.channel);
        Channels.fireChannelUnbound(this.channel);
        Channels.fireChannelClosed(this.channel);
        return !this.productQueue.isEmpty();
    }

    /* access modifiers changed from: protected */
    public final Channel getChannel() {
        return this.channel;
    }

    /* access modifiers changed from: protected */
    public final boolean isEmpty() {
        return this.productQueue.isEmpty();
    }

    public final E poll() {
        return this.productQueue.poll();
    }

    public final E peek() {
        return this.productQueue.peek();
    }

    public final Object[] pollAll() {
        int size = size();
        Object[] a = new Object[size];
        for (int i = 0; i < size; i++) {
            E product = poll();
            if (product == null) {
                throw new ConcurrentModificationException();
            }
            a[i] = product;
        }
        return a;
    }

    public final <T> T[] pollAll(T[] a) {
        if (a == null) {
            throw new NullPointerException("a");
        }
        int size = size();
        if (a.length < size) {
            a = (Object[]) ((Object[]) Array.newInstance(a.getClass().getComponentType(), size));
        }
        int i = 0;
        while (true) {
            T product = poll();
            if (product == null) {
                break;
            }
            a[i] = product;
            i++;
        }
        if (a.length > size) {
            a[size] = null;
        }
        return a;
    }

    public final int size() {
        return this.productQueue.size();
    }

    public ChannelPipeline getPipeline() {
        return this.pipeline;
    }
}