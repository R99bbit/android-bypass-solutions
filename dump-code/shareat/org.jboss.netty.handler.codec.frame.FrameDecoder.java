package org.jboss.netty.handler.codec.frame;

import java.net.SocketAddress;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.buffer.CompositeChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.LifeCycleAwareChannelHandler;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;

public abstract class FrameDecoder extends SimpleChannelUpstreamHandler implements LifeCycleAwareChannelHandler {
    static final /* synthetic */ boolean $assertionsDisabled = (!FrameDecoder.class.desiredAssertionStatus());
    public static final int DEFAULT_MAX_COMPOSITEBUFFER_COMPONENTS = 1024;
    private int copyThreshold;
    private volatile ChannelHandlerContext ctx;
    protected ChannelBuffer cumulation;
    private int maxCumulationBufferComponents;
    private boolean unfold;

    /* access modifiers changed from: protected */
    public abstract Object decode(ChannelHandlerContext channelHandlerContext, Channel channel, ChannelBuffer channelBuffer) throws Exception;

    protected FrameDecoder() {
        this(false);
    }

    protected FrameDecoder(boolean unfold2) {
        this.maxCumulationBufferComponents = 1024;
        this.unfold = unfold2;
    }

    public final boolean isUnfold() {
        return this.unfold;
    }

    public final void setUnfold(boolean unfold2) {
        if (this.ctx == null) {
            this.unfold = unfold2;
            return;
        }
        throw new IllegalStateException("decoder properties cannot be changed once the decoder is added to a pipeline.");
    }

    public final int getMaxCumulationBufferCapacity() {
        return this.copyThreshold;
    }

    public final void setMaxCumulationBufferCapacity(int copyThreshold2) {
        if (copyThreshold2 < 0) {
            throw new IllegalArgumentException("maxCumulationBufferCapacity must be >= 0");
        } else if (this.ctx == null) {
            this.copyThreshold = copyThreshold2;
        } else {
            throw new IllegalStateException("decoder properties cannot be changed once the decoder is added to a pipeline.");
        }
    }

    public final int getMaxCumulationBufferComponents() {
        return this.maxCumulationBufferComponents;
    }

    public final void setMaxCumulationBufferComponents(int maxCumulationBufferComponents2) {
        if (maxCumulationBufferComponents2 < 2) {
            throw new IllegalArgumentException("maxCumulationBufferComponents: " + maxCumulationBufferComponents2 + " (expected: >= 2)");
        } else if (this.ctx == null) {
            this.maxCumulationBufferComponents = maxCumulationBufferComponents2;
        } else {
            throw new IllegalStateException("decoder properties cannot be changed once the decoder is added to a pipeline.");
        }
    }

    public void messageReceived(ChannelHandlerContext ctx2, MessageEvent e) throws Exception {
        Object m = e.getMessage();
        if (!(m instanceof ChannelBuffer)) {
            ctx2.sendUpstream(e);
            return;
        }
        ChannelBuffer input = (ChannelBuffer) m;
        if (!input.readable()) {
            return;
        }
        if (this.cumulation == null) {
            try {
                callDecode(ctx2, e.getChannel(), input, e.getRemoteAddress());
            } finally {
                updateCumulation(ctx2, input);
            }
        } else {
            ChannelBuffer input2 = appendToCumulation(input);
            try {
                callDecode(ctx2, e.getChannel(), input2, e.getRemoteAddress());
            } finally {
                updateCumulation(ctx2, input2);
            }
        }
    }

    /* access modifiers changed from: protected */
    public ChannelBuffer appendToCumulation(ChannelBuffer input) {
        ChannelBuffer cumulation2 = this.cumulation;
        if ($assertionsDisabled || cumulation2.readable()) {
            if (cumulation2 instanceof CompositeChannelBuffer) {
                CompositeChannelBuffer composite = (CompositeChannelBuffer) cumulation2;
                if (composite.numComponents() >= this.maxCumulationBufferComponents) {
                    cumulation2 = composite.copy();
                }
            }
            ChannelBuffer input2 = ChannelBuffers.wrappedBuffer(cumulation2, input);
            this.cumulation = input2;
            return input2;
        }
        throw new AssertionError();
    }

    /* access modifiers changed from: protected */
    public ChannelBuffer updateCumulation(ChannelHandlerContext ctx2, ChannelBuffer input) {
        int readableBytes = input.readableBytes();
        if (readableBytes > 0) {
            int inputCapacity = input.capacity();
            if (readableBytes < inputCapacity && inputCapacity > this.copyThreshold) {
                ChannelBuffer newCumulation = newCumulationBuffer(ctx2, input.readableBytes());
                this.cumulation = newCumulation;
                this.cumulation.writeBytes(input);
                return newCumulation;
            } else if (input.readerIndex() != 0) {
                ChannelBuffer newCumulation2 = input.slice();
                this.cumulation = newCumulation2;
                return newCumulation2;
            } else {
                ChannelBuffer newCumulation3 = input;
                this.cumulation = input;
                return newCumulation3;
            }
        } else {
            this.cumulation = null;
            return null;
        }
    }

    public void channelDisconnected(ChannelHandlerContext ctx2, ChannelStateEvent e) throws Exception {
        cleanup(ctx2, e);
    }

    public void channelClosed(ChannelHandlerContext ctx2, ChannelStateEvent e) throws Exception {
        cleanup(ctx2, e);
    }

    public void exceptionCaught(ChannelHandlerContext ctx2, ExceptionEvent e) throws Exception {
        ctx2.sendUpstream(e);
    }

    /* access modifiers changed from: protected */
    public Object decodeLast(ChannelHandlerContext ctx2, Channel channel, ChannelBuffer buffer) throws Exception {
        return decode(ctx2, channel, buffer);
    }

    private void callDecode(ChannelHandlerContext context, Channel channel, ChannelBuffer cumulation2, SocketAddress remoteAddress) throws Exception {
        while (cumulation2.readable()) {
            int oldReaderIndex = cumulation2.readerIndex();
            Object frame = decode(context, channel, cumulation2);
            if (frame == null) {
                if (oldReaderIndex == cumulation2.readerIndex()) {
                    return;
                }
            } else if (oldReaderIndex == cumulation2.readerIndex()) {
                throw new IllegalStateException("decode() method must read at least one byte if it returned a frame (caused by: " + getClass() + ')');
            } else {
                unfoldAndFireMessageReceived(context, remoteAddress, frame);
            }
        }
    }

    /* access modifiers changed from: protected */
    public final void unfoldAndFireMessageReceived(ChannelHandlerContext context, SocketAddress remoteAddress, Object result) {
        if (!this.unfold) {
            Channels.fireMessageReceived(context, result, remoteAddress);
        } else if (result instanceof Object[]) {
            for (Object r : (Object[]) result) {
                Channels.fireMessageReceived(context, r, remoteAddress);
            }
        } else if (result instanceof Iterable) {
            for (Object r2 : (Iterable) result) {
                Channels.fireMessageReceived(context, r2, remoteAddress);
            }
        } else {
            Channels.fireMessageReceived(context, result, remoteAddress);
        }
    }

    /* access modifiers changed from: protected */
    public void cleanup(ChannelHandlerContext ctx2, ChannelStateEvent e) throws Exception {
        try {
            ChannelBuffer cumulation2 = this.cumulation;
            if (cumulation2 != null) {
                this.cumulation = null;
                if (cumulation2.readable()) {
                    callDecode(ctx2, ctx2.getChannel(), cumulation2, null);
                }
                Object partialFrame = decodeLast(ctx2, ctx2.getChannel(), cumulation2);
                if (partialFrame != null) {
                    unfoldAndFireMessageReceived(ctx2, null, partialFrame);
                }
                ctx2.sendUpstream(e);
            }
        } finally {
            ctx2.sendUpstream(e);
        }
    }

    /* access modifiers changed from: protected */
    public ChannelBuffer newCumulationBuffer(ChannelHandlerContext ctx2, int minimumCapacity) {
        return ctx2.getChannel().getConfig().getBufferFactory().getBuffer(Math.max(minimumCapacity, 256));
    }

    public void replace(String handlerName, ChannelHandler handler) {
        if (this.ctx == null) {
            throw new IllegalStateException("Replace cann only be called once the FrameDecoder is added to the ChannelPipeline");
        }
        ChannelPipeline pipeline = this.ctx.getPipeline();
        pipeline.addAfter(this.ctx.getName(), handlerName, handler);
        try {
            if (this.cumulation != null) {
                Channels.fireMessageReceived(this.ctx, (Object) this.cumulation.readBytes(actualReadableBytes()));
            }
        } finally {
            pipeline.remove((ChannelHandler) this);
        }
    }

    /* access modifiers changed from: protected */
    public int actualReadableBytes() {
        return internalBuffer().readableBytes();
    }

    /* access modifiers changed from: protected */
    public ChannelBuffer internalBuffer() {
        ChannelBuffer buf = this.cumulation;
        if (buf == null) {
            return ChannelBuffers.EMPTY_BUFFER;
        }
        return buf;
    }

    /* access modifiers changed from: protected */
    public ChannelBuffer extractFrame(ChannelBuffer buffer, int index, int length) {
        ChannelBuffer frame = buffer.factory().getBuffer(length);
        frame.writeBytes(buffer, index, length);
        return frame;
    }

    public void beforeAdd(ChannelHandlerContext ctx2) throws Exception {
        this.ctx = ctx2;
    }

    public void afterAdd(ChannelHandlerContext ctx2) throws Exception {
    }

    public void beforeRemove(ChannelHandlerContext ctx2) throws Exception {
    }

    public void afterRemove(ChannelHandlerContext ctx2) throws Exception {
    }
}