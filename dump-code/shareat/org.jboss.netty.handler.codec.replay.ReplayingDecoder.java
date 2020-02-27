package org.jboss.netty.handler.codec.replay;

import java.lang.Enum;
import java.net.SocketAddress;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.handler.codec.frame.FrameDecoder;

public abstract class ReplayingDecoder<T extends Enum<T>> extends FrameDecoder {
    private int checkpoint;
    private boolean needsCleanup;
    private final ReplayingDecoderBuffer replayable;
    private T state;

    /* access modifiers changed from: protected */
    public abstract Object decode(ChannelHandlerContext channelHandlerContext, Channel channel, ChannelBuffer channelBuffer, T t) throws Exception;

    protected ReplayingDecoder() {
        this((T) null);
    }

    protected ReplayingDecoder(boolean unfold) {
        this(null, unfold);
    }

    protected ReplayingDecoder(T initialState) {
        this(initialState, false);
    }

    protected ReplayingDecoder(T initialState, boolean unfold) {
        super(unfold);
        this.replayable = new ReplayingDecoderBuffer(this);
        this.state = initialState;
    }

    /* access modifiers changed from: protected */
    public ChannelBuffer internalBuffer() {
        return super.internalBuffer();
    }

    /* access modifiers changed from: protected */
    public void checkpoint() {
        ChannelBuffer cumulation = this.cumulation;
        if (cumulation != null) {
            this.checkpoint = cumulation.readerIndex();
        } else {
            this.checkpoint = -1;
        }
    }

    /* access modifiers changed from: protected */
    public void checkpoint(T state2) {
        checkpoint();
        setState(state2);
    }

    /* access modifiers changed from: protected */
    public T getState() {
        return this.state;
    }

    /* access modifiers changed from: protected */
    public T setState(T newState) {
        T oldState = this.state;
        this.state = newState;
        return oldState;
    }

    /* access modifiers changed from: protected */
    public Object decodeLast(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer, T state2) throws Exception {
        return decode(ctx, channel, buffer, state2);
    }

    /* access modifiers changed from: protected */
    public final Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        return decode(ctx, channel, buffer, this.state);
    }

    /* access modifiers changed from: protected */
    public final Object decodeLast(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        return decodeLast(ctx, channel, buffer, this.state);
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=org.jboss.netty.handler.codec.replay.ReplayingDecoder, code=org.jboss.netty.buffer.ChannelBuffer, for r14v0, types: [org.jboss.netty.handler.codec.replay.ReplayingDecoder] */
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        ChannelBuffer cumulation;
        Object m = e.getMessage();
        if (!(m instanceof ChannelBuffer)) {
            ctx.sendUpstream(e);
            return;
        }
        ChannelBuffer input = (ChannelBuffer) m;
        if (input.readable()) {
            this.needsCleanup = true;
            if (this.cumulation == null) {
                this.cumulation = input;
                int oldReaderIndex = input.readerIndex();
                int inputSize = input.readableBytes();
                try {
                    callDecode(ctx, e.getChannel(), input, this.replayable, e.getRemoteAddress());
                    int readableBytes = input.readableBytes();
                    if (readableBytes > 0) {
                        int inputCapacity = input.capacity();
                        boolean copy = readableBytes != inputCapacity && inputCapacity > getMaxCumulationBufferCapacity();
                        if (this.checkpoint > 0) {
                            int bytesToPreserve = inputSize - (this.checkpoint - oldReaderIndex);
                            if (copy) {
                                ChannelBuffer cumulation2 = newCumulationBuffer(ctx, bytesToPreserve);
                                this.cumulation = cumulation2;
                                cumulation2.writeBytes(input, this.checkpoint, bytesToPreserve);
                                return;
                            }
                            this.cumulation = input.slice(this.checkpoint, bytesToPreserve);
                        } else if (this.checkpoint == 0) {
                            if (copy) {
                                ChannelBuffer cumulation3 = newCumulationBuffer(ctx, inputSize);
                                this.cumulation = cumulation3;
                                cumulation3.writeBytes(input, oldReaderIndex, inputSize);
                                cumulation3.readerIndex(input.readerIndex());
                                return;
                            }
                            ChannelBuffer cumulation4 = input.slice(oldReaderIndex, inputSize);
                            this.cumulation = cumulation4;
                            cumulation4.readerIndex(input.readerIndex());
                        } else if (copy) {
                            this.cumulation = cumulation;
                            cumulation.writeBytes(input);
                        } else {
                            this.cumulation = input;
                        }
                    } else {
                        this.cumulation = null;
                    }
                } finally {
                    cumulation = input.readableBytes();
                    if (cumulation > 0) {
                        int inputCapacity2 = input.capacity();
                        boolean copy2 = cumulation != inputCapacity2 && inputCapacity2 > getMaxCumulationBufferCapacity();
                        if (this.checkpoint > 0) {
                            int bytesToPreserve2 = inputSize - (this.checkpoint - oldReaderIndex);
                            if (copy2) {
                                ChannelBuffer cumulation5 = newCumulationBuffer(ctx, bytesToPreserve2);
                                this.cumulation = cumulation5;
                                cumulation5.writeBytes(input, this.checkpoint, bytesToPreserve2);
                            } else {
                                this.cumulation = input.slice(this.checkpoint, bytesToPreserve2);
                            }
                        } else if (this.checkpoint == 0) {
                            if (copy2) {
                                ChannelBuffer cumulation6 = newCumulationBuffer(ctx, inputSize);
                                this.cumulation = cumulation6;
                                cumulation6.writeBytes(input, oldReaderIndex, inputSize);
                                cumulation6.readerIndex(input.readerIndex());
                            } else {
                                ChannelBuffer cumulation7 = input.slice(oldReaderIndex, inputSize);
                                this.cumulation = cumulation7;
                                cumulation7.readerIndex(input.readerIndex());
                            }
                        } else if (copy2) {
                            ChannelBuffer cumulation8 = newCumulationBuffer(ctx, input.readableBytes());
                            this.cumulation = cumulation8;
                            cumulation8.writeBytes(input);
                        } else {
                            this.cumulation = input;
                        }
                    } else {
                        this.cumulation = null;
                    }
                }
            } else {
                ChannelBuffer input2 = appendToCumulation(input);
                try {
                    callDecode(ctx, e.getChannel(), input2, this.replayable, e.getRemoteAddress());
                } finally {
                    updateCumulation(ctx, input2);
                }
            }
        }
    }

    private void callDecode(ChannelHandlerContext context, Channel channel, ChannelBuffer input, ChannelBuffer replayableInput, SocketAddress remoteAddress) throws Exception {
        while (input.readable()) {
            int oldReaderIndex = input.readerIndex();
            this.checkpoint = oldReaderIndex;
            Object result = null;
            T oldState = this.state;
            try {
                result = decode(context, channel, replayableInput, this.state);
                if (result == null) {
                    if (oldReaderIndex == input.readerIndex() && oldState == this.state) {
                        throw new IllegalStateException("null cannot be returned if no data is consumed and state didn't change.");
                    }
                }
            } catch (ReplayError e) {
                int checkpoint2 = this.checkpoint;
                if (checkpoint2 >= 0) {
                    input.readerIndex(checkpoint2);
                }
            }
            if (result != null) {
                if (oldReaderIndex == input.readerIndex() && oldState == this.state) {
                    throw new IllegalStateException("decode() method must consume at least one byte if it returned a decoded message (caused by: " + getClass() + ')');
                }
                unfoldAndFireMessageReceived(context, remoteAddress, result);
            } else {
                return;
            }
        }
    }

    /* access modifiers changed from: protected */
    public void cleanup(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        try {
            ChannelBuffer cumulation = this.cumulation;
            if (this.needsCleanup) {
                this.needsCleanup = false;
                this.replayable.terminate();
                if (cumulation != null && cumulation.readable()) {
                    callDecode(ctx, e.getChannel(), cumulation, this.replayable, null);
                }
                Object partiallyDecoded = decodeLast(ctx, e.getChannel(), this.replayable, this.state);
                this.cumulation = null;
                if (partiallyDecoded != null) {
                    unfoldAndFireMessageReceived(ctx, null, partiallyDecoded);
                }
            }
        } catch (ReplayError e2) {
        } catch (Throwable th) {
            ctx.sendUpstream(e);
            throw th;
        }
        ctx.sendUpstream(e);
    }
}