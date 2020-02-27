package org.jboss.netty.handler.codec.frame;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.Channels;

public class LengthFieldBasedFrameDecoder extends FrameDecoder {
    private long bytesToDiscard;
    private boolean discardingTooLongFrame;
    private final boolean failFast;
    private final int initialBytesToStrip;
    private final int lengthAdjustment;
    private final int lengthFieldEndOffset;
    private final int lengthFieldLength;
    private final int lengthFieldOffset;
    private final int maxFrameLength;
    private long tooLongFrameLength;

    public LengthFieldBasedFrameDecoder(int maxFrameLength2, int lengthFieldOffset2, int lengthFieldLength2) {
        this(maxFrameLength2, lengthFieldOffset2, lengthFieldLength2, 0, 0);
    }

    public LengthFieldBasedFrameDecoder(int maxFrameLength2, int lengthFieldOffset2, int lengthFieldLength2, int lengthAdjustment2, int initialBytesToStrip2) {
        this(maxFrameLength2, lengthFieldOffset2, lengthFieldLength2, lengthAdjustment2, initialBytesToStrip2, false);
    }

    public LengthFieldBasedFrameDecoder(int maxFrameLength2, int lengthFieldOffset2, int lengthFieldLength2, int lengthAdjustment2, int initialBytesToStrip2, boolean failFast2) {
        if (maxFrameLength2 <= 0) {
            throw new IllegalArgumentException("maxFrameLength must be a positive integer: " + maxFrameLength2);
        } else if (lengthFieldOffset2 < 0) {
            throw new IllegalArgumentException("lengthFieldOffset must be a non-negative integer: " + lengthFieldOffset2);
        } else if (initialBytesToStrip2 < 0) {
            throw new IllegalArgumentException("initialBytesToStrip must be a non-negative integer: " + initialBytesToStrip2);
        } else if (lengthFieldLength2 != 1 && lengthFieldLength2 != 2 && lengthFieldLength2 != 3 && lengthFieldLength2 != 4 && lengthFieldLength2 != 8) {
            throw new IllegalArgumentException("lengthFieldLength must be either 1, 2, 3, 4, or 8: " + lengthFieldLength2);
        } else if (lengthFieldOffset2 > maxFrameLength2 - lengthFieldLength2) {
            throw new IllegalArgumentException("maxFrameLength (" + maxFrameLength2 + ") " + "must be equal to or greater than " + "lengthFieldOffset (" + lengthFieldOffset2 + ") + " + "lengthFieldLength (" + lengthFieldLength2 + ").");
        } else {
            this.maxFrameLength = maxFrameLength2;
            this.lengthFieldOffset = lengthFieldOffset2;
            this.lengthFieldLength = lengthFieldLength2;
            this.lengthAdjustment = lengthAdjustment2;
            this.lengthFieldEndOffset = lengthFieldOffset2 + lengthFieldLength2;
            this.initialBytesToStrip = initialBytesToStrip2;
            this.failFast = failFast2;
        }
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        long frameLength;
        if (this.discardingTooLongFrame) {
            long bytesToDiscard2 = this.bytesToDiscard;
            int localBytesToDiscard = (int) Math.min(bytesToDiscard2, (long) buffer.readableBytes());
            buffer.skipBytes(localBytesToDiscard);
            this.bytesToDiscard = bytesToDiscard2 - ((long) localBytesToDiscard);
            failIfNecessary(ctx, false);
            return null;
        } else if (buffer.readableBytes() < this.lengthFieldEndOffset) {
            return null;
        } else {
            int actualLengthFieldOffset = buffer.readerIndex() + this.lengthFieldOffset;
            switch (this.lengthFieldLength) {
                case 1:
                    frameLength = (long) buffer.getUnsignedByte(actualLengthFieldOffset);
                    break;
                case 2:
                    frameLength = (long) buffer.getUnsignedShort(actualLengthFieldOffset);
                    break;
                case 3:
                    frameLength = (long) buffer.getUnsignedMedium(actualLengthFieldOffset);
                    break;
                case 4:
                    frameLength = buffer.getUnsignedInt(actualLengthFieldOffset);
                    break;
                case 8:
                    frameLength = buffer.getLong(actualLengthFieldOffset);
                    break;
                default:
                    throw new Error("should not reach here");
            }
            if (frameLength < 0) {
                buffer.skipBytes(this.lengthFieldEndOffset);
                throw new CorruptedFrameException("negative pre-adjustment length field: " + frameLength);
            }
            long frameLength2 = frameLength + ((long) (this.lengthAdjustment + this.lengthFieldEndOffset));
            if (frameLength2 < ((long) this.lengthFieldEndOffset)) {
                buffer.skipBytes(this.lengthFieldEndOffset);
                throw new CorruptedFrameException("Adjusted frame length (" + frameLength2 + ") is less " + "than lengthFieldEndOffset: " + this.lengthFieldEndOffset);
            } else if (frameLength2 > ((long) this.maxFrameLength)) {
                this.discardingTooLongFrame = true;
                this.tooLongFrameLength = frameLength2;
                this.bytesToDiscard = frameLength2 - ((long) buffer.readableBytes());
                buffer.skipBytes(buffer.readableBytes());
                failIfNecessary(ctx, true);
                return null;
            } else {
                int frameLengthInt = (int) frameLength2;
                if (buffer.readableBytes() < frameLengthInt) {
                    return null;
                }
                if (this.initialBytesToStrip > frameLengthInt) {
                    buffer.skipBytes(frameLengthInt);
                    throw new CorruptedFrameException("Adjusted frame length (" + frameLength2 + ") is less " + "than initialBytesToStrip: " + this.initialBytesToStrip);
                }
                buffer.skipBytes(this.initialBytesToStrip);
                int readerIndex = buffer.readerIndex();
                int actualFrameLength = frameLengthInt - this.initialBytesToStrip;
                ChannelBuffer extractFrame = extractFrame(buffer, readerIndex, actualFrameLength);
                buffer.readerIndex(readerIndex + actualFrameLength);
                return extractFrame;
            }
        }
    }

    private void failIfNecessary(ChannelHandlerContext ctx, boolean firstDetectionOfTooLongFrame) {
        if (this.bytesToDiscard == 0) {
            long tooLongFrameLength2 = this.tooLongFrameLength;
            this.tooLongFrameLength = 0;
            this.discardingTooLongFrame = false;
            if (!this.failFast || (this.failFast && firstDetectionOfTooLongFrame)) {
                fail(ctx, tooLongFrameLength2);
            }
        } else if (this.failFast && firstDetectionOfTooLongFrame) {
            fail(ctx, this.tooLongFrameLength);
        }
    }

    private void fail(ChannelHandlerContext ctx, long frameLength) {
        if (frameLength > 0) {
            Channels.fireExceptionCaught(ctx.getChannel(), (Throwable) new TooLongFrameException("Adjusted frame length exceeds " + this.maxFrameLength + ": " + frameLength + " - discarded"));
        } else {
            Channels.fireExceptionCaught(ctx.getChannel(), (Throwable) new TooLongFrameException("Adjusted frame length exceeds " + this.maxFrameLength + " - discarding"));
        }
    }
}