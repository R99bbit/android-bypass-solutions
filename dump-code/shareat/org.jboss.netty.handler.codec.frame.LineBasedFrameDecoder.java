package org.jboss.netty.handler.codec.frame;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.Channels;

public class LineBasedFrameDecoder extends FrameDecoder {
    private int discardedBytes;
    private boolean discarding;
    private final boolean failFast;
    private final int maxLength;
    private final boolean stripDelimiter;

    public LineBasedFrameDecoder(int maxLength2) {
        this(maxLength2, true, false);
    }

    public LineBasedFrameDecoder(int maxLength2, boolean stripDelimiter2, boolean failFast2) {
        this.maxLength = maxLength2;
        this.failFast = failFast2;
        this.stripDelimiter = stripDelimiter2;
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        int delimLength = 2;
        ChannelBuffer frame = null;
        int eol = findEndOfLine(buffer);
        if (!this.discarding) {
            if (eol >= 0) {
                int length = eol - buffer.readerIndex();
                if (buffer.getByte(eol) != 13) {
                    delimLength = 1;
                }
                if (length > this.maxLength) {
                    buffer.readerIndex(eol + delimLength);
                    fail(ctx, length);
                } else {
                    try {
                        if (this.stripDelimiter) {
                            frame = extractFrame(buffer, buffer.readerIndex(), length);
                        } else {
                            frame = extractFrame(buffer, buffer.readerIndex(), length + delimLength);
                        }
                    } finally {
                        buffer.skipBytes(length + delimLength);
                    }
                }
            } else {
                int length2 = buffer.readableBytes();
                if (length2 > this.maxLength) {
                    this.discardedBytes = length2;
                    buffer.readerIndex(buffer.writerIndex());
                    this.discarding = true;
                    if (this.failFast) {
                        fail(ctx, "over " + this.discardedBytes);
                    }
                }
            }
        } else if (eol >= 0) {
            int length3 = (this.discardedBytes + eol) - buffer.readerIndex();
            if (buffer.getByte(eol) != 13) {
                delimLength = 1;
            }
            buffer.readerIndex(eol + delimLength);
            this.discardedBytes = 0;
            this.discarding = false;
            if (!this.failFast) {
                fail(ctx, length3);
            }
        } else {
            this.discardedBytes = buffer.readableBytes();
            buffer.readerIndex(buffer.writerIndex());
        }
        return frame;
    }

    private void fail(ChannelHandlerContext ctx, int length) {
        fail(ctx, String.valueOf(length));
    }

    private void fail(ChannelHandlerContext ctx, String length) {
        Channels.fireExceptionCaught(ctx.getChannel(), (Throwable) new TooLongFrameException("frame length (" + length + ") exceeds the allowed maximum (" + this.maxLength + ')'));
    }

    private static int findEndOfLine(ChannelBuffer buffer) {
        int n = buffer.writerIndex();
        for (int i = buffer.readerIndex(); i < n; i++) {
            byte b = buffer.getByte(i);
            if (b == 10) {
                return i;
            }
            if (b == 13 && i < n - 1 && buffer.getByte(i + 1) == 10) {
                return i;
            }
        }
        return -1;
    }
}