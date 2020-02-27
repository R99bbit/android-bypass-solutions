package org.jboss.netty.handler.codec.frame;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.Channels;

public class DelimiterBasedFrameDecoder extends FrameDecoder {
    private final ChannelBuffer[] delimiters;
    private boolean discardingTooLongFrame;
    private final boolean failFast;
    private final LineBasedFrameDecoder lineBasedDecoder;
    private final int maxFrameLength;
    private final boolean stripDelimiter;
    private int tooLongFrameLength;

    public DelimiterBasedFrameDecoder(int maxFrameLength2, ChannelBuffer delimiter) {
        this(maxFrameLength2, true, delimiter);
    }

    public DelimiterBasedFrameDecoder(int maxFrameLength2, boolean stripDelimiter2, ChannelBuffer delimiter) {
        this(maxFrameLength2, stripDelimiter2, false, delimiter);
    }

    public DelimiterBasedFrameDecoder(int maxFrameLength2, boolean stripDelimiter2, boolean failFast2, ChannelBuffer delimiter) {
        this(maxFrameLength2, stripDelimiter2, failFast2, delimiter.slice(delimiter.readerIndex(), delimiter.readableBytes()));
    }

    public DelimiterBasedFrameDecoder(int maxFrameLength2, ChannelBuffer... delimiters2) {
        this(maxFrameLength2, true, delimiters2);
    }

    public DelimiterBasedFrameDecoder(int maxFrameLength2, boolean stripDelimiter2, ChannelBuffer... delimiters2) {
        this(maxFrameLength2, stripDelimiter2, false, delimiters2);
    }

    public DelimiterBasedFrameDecoder(int maxFrameLength2, boolean stripDelimiter2, boolean failFast2, ChannelBuffer... delimiters2) {
        validateMaxFrameLength(maxFrameLength2);
        if (delimiters2 == null) {
            throw new NullPointerException("delimiters");
        } else if (delimiters2.length == 0) {
            throw new IllegalArgumentException("empty delimiters");
        } else {
            if (!isLineBased(delimiters2) || isSubclass()) {
                this.delimiters = new ChannelBuffer[delimiters2.length];
                for (int i = 0; i < delimiters2.length; i++) {
                    ChannelBuffer d = delimiters2[i];
                    validateDelimiter(d);
                    this.delimiters[i] = d.slice(d.readerIndex(), d.readableBytes());
                }
                this.lineBasedDecoder = null;
            } else {
                this.lineBasedDecoder = new LineBasedFrameDecoder(maxFrameLength2, stripDelimiter2, failFast2);
                this.delimiters = null;
            }
            this.maxFrameLength = maxFrameLength2;
            this.stripDelimiter = stripDelimiter2;
            this.failFast = failFast2;
        }
    }

    private static boolean isLineBased(ChannelBuffer[] delimiters2) {
        boolean z = true;
        if (delimiters2.length != 2) {
            return false;
        }
        ChannelBuffer a = delimiters2[0];
        ChannelBuffer b = delimiters2[1];
        if (a.capacity() < b.capacity()) {
            a = delimiters2[1];
            b = delimiters2[0];
        }
        if (!(a.capacity() == 2 && b.capacity() == 1 && a.getByte(0) == 13 && a.getByte(1) == 10 && b.getByte(0) == 10)) {
            z = false;
        }
        return z;
    }

    private boolean isSubclass() {
        return getClass() != DelimiterBasedFrameDecoder.class;
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        ChannelBuffer[] arr$;
        ChannelBuffer frame;
        if (this.lineBasedDecoder != null) {
            return this.lineBasedDecoder.decode(ctx, channel, buffer);
        }
        int minFrameLength = ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        ChannelBuffer minDelim = null;
        for (ChannelBuffer delim : this.delimiters) {
            int frameLength = indexOf(buffer, delim);
            if (frameLength >= 0 && frameLength < minFrameLength) {
                minFrameLength = frameLength;
                minDelim = delim;
            }
        }
        if (minDelim != null) {
            int minDelimLength = minDelim.capacity();
            if (this.discardingTooLongFrame) {
                this.discardingTooLongFrame = false;
                buffer.skipBytes(minFrameLength + minDelimLength);
                int tooLongFrameLength2 = this.tooLongFrameLength;
                this.tooLongFrameLength = 0;
                if (this.failFast) {
                    return null;
                }
                fail(ctx, (long) tooLongFrameLength2);
                return null;
            } else if (minFrameLength > this.maxFrameLength) {
                buffer.skipBytes(minFrameLength + minDelimLength);
                fail(ctx, (long) minFrameLength);
                return null;
            } else {
                if (this.stripDelimiter) {
                    frame = extractFrame(buffer, buffer.readerIndex(), minFrameLength);
                } else {
                    frame = extractFrame(buffer, buffer.readerIndex(), minFrameLength + minDelimLength);
                }
                buffer.skipBytes(minFrameLength + minDelimLength);
                return frame;
            }
        } else if (this.discardingTooLongFrame) {
            this.tooLongFrameLength += buffer.readableBytes();
            buffer.skipBytes(buffer.readableBytes());
            return null;
        } else if (buffer.readableBytes() <= this.maxFrameLength) {
            return null;
        } else {
            this.tooLongFrameLength = buffer.readableBytes();
            buffer.skipBytes(buffer.readableBytes());
            this.discardingTooLongFrame = true;
            if (!this.failFast) {
                return null;
            }
            fail(ctx, (long) this.tooLongFrameLength);
            return null;
        }
    }

    private void fail(ChannelHandlerContext ctx, long frameLength) {
        if (frameLength > 0) {
            Channels.fireExceptionCaught(ctx.getChannel(), (Throwable) new TooLongFrameException("frame length exceeds " + this.maxFrameLength + ": " + frameLength + " - discarded"));
        } else {
            Channels.fireExceptionCaught(ctx.getChannel(), (Throwable) new TooLongFrameException("frame length exceeds " + this.maxFrameLength + " - discarding"));
        }
    }

    private static int indexOf(ChannelBuffer haystack, ChannelBuffer needle) {
        for (int i = haystack.readerIndex(); i < haystack.writerIndex(); i++) {
            int haystackIndex = i;
            int needleIndex = 0;
            while (needleIndex < needle.capacity() && haystack.getByte(haystackIndex) == needle.getByte(needleIndex)) {
                haystackIndex++;
                if (haystackIndex == haystack.writerIndex() && needleIndex != needle.capacity() - 1) {
                    return -1;
                }
                needleIndex++;
            }
            if (needleIndex == needle.capacity()) {
                return i - haystack.readerIndex();
            }
        }
        return -1;
    }

    private static void validateDelimiter(ChannelBuffer delimiter) {
        if (delimiter == null) {
            throw new NullPointerException("delimiter");
        } else if (!delimiter.readable()) {
            throw new IllegalArgumentException("empty delimiter");
        }
    }

    private static void validateMaxFrameLength(int maxFrameLength2) {
        if (maxFrameLength2 <= 0) {
            throw new IllegalArgumentException("maxFrameLength must be a positive integer: " + maxFrameLength2);
        }
    }
}