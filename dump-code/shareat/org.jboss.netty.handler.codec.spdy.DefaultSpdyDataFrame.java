package org.jboss.netty.handler.codec.spdy;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.util.internal.StringUtil;

public class DefaultSpdyDataFrame extends DefaultSpdyStreamFrame implements SpdyDataFrame {
    private ChannelBuffer data = ChannelBuffers.EMPTY_BUFFER;

    public DefaultSpdyDataFrame(int streamId) {
        super(streamId);
    }

    public ChannelBuffer getData() {
        return this.data;
    }

    public void setData(ChannelBuffer data2) {
        if (data2 == null) {
            data2 = ChannelBuffers.EMPTY_BUFFER;
        }
        if (data2.readableBytes() > 16777215) {
            throw new IllegalArgumentException("data payload cannot exceed 16777215 bytes");
        }
        this.data = data2;
    }

    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append(getClass().getSimpleName());
        buf.append("(last: ");
        buf.append(isLast());
        buf.append(')');
        buf.append(StringUtil.NEWLINE);
        buf.append("--> Stream-ID = ");
        buf.append(getStreamId());
        buf.append(StringUtil.NEWLINE);
        buf.append("--> Size = ");
        buf.append(getData().readableBytes());
        return buf.toString();
    }
}