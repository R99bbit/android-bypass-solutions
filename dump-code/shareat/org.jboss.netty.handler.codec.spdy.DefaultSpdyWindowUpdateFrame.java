package org.jboss.netty.handler.codec.spdy;

import org.jboss.netty.util.internal.StringUtil;

public class DefaultSpdyWindowUpdateFrame implements SpdyWindowUpdateFrame {
    private int deltaWindowSize;
    private int streamId;

    public DefaultSpdyWindowUpdateFrame(int streamId2, int deltaWindowSize2) {
        setStreamId(streamId2);
        setDeltaWindowSize(deltaWindowSize2);
    }

    public int getStreamId() {
        return this.streamId;
    }

    public void setStreamId(int streamId2) {
        if (streamId2 < 0) {
            throw new IllegalArgumentException("Stream-ID cannot be negative: " + streamId2);
        }
        this.streamId = streamId2;
    }

    public int getDeltaWindowSize() {
        return this.deltaWindowSize;
    }

    public void setDeltaWindowSize(int deltaWindowSize2) {
        if (deltaWindowSize2 <= 0) {
            throw new IllegalArgumentException("Delta-Window-Size must be positive: " + deltaWindowSize2);
        }
        this.deltaWindowSize = deltaWindowSize2;
    }

    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append(getClass().getSimpleName());
        buf.append(StringUtil.NEWLINE);
        buf.append("--> Stream-ID = ");
        buf.append(getStreamId());
        buf.append(StringUtil.NEWLINE);
        buf.append("--> Delta-Window-Size = ");
        buf.append(getDeltaWindowSize());
        return buf.toString();
    }
}