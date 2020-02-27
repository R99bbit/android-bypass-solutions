package org.jboss.netty.handler.codec.spdy;

public abstract class DefaultSpdyStreamFrame implements SpdyStreamFrame {
    private boolean last;
    private int streamId;

    protected DefaultSpdyStreamFrame(int streamId2) {
        setStreamId(streamId2);
    }

    public int getStreamId() {
        return this.streamId;
    }

    public void setStreamId(int streamId2) {
        if (streamId2 <= 0) {
            throw new IllegalArgumentException("Stream-ID must be positive: " + streamId2);
        }
        this.streamId = streamId2;
    }

    public boolean isLast() {
        return this.last;
    }

    public void setLast(boolean last2) {
        this.last = last2;
    }
}