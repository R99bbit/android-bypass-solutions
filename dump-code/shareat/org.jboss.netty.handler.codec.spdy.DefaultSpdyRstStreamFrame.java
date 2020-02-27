package org.jboss.netty.handler.codec.spdy;

import org.jboss.netty.util.internal.StringUtil;

public class DefaultSpdyRstStreamFrame extends DefaultSpdyStreamFrame implements SpdyRstStreamFrame {
    private SpdyStreamStatus status;

    public DefaultSpdyRstStreamFrame(int streamId, int statusCode) {
        this(streamId, SpdyStreamStatus.valueOf(statusCode));
    }

    public DefaultSpdyRstStreamFrame(int streamId, SpdyStreamStatus status2) {
        super(streamId);
        setStatus(status2);
    }

    public SpdyStreamStatus getStatus() {
        return this.status;
    }

    public void setStatus(SpdyStreamStatus status2) {
        this.status = status2;
    }

    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append(getClass().getSimpleName());
        buf.append(StringUtil.NEWLINE);
        buf.append("--> Stream-ID = ");
        buf.append(getStreamId());
        buf.append(StringUtil.NEWLINE);
        buf.append("--> Status: ");
        buf.append(getStatus().toString());
        return buf.toString();
    }
}