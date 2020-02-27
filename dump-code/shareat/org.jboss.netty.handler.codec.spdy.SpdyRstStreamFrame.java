package org.jboss.netty.handler.codec.spdy;

public interface SpdyRstStreamFrame extends SpdyStreamFrame {
    SpdyStreamStatus getStatus();

    void setStatus(SpdyStreamStatus spdyStreamStatus);
}