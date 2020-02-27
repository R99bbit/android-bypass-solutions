package org.jboss.netty.handler.codec.spdy;

public interface SpdyGoAwayFrame extends SpdyFrame {
    int getLastGoodStreamId();

    SpdySessionStatus getStatus();

    void setLastGoodStreamId(int i);

    void setStatus(SpdySessionStatus spdySessionStatus);
}