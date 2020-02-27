package org.jboss.netty.handler.codec.spdy;

public interface SpdyWindowUpdateFrame extends SpdyFrame {
    int getDeltaWindowSize();

    int getStreamId();

    void setDeltaWindowSize(int i);

    void setStreamId(int i);
}