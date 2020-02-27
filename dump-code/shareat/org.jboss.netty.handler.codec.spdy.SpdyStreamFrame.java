package org.jboss.netty.handler.codec.spdy;

public interface SpdyStreamFrame extends SpdyFrame {
    int getStreamId();

    boolean isLast();

    void setLast(boolean z);

    void setStreamId(int i);
}