package org.jboss.netty.handler.codec.spdy;

public interface SpdyPingFrame extends SpdyFrame {
    int getId();

    void setId(int i);
}