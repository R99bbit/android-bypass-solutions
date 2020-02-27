package org.jboss.netty.handler.codec.spdy;

public interface SpdySynStreamFrame extends SpdyHeadersFrame {
    int getAssociatedToStreamId();

    byte getPriority();

    boolean isUnidirectional();

    void setAssociatedToStreamId(int i);

    void setPriority(byte b);

    void setUnidirectional(boolean z);
}