package org.jboss.netty.handler.codec.http.websocketx;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;

public class PingWebSocketFrame extends WebSocketFrame {
    public PingWebSocketFrame() {
        setFinalFragment(true);
        setBinaryData(ChannelBuffers.EMPTY_BUFFER);
    }

    public PingWebSocketFrame(ChannelBuffer binaryData) {
        setBinaryData(binaryData);
    }

    public PingWebSocketFrame(boolean finalFragment, int rsv, ChannelBuffer binaryData) {
        setFinalFragment(finalFragment);
        setRsv(rsv);
        setBinaryData(binaryData);
    }

    public String toString() {
        return getClass().getSimpleName() + "(data: " + getBinaryData() + ')';
    }
}