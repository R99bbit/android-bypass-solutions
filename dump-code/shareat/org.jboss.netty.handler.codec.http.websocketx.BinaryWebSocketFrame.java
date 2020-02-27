package org.jboss.netty.handler.codec.http.websocketx;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;

public class BinaryWebSocketFrame extends WebSocketFrame {
    public BinaryWebSocketFrame() {
        setBinaryData(ChannelBuffers.EMPTY_BUFFER);
    }

    public BinaryWebSocketFrame(ChannelBuffer binaryData) {
        setBinaryData(binaryData);
    }

    public BinaryWebSocketFrame(boolean finalFragment, int rsv, ChannelBuffer binaryData) {
        setFinalFragment(finalFragment);
        setRsv(rsv);
        setBinaryData(binaryData);
    }

    public String toString() {
        return getClass().getSimpleName() + "(data: " + getBinaryData() + ')';
    }
}