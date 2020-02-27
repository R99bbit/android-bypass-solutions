package org.jboss.netty.handler.codec.http.websocketx;

public class WebSocket13FrameDecoder extends WebSocket08FrameDecoder {
    public WebSocket13FrameDecoder(boolean maskedPayload, boolean allowExtensions) {
        this(maskedPayload, allowExtensions, Long.MAX_VALUE);
    }

    public WebSocket13FrameDecoder(boolean maskedPayload, boolean allowExtensions, long maxFramePayloadLength) {
        super(maskedPayload, allowExtensions, maxFramePayloadLength);
    }
}