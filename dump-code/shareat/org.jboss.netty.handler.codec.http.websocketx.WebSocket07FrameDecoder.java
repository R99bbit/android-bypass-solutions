package org.jboss.netty.handler.codec.http.websocketx;

public class WebSocket07FrameDecoder extends WebSocket08FrameDecoder {
    public WebSocket07FrameDecoder(boolean maskedPayload, boolean allowExtensions, long maxFramePayloadLength) {
        super(maskedPayload, allowExtensions, maxFramePayloadLength);
    }
}