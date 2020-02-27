package org.jboss.netty.handler.codec.http.websocketx;

import java.net.URI;
import java.util.Map;

public class WebSocketClientHandshakerFactory {
    public WebSocketClientHandshaker newHandshaker(URI webSocketURL, WebSocketVersion version, String subprotocol, boolean allowExtensions, Map<String, String> customHeaders) {
        return newHandshaker(webSocketURL, version, subprotocol, allowExtensions, customHeaders, Long.MAX_VALUE);
    }

    public WebSocketClientHandshaker newHandshaker(URI webSocketURL, WebSocketVersion version, String subprotocol, boolean allowExtensions, Map<String, String> customHeaders, long maxFramePayloadLength) {
        if (version == WebSocketVersion.V13) {
            return new WebSocketClientHandshaker13(webSocketURL, WebSocketVersion.V13, subprotocol, allowExtensions, customHeaders, maxFramePayloadLength);
        } else if (version == WebSocketVersion.V08) {
            return new WebSocketClientHandshaker08(webSocketURL, WebSocketVersion.V08, subprotocol, allowExtensions, customHeaders, maxFramePayloadLength);
        } else if (version == WebSocketVersion.V07) {
            return new WebSocketClientHandshaker07(webSocketURL, WebSocketVersion.V07, subprotocol, allowExtensions, customHeaders, maxFramePayloadLength);
        } else if (version == WebSocketVersion.V00) {
            return new WebSocketClientHandshaker00(webSocketURL, WebSocketVersion.V00, subprotocol, customHeaders, maxFramePayloadLength);
        } else {
            throw new WebSocketHandshakeException("Protocol version " + version.toString() + " not supported.");
        }
    }
}