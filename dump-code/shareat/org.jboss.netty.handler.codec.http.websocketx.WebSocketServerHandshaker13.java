package org.jboss.netty.handler.codec.http.websocketx;

import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.CharsetUtil;

public class WebSocketServerHandshaker13 extends WebSocketServerHandshaker {
    public static final String WEBSOCKET_13_ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(WebSocketServerHandshaker13.class);
    private final boolean allowExtensions;

    public WebSocketServerHandshaker13(String webSocketURL, String subprotocols, boolean allowExtensions2) {
        this(webSocketURL, subprotocols, allowExtensions2, Long.MAX_VALUE);
    }

    public WebSocketServerHandshaker13(String webSocketURL, String subprotocols, boolean allowExtensions2, long maxFramePayloadLength) {
        super(WebSocketVersion.V13, webSocketURL, subprotocols, maxFramePayloadLength);
        this.allowExtensions = allowExtensions2;
    }

    public ChannelFuture handshake(Channel channel, HttpRequest req) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Channel %s WS Version 13 server handshake", new Object[]{channel.getId()}));
        }
        HttpResponse res = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.SWITCHING_PROTOCOLS);
        String key = req.headers().get(Names.SEC_WEBSOCKET_KEY);
        if (key == null) {
            throw new WebSocketHandshakeException("not a WebSocket request: missing key");
        }
        String accept = WebSocketUtil.base64(WebSocketUtil.sha1(ChannelBuffers.copiedBuffer((CharSequence) key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", CharsetUtil.US_ASCII)));
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("WS Version 13 Server Handshake key: %s. Response: %s.", new Object[]{key, accept}));
        }
        res.setStatus(HttpResponseStatus.SWITCHING_PROTOCOLS);
        res.headers().add((String) "Upgrade", (Object) Values.WEBSOCKET.toLowerCase());
        res.headers().add((String) "Connection", (Object) "Upgrade");
        res.headers().add((String) Names.SEC_WEBSOCKET_ACCEPT, (Object) accept);
        String subprotocols = req.headers().get(Names.SEC_WEBSOCKET_PROTOCOL);
        if (subprotocols != null) {
            String selectedSubprotocol = selectSubprotocol(subprotocols);
            if (selectedSubprotocol == null) {
                throw new WebSocketHandshakeException("Requested subprotocol(s) not supported: " + subprotocols);
            }
            res.headers().add((String) Names.SEC_WEBSOCKET_PROTOCOL, (Object) selectedSubprotocol);
            setSelectedSubprotocol(selectedSubprotocol);
        }
        return writeHandshakeResponse(channel, res, new WebSocket13FrameEncoder(false), new WebSocket13FrameDecoder(true, this.allowExtensions, getMaxFramePayloadLength()));
    }

    public ChannelFuture close(Channel channel, CloseWebSocketFrame frame) {
        ChannelFuture f = channel.write(frame);
        f.addListener(ChannelFutureListener.CLOSE);
        return f;
    }
}