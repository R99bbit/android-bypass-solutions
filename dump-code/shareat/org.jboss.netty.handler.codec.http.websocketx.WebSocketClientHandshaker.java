package org.jboss.netty.handler.codec.http.websocketx;

import java.net.URI;
import java.util.Map;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.handler.codec.http.HttpResponse;

public abstract class WebSocketClientHandshaker {
    private volatile String actualSubprotocol;
    protected final Map<String, String> customHeaders;
    private final String expectedSubprotocol;
    private volatile boolean handshakeComplete;
    private final long maxFramePayloadLength;
    private final WebSocketVersion version;
    private final URI webSocketUrl;

    public abstract void finishHandshake(Channel channel, HttpResponse httpResponse);

    public abstract ChannelFuture handshake(Channel channel) throws Exception;

    protected WebSocketClientHandshaker(URI webSocketUrl2, WebSocketVersion version2, String subprotocol, Map<String, String> customHeaders2) {
        this(webSocketUrl2, version2, subprotocol, customHeaders2, Long.MAX_VALUE);
    }

    protected WebSocketClientHandshaker(URI webSocketUrl2, WebSocketVersion version2, String subprotocol, Map<String, String> customHeaders2, long maxFramePayloadLength2) {
        this.webSocketUrl = webSocketUrl2;
        this.version = version2;
        this.expectedSubprotocol = subprotocol;
        this.customHeaders = customHeaders2;
        this.maxFramePayloadLength = maxFramePayloadLength2;
    }

    public URI getWebSocketUrl() {
        return this.webSocketUrl;
    }

    public WebSocketVersion getVersion() {
        return this.version;
    }

    public long getMaxFramePayloadLength() {
        return this.maxFramePayloadLength;
    }

    public boolean isHandshakeComplete() {
        return this.handshakeComplete;
    }

    /* access modifiers changed from: protected */
    public void setHandshakeComplete() {
        this.handshakeComplete = true;
    }

    public String getExpectedSubprotocol() {
        return this.expectedSubprotocol;
    }

    public String getActualSubprotocol() {
        return this.actualSubprotocol;
    }

    /* access modifiers changed from: protected */
    public void setActualSubprotocol(String actualSubprotocol2) {
        this.actualSubprotocol = actualSubprotocol2;
    }
}