package org.jboss.netty.handler.codec.http.websocketx;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.handler.codec.http.HttpChunkAggregator;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpRequestDecoder;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseEncoder;
import org.jboss.netty.util.internal.StringUtil;

public abstract class WebSocketServerHandshaker {
    public static final ChannelFutureListener HANDSHAKE_LISTENER = new ChannelFutureListener() {
        public void operationComplete(ChannelFuture future) throws Exception {
            if (!future.isSuccess()) {
                Channels.fireExceptionCaught(future.getChannel(), future.getCause());
            }
        }
    };
    public static final String SUB_PROTOCOL_WILDCARD = "*";
    private final long maxFramePayloadLength;
    private String selectedSubprotocol;
    private final String[] subprotocols;
    private final WebSocketVersion version;
    private final String webSocketUrl;

    public abstract ChannelFuture close(Channel channel, CloseWebSocketFrame closeWebSocketFrame);

    public abstract ChannelFuture handshake(Channel channel, HttpRequest httpRequest);

    protected WebSocketServerHandshaker(WebSocketVersion version2, String webSocketUrl2, String subprotocols2) {
        this(version2, webSocketUrl2, subprotocols2, Long.MAX_VALUE);
    }

    protected WebSocketServerHandshaker(WebSocketVersion version2, String webSocketUrl2, String subprotocols2, long maxFramePayloadLength2) {
        this.version = version2;
        this.webSocketUrl = webSocketUrl2;
        if (subprotocols2 != null) {
            String[] subprotocolArray = StringUtil.split(subprotocols2, ',');
            for (int i = 0; i < subprotocolArray.length; i++) {
                subprotocolArray[i] = subprotocolArray[i].trim();
            }
            this.subprotocols = subprotocolArray;
        } else {
            this.subprotocols = new String[0];
        }
        this.maxFramePayloadLength = maxFramePayloadLength2;
    }

    public String getWebSocketUrl() {
        return this.webSocketUrl;
    }

    public Set<String> getSubprotocols() {
        Set<String> ret = new LinkedHashSet<>();
        Collections.addAll(ret, this.subprotocols);
        return ret;
    }

    public WebSocketVersion getVersion() {
        return this.version;
    }

    public long getMaxFramePayloadLength() {
        return this.maxFramePayloadLength;
    }

    /* access modifiers changed from: protected */
    public ChannelFuture writeHandshakeResponse(Channel channel, HttpResponse res, ChannelHandler encoder, ChannelHandler decoder) {
        final ChannelPipeline p = channel.getPipeline();
        if (p.get(HttpChunkAggregator.class) != null) {
            p.remove(HttpChunkAggregator.class);
        }
        final String httpEncoderName = p.getContext(HttpResponseEncoder.class).getName();
        p.addAfter(httpEncoderName, "wsencoder", encoder);
        ((HttpRequestDecoder) p.get(HttpRequestDecoder.class)).replace("wsdecoder", decoder);
        ChannelFuture future = channel.write(res);
        future.addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture future) {
                p.remove(httpEncoderName);
            }
        });
        return future;
    }

    /* access modifiers changed from: protected */
    public String selectSubprotocol(String requestedSubprotocols) {
        String[] arr$;
        if (requestedSubprotocols == null || this.subprotocols.length == 0) {
            return null;
        }
        for (String p : StringUtil.split(requestedSubprotocols, ',')) {
            String requestedSubprotocol = p.trim();
            for (String supportedSubprotocol : this.subprotocols) {
                if ("*".equals(supportedSubprotocol) || requestedSubprotocol.equals(supportedSubprotocol)) {
                    return requestedSubprotocol;
                }
            }
        }
        return null;
    }

    public String getSelectedSubprotocol() {
        return this.selectedSubprotocol;
    }

    /* access modifiers changed from: protected */
    public void setSelectedSubprotocol(String value) {
        this.selectedSubprotocol = value;
    }
}