package org.jboss.netty.handler.codec.http.websocketx;

import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.handler.ssl.SslHandler;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

public class WebSocketServerProtocolHandshakeHandler extends SimpleChannelUpstreamHandler {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(WebSocketServerProtocolHandshakeHandler.class);
    private final boolean allowExtensions;
    private final String subprotocols;
    private final String websocketPath;

    public WebSocketServerProtocolHandshakeHandler(String websocketPath2, String subprotocols2, boolean allowExtensions2) {
        this.websocketPath = websocketPath2;
        this.subprotocols = subprotocols2;
        this.allowExtensions = allowExtensions2;
    }

    public void messageReceived(final ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        if (e.getMessage() instanceof HttpRequest) {
            HttpRequest req = (HttpRequest) e.getMessage();
            if (req.getMethod() != HttpMethod.GET) {
                sendHttpResponse(ctx, req, new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN));
                return;
            }
            WebSocketServerHandshakerFactory wsFactory = new WebSocketServerHandshakerFactory(getWebSocketLocation(ctx.getPipeline(), req, this.websocketPath), this.subprotocols, this.allowExtensions);
            WebSocketServerHandshaker handshaker = wsFactory.newHandshaker(req);
            if (handshaker == null) {
                wsFactory.sendUnsupportedWebSocketVersionResponse(ctx.getChannel());
                return;
            }
            handshaker.handshake(ctx.getChannel(), req).addListener(new ChannelFutureListener() {
                public void operationComplete(ChannelFuture future) throws Exception {
                    if (!future.isSuccess()) {
                        Channels.fireExceptionCaught(ctx, future.getCause());
                    }
                }
            });
            WebSocketServerProtocolHandler.setHandshaker(ctx, handshaker);
            ctx.getPipeline().replace((ChannelHandler) this, (String) "WS403Responder", WebSocketServerProtocolHandler.forbiddenHttpRequestResponder());
        }
    }

    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        logger.error("Exception Caught", cause);
        ctx.getChannel().close();
    }

    private static void sendHttpResponse(ChannelHandlerContext ctx, HttpRequest req, HttpResponse res) {
        ChannelFuture f = ctx.getChannel().write(res);
        if (!HttpHeaders.isKeepAlive(req) || res.getStatus().getCode() != 200) {
            f.addListener(ChannelFutureListener.CLOSE);
        }
    }

    private static String getWebSocketLocation(ChannelPipeline cp, HttpRequest req, String path) {
        String protocol = "ws";
        if (cp.get(SslHandler.class) != null) {
            protocol = "wss";
        }
        return protocol + "://" + req.headers().get("Host") + path;
    }
}