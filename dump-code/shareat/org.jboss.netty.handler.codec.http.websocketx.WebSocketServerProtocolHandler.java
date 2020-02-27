package org.jboss.netty.handler.codec.http.websocketx;

import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.LifeCycleAwareChannelHandler;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;

public class WebSocketServerProtocolHandler extends SimpleChannelUpstreamHandler implements LifeCycleAwareChannelHandler {
    private final boolean allowExtensions;
    private final String subprotocols;
    private final String websocketPath;

    public WebSocketServerProtocolHandler(String websocketPath2) {
        this(websocketPath2, null, false);
    }

    public WebSocketServerProtocolHandler(String websocketPath2, String subprotocols2) {
        this(websocketPath2, subprotocols2, false);
    }

    public WebSocketServerProtocolHandler(String websocketPath2, String subprotocols2, boolean allowExtensions2) {
        this.websocketPath = websocketPath2;
        this.subprotocols = subprotocols2;
        this.allowExtensions = allowExtensions2;
    }

    public void afterAdd(ChannelHandlerContext ctx) throws Exception {
        if (ctx.getPipeline().get(WebSocketServerProtocolHandshakeHandler.class) == null) {
            ctx.getPipeline().addBefore(ctx.getName(), WebSocketServerProtocolHandshakeHandler.class.getName(), new WebSocketServerProtocolHandshakeHandler(this.websocketPath, this.subprotocols, this.allowExtensions));
        }
    }

    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        if (e.getMessage() instanceof WebSocketFrame) {
            WebSocketFrame frame = (WebSocketFrame) e.getMessage();
            if (frame instanceof CloseWebSocketFrame) {
                getHandshaker(ctx).close(ctx.getChannel(), (CloseWebSocketFrame) frame);
                return;
            } else if (frame instanceof PingWebSocketFrame) {
                ctx.getChannel().write(new PongWebSocketFrame(frame.getBinaryData()));
                return;
            }
        }
        ctx.sendUpstream(e);
    }

    public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
        if (e.getCause() instanceof WebSocketHandshakeException) {
            DefaultHttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.BAD_REQUEST);
            response.setContent(ChannelBuffers.wrappedBuffer(e.getCause().getMessage().getBytes()));
            ctx.getChannel().write(response).addListener(ChannelFutureListener.CLOSE);
            return;
        }
        ctx.getChannel().close();
    }

    static WebSocketServerHandshaker getHandshaker(ChannelHandlerContext ctx) {
        return (WebSocketServerHandshaker) ctx.getAttachment();
    }

    static void setHandshaker(ChannelHandlerContext ctx, WebSocketServerHandshaker handshaker) {
        ctx.setAttachment(handshaker);
    }

    static ChannelHandler forbiddenHttpRequestResponder() {
        return new SimpleChannelHandler() {
            public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
                if (!(e.getMessage() instanceof WebSocketFrame)) {
                    ctx.getChannel().write(new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN));
                    return;
                }
                ctx.sendUpstream(e);
            }
        };
    }

    public void beforeAdd(ChannelHandlerContext ctx) throws Exception {
    }

    public void beforeRemove(ChannelHandlerContext ctx) throws Exception {
    }

    public void afterRemove(ChannelHandlerContext ctx) throws Exception {
    }
}