package org.jboss.netty.handler.codec.spdy;

import javax.net.ssl.SSLEngine;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelUpstreamHandler;
import org.jboss.netty.handler.codec.http.HttpChunkAggregator;
import org.jboss.netty.handler.codec.http.HttpRequestDecoder;
import org.jboss.netty.handler.codec.http.HttpResponseEncoder;
import org.jboss.netty.handler.ssl.SslHandler;

public abstract class SpdyOrHttpChooser implements ChannelUpstreamHandler {
    private final int maxHttpContentLength;
    private final int maxSpdyContentLength;

    public enum SelectedProtocol {
        SpdyVersion3_1,
        SpdyVersion3,
        HttpVersion1_1,
        HttpVersion1_0,
        None
    }

    /* access modifiers changed from: protected */
    public abstract ChannelUpstreamHandler createHttpRequestHandlerForHttp();

    /* access modifiers changed from: protected */
    public abstract SelectedProtocol getProtocol(SSLEngine sSLEngine);

    protected SpdyOrHttpChooser(int maxSpdyContentLength2, int maxHttpContentLength2) {
        this.maxSpdyContentLength = maxSpdyContentLength2;
        this.maxHttpContentLength = maxHttpContentLength2;
    }

    public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        SslHandler handler = (SslHandler) ctx.getPipeline().get(SslHandler.class);
        if (handler == null) {
            throw new IllegalStateException("SslHandler is needed for SPDY");
        }
        ChannelPipeline pipeline = ctx.getPipeline();
        switch (getProtocol(handler.getEngine())) {
            case None:
                return;
            case SpdyVersion3:
                addSpdyHandlers(ctx, SpdyVersion.SPDY_3);
                break;
            case SpdyVersion3_1:
                addSpdyHandlers(ctx, SpdyVersion.SPDY_3_1);
                break;
            case HttpVersion1_0:
            case HttpVersion1_1:
                addHttpHandlers(ctx);
                break;
            default:
                throw new IllegalStateException("Unknown SelectedProtocol");
        }
        pipeline.remove((ChannelHandler) this);
        ctx.sendUpstream(e);
    }

    /* access modifiers changed from: protected */
    public void addSpdyHandlers(ChannelHandlerContext ctx, SpdyVersion version) {
        ChannelPipeline pipeline = ctx.getPipeline();
        pipeline.addLast("spdyDecoder", new SpdyFrameDecoder(version));
        pipeline.addLast("spdyEncoder", new SpdyFrameEncoder(version));
        pipeline.addLast("spdySessionHandler", new SpdySessionHandler(version, true));
        pipeline.addLast("spdyHttpEncoder", new SpdyHttpEncoder(version));
        pipeline.addLast("spdyHttpDecoder", new SpdyHttpDecoder(version, this.maxSpdyContentLength));
        pipeline.addLast("spdyStreamIdHandler", new SpdyHttpResponseStreamIdHandler());
        pipeline.addLast("httpRquestHandler", createHttpRequestHandlerForSpdy());
    }

    /* access modifiers changed from: protected */
    public void addHttpHandlers(ChannelHandlerContext ctx) {
        ChannelPipeline pipeline = ctx.getPipeline();
        pipeline.addLast("httpRquestDecoder", new HttpRequestDecoder());
        pipeline.addLast("httpResponseEncoder", new HttpResponseEncoder());
        pipeline.addLast("httpChunkAggregator", new HttpChunkAggregator(this.maxHttpContentLength));
        pipeline.addLast("httpRquestHandler", createHttpRequestHandlerForHttp());
    }

    /* access modifiers changed from: protected */
    public ChannelUpstreamHandler createHttpRequestHandlerForSpdy() {
        return createHttpRequestHandlerForHttp();
    }
}