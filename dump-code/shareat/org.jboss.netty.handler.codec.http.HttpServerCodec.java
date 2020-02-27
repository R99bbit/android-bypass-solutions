package org.jboss.netty.handler.codec.http;

import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelUpstreamHandler;

public class HttpServerCodec implements ChannelUpstreamHandler, ChannelDownstreamHandler {
    private final HttpRequestDecoder decoder;
    private final HttpResponseEncoder encoder;

    public HttpServerCodec() {
        this(4096, 8192, 8192);
    }

    public HttpServerCodec(int maxInitialLineLength, int maxHeaderSize, int maxChunkSize) {
        this.encoder = new HttpResponseEncoder();
        this.decoder = new HttpRequestDecoder(maxInitialLineLength, maxHeaderSize, maxChunkSize);
    }

    public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        this.decoder.handleUpstream(ctx, e);
    }

    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        this.encoder.handleDownstream(ctx, e);
    }
}