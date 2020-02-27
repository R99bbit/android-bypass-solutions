package org.jboss.netty.handler.codec.spdy;

import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelUpstreamHandler;

public class SpdyHttpCodec implements ChannelUpstreamHandler, ChannelDownstreamHandler {
    private final SpdyHttpDecoder decoder;
    private final SpdyHttpEncoder encoder;

    public SpdyHttpCodec(SpdyVersion version, int maxContentLength) {
        this.decoder = new SpdyHttpDecoder(version, maxContentLength);
        this.encoder = new SpdyHttpEncoder(version);
    }

    public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        this.decoder.handleUpstream(ctx, e);
    }

    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        this.encoder.handleDownstream(ctx, e);
    }
}