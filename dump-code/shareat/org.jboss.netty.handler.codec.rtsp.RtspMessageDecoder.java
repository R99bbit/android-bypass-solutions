package org.jboss.netty.handler.codec.rtsp;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.embedder.DecoderEmbedder;
import org.jboss.netty.handler.codec.http.HttpChunkAggregator;
import org.jboss.netty.handler.codec.http.HttpMessage;
import org.jboss.netty.handler.codec.http.HttpMessageDecoder;

public abstract class RtspMessageDecoder extends HttpMessageDecoder {
    private final DecoderEmbedder<HttpMessage> aggregator;

    protected RtspMessageDecoder() {
        this(4096, 8192, 8192);
    }

    protected RtspMessageDecoder(int maxInitialLineLength, int maxHeaderSize, int maxContentLength) {
        super(maxInitialLineLength, maxHeaderSize, maxContentLength * 2);
        this.aggregator = new DecoderEmbedder<>(new HttpChunkAggregator(maxContentLength));
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer, State state) throws Exception {
        Object o = super.decode(ctx, channel, buffer, state);
        if (o == null || !this.aggregator.offer(o)) {
            return null;
        }
        return this.aggregator.poll();
    }

    /* access modifiers changed from: protected */
    public boolean isContentAlwaysEmpty(HttpMessage msg) {
        boolean empty = super.isContentAlwaysEmpty(msg);
        if (empty) {
            return true;
        }
        if (!msg.headers().contains("Content-Length")) {
            return true;
        }
        return empty;
    }
}