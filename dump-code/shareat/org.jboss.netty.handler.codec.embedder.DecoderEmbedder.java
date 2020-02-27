package org.jboss.netty.handler.codec.embedder;

import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelUpstreamHandler;
import org.jboss.netty.channel.Channels;

public class DecoderEmbedder<E> extends AbstractCodecEmbedder<E> {
    public /* bridge */ /* synthetic */ boolean finish() {
        return super.finish();
    }

    public /* bridge */ /* synthetic */ ChannelPipeline getPipeline() {
        return super.getPipeline();
    }

    public DecoderEmbedder(ChannelUpstreamHandler... handlers) {
        super(handlers);
    }

    public DecoderEmbedder(ChannelBufferFactory bufferFactory, ChannelUpstreamHandler... handlers) {
        super(bufferFactory, handlers);
    }

    public boolean offer(Object input) {
        Channels.fireMessageReceived(getChannel(), input);
        return !isEmpty();
    }
}