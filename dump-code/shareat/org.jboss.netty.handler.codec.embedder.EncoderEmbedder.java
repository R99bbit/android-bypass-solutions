package org.jboss.netty.handler.codec.embedder;

import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.Channels;

public class EncoderEmbedder<E> extends AbstractCodecEmbedder<E> {
    public /* bridge */ /* synthetic */ boolean finish() {
        return super.finish();
    }

    public /* bridge */ /* synthetic */ ChannelPipeline getPipeline() {
        return super.getPipeline();
    }

    public EncoderEmbedder(ChannelDownstreamHandler... handlers) {
        super(handlers);
    }

    public EncoderEmbedder(ChannelBufferFactory bufferFactory, ChannelDownstreamHandler... handlers) {
        super(bufferFactory, handlers);
    }

    public boolean offer(Object input) {
        Channels.write(getChannel(), input).setSuccess();
        return !isEmpty();
    }
}