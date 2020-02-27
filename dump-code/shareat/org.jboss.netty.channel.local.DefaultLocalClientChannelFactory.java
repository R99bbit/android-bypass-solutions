package org.jboss.netty.channel.local;

import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelSink;

public class DefaultLocalClientChannelFactory implements LocalClientChannelFactory {
    private final ChannelSink sink = new LocalClientChannelSink();

    public LocalChannel newChannel(ChannelPipeline pipeline) {
        return new DefaultLocalChannel(null, this, pipeline, this.sink, null);
    }

    public void releaseExternalResources() {
    }

    public void shutdown() {
    }
}