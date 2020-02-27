package org.jboss.netty.bootstrap;

import java.net.SocketAddress;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipelineException;

public class ClientBootstrap extends Bootstrap {
    public ClientBootstrap() {
    }

    public ClientBootstrap(ChannelFactory channelFactory) {
        super(channelFactory);
    }

    public ChannelFuture connect() {
        SocketAddress remoteAddress = (SocketAddress) getOption("remoteAddress");
        if (remoteAddress != null) {
            return connect(remoteAddress);
        }
        throw new IllegalStateException("remoteAddress option is not set.");
    }

    public ChannelFuture connect(SocketAddress remoteAddress) {
        if (remoteAddress != null) {
            return connect(remoteAddress, (SocketAddress) getOption("localAddress"));
        }
        throw new NullPointerException("remoteAddress");
    }

    public ChannelFuture connect(SocketAddress remoteAddress, SocketAddress localAddress) {
        if (remoteAddress == null) {
            throw new NullPointerException("remoteAddress");
        }
        try {
            Channel ch = getFactory().newChannel(getPipelineFactory().getPipeline());
            boolean success = false;
            try {
                ch.getConfig().setOptions(getOptions());
                success = true;
                if (localAddress != null) {
                    ch.bind(localAddress);
                }
                return ch.connect(remoteAddress);
            } finally {
                if (!success) {
                    ch.close();
                }
            }
        } catch (Exception e) {
            throw new ChannelPipelineException("Failed to initialize a pipeline.", e);
        }
    }

    public ChannelFuture bind(SocketAddress localAddress) {
        if (localAddress == null) {
            throw new NullPointerException("localAddress");
        }
        try {
            Channel ch = getFactory().newChannel(getPipelineFactory().getPipeline());
            boolean success = false;
            try {
                ch.getConfig().setOptions(getOptions());
                success = true;
                return ch.bind(localAddress);
            } finally {
                if (!success) {
                    ch.close();
                }
            }
        } catch (Exception e) {
            throw new ChannelPipelineException("Failed to initialize a pipeline.", e);
        }
    }
}