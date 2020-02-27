package org.jboss.netty.bootstrap;

import java.net.SocketAddress;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipelineException;

public class ConnectionlessBootstrap extends Bootstrap {
    public ConnectionlessBootstrap() {
    }

    public ConnectionlessBootstrap(ChannelFactory channelFactory) {
        super(channelFactory);
    }

    public Channel bind() {
        SocketAddress localAddress = (SocketAddress) getOption("localAddress");
        if (localAddress != null) {
            return bind(localAddress);
        }
        throw new IllegalStateException("localAddress option is not set.");
    }

    public Channel bind(SocketAddress localAddress) {
        if (localAddress == null) {
            throw new NullPointerException("localAddress");
        }
        try {
            Channel ch = getFactory().newChannel(getPipelineFactory().getPipeline());
            boolean success = false;
            try {
                ch.getConfig().setOptions(getOptions());
                success = true;
                ChannelFuture future = ch.bind(localAddress);
                future.awaitUninterruptibly();
                if (future.isSuccess()) {
                    return ch;
                }
                future.getChannel().close().awaitUninterruptibly();
                throw new ChannelException("Failed to bind to: " + localAddress, future.getCause());
            } finally {
                if (!success) {
                    ch.close();
                }
            }
        } catch (Exception e) {
            throw new ChannelPipelineException("Failed to initialize a pipeline.", e);
        }
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
        throw new NullPointerException("remotedAddress");
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
}