package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelSink;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.Timeout;

final class NioClientSocketChannel extends NioSocketChannel {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(NioClientSocketChannel.class);
    volatile boolean boundManually;
    long connectDeadlineNanos;
    volatile ChannelFuture connectFuture;
    volatile SocketAddress requestedRemoteAddress;
    volatile Timeout timoutTimer;

    private static SocketChannel newSocket() {
        try {
            SocketChannel socket = SocketChannel.open();
            try {
                socket.configureBlocking(false);
                if (1 == 0) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        if (logger.isWarnEnabled()) {
                            logger.warn("Failed to close a partially initialized socket.", e);
                        }
                    }
                }
                return socket;
            } catch (IOException e2) {
                throw new ChannelException("Failed to enter non-blocking mode.", e2);
            } catch (Throwable th) {
                if (0 == 0) {
                    try {
                        socket.close();
                    } catch (IOException e3) {
                        if (logger.isWarnEnabled()) {
                            logger.warn("Failed to close a partially initialized socket.", e3);
                        }
                    }
                }
                throw th;
            }
        } catch (IOException e4) {
            throw new ChannelException("Failed to open a socket.", e4);
        }
    }

    NioClientSocketChannel(ChannelFactory factory, ChannelPipeline pipeline, ChannelSink sink, NioWorker worker) {
        super(null, factory, pipeline, sink, newSocket(), worker);
        Channels.fireChannelOpen((Channel) this);
    }
}