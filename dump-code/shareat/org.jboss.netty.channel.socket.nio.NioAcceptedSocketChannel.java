package org.jboss.netty.channel.socket.nio;

import java.nio.channels.SocketChannel;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelSink;
import org.jboss.netty.channel.Channels;

final class NioAcceptedSocketChannel extends NioSocketChannel {
    final Thread bossThread;

    NioAcceptedSocketChannel(ChannelFactory factory, ChannelPipeline pipeline, Channel parent, ChannelSink sink, SocketChannel socket, NioWorker worker, Thread bossThread2) {
        super(parent, factory, pipeline, sink, socket, worker);
        this.bossThread = bossThread2;
        setConnected();
        Channels.fireChannelOpen((Channel) this);
    }
}