package org.jboss.netty.channel.socket.http;

import java.net.SocketAddress;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.AbstractChannelSink;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelState;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.MessageEvent;

final class HttpTunnelingClientSocketPipelineSink extends AbstractChannelSink {
    HttpTunnelingClientSocketPipelineSink() {
    }

    public void eventSunk(ChannelPipeline pipeline, ChannelEvent e) throws Exception {
        HttpTunnelingClientSocketChannel channel = (HttpTunnelingClientSocketChannel) e.getChannel();
        ChannelFuture future = e.getFuture();
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent stateEvent = (ChannelStateEvent) e;
            ChannelState state = stateEvent.getState();
            Object value = stateEvent.getValue();
            switch (state) {
                case OPEN:
                    if (Boolean.FALSE.equals(value)) {
                        channel.closeReal(future);
                        return;
                    }
                    return;
                case BOUND:
                    if (value != null) {
                        channel.bindReal((SocketAddress) value, future);
                        return;
                    } else {
                        channel.unbindReal(future);
                        return;
                    }
                case CONNECTED:
                    if (value != null) {
                        channel.connectReal((SocketAddress) value, future);
                        return;
                    } else {
                        channel.closeReal(future);
                        return;
                    }
                case INTEREST_OPS:
                    channel.setInterestOpsReal(((Integer) value).intValue(), future);
                    return;
                default:
                    return;
            }
        } else if (e instanceof MessageEvent) {
            channel.writeReal((ChannelBuffer) ((MessageEvent) e).getMessage(), future);
        }
    }
}