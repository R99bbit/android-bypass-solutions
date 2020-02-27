package org.jboss.netty.channel;

import java.util.EventListener;

public interface ChannelFutureListener extends EventListener {
    public static final ChannelFutureListener CLOSE = new ChannelFutureListener() {
        public void operationComplete(ChannelFuture future) {
            future.getChannel().close();
        }
    };
    public static final ChannelFutureListener CLOSE_ON_FAILURE = new ChannelFutureListener() {
        public void operationComplete(ChannelFuture future) {
            if (!future.isSuccess()) {
                future.getChannel().close();
            }
        }
    };

    void operationComplete(ChannelFuture channelFuture) throws Exception;
}