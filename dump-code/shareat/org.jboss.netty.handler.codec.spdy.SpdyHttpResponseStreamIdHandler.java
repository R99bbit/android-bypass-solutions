package org.jboss.netty.handler.codec.spdy;

import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.handler.codec.http.HttpMessage;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.spdy.SpdyHttpHeaders.Names;

public class SpdyHttpResponseStreamIdHandler extends SimpleChannelHandler {
    private static final Integer NO_ID = Integer.valueOf(-1);
    private final Queue<Integer> ids = new ConcurrentLinkedQueue();

    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        if (e.getMessage() instanceof HttpMessage) {
            if (!((HttpMessage) e.getMessage()).headers().contains(Names.STREAM_ID)) {
                this.ids.add(NO_ID);
            } else {
                this.ids.add(Integer.valueOf(SpdyHttpHeaders.getStreamId((HttpMessage) e.getMessage())));
            }
        } else if (e.getMessage() instanceof SpdyRstStreamFrame) {
            this.ids.remove(Integer.valueOf(((SpdyRstStreamFrame) e.getMessage()).getStreamId()));
        }
        super.messageReceived(ctx, e);
    }

    public void writeRequested(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        if (e.getMessage() instanceof HttpResponse) {
            HttpResponse response = (HttpResponse) e.getMessage();
            Integer id = this.ids.poll();
            if (!(id == null || id.intValue() == NO_ID.intValue() || response.headers().contains(Names.STREAM_ID))) {
                SpdyHttpHeaders.setStreamId(response, id.intValue());
            }
        }
        super.writeRequested(ctx, e);
    }
}