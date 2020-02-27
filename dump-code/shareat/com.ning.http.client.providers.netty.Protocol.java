package com.ning.http.client.providers.netty;

import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;

public interface Protocol {
    void handle(ChannelHandlerContext channelHandlerContext, MessageEvent messageEvent) throws Exception;

    void onClose(ChannelHandlerContext channelHandlerContext, ChannelStateEvent channelStateEvent);

    void onError(ChannelHandlerContext channelHandlerContext, ExceptionEvent exceptionEvent);
}