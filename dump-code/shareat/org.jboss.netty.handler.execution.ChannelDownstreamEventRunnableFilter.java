package org.jboss.netty.handler.execution;

public class ChannelDownstreamEventRunnableFilter implements ChannelEventRunnableFilter {
    public boolean filter(ChannelEventRunnable event) {
        return event instanceof ChannelDownstreamEventRunnable;
    }
}