package org.jboss.netty.handler.execution;

public class ChannelUpstreamEventRunnableFilter implements ChannelEventRunnableFilter {
    public boolean filter(ChannelEventRunnable event) {
        return event instanceof ChannelDownstreamEventRunnable;
    }
}