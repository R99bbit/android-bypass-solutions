package org.jboss.netty.channel;

import java.net.SocketAddress;

public abstract class AbstractServerChannel extends AbstractChannel implements ServerChannel {
    protected AbstractServerChannel(ChannelFactory factory, ChannelPipeline pipeline, ChannelSink sink) {
        super(null, factory, pipeline, sink);
    }

    public ChannelFuture connect(SocketAddress remoteAddress) {
        return getUnsupportedOperationFuture();
    }

    public ChannelFuture disconnect() {
        return getUnsupportedOperationFuture();
    }

    public int getInterestOps() {
        return 0;
    }

    public ChannelFuture setInterestOps(int interestOps) {
        return getUnsupportedOperationFuture();
    }

    /* access modifiers changed from: protected */
    public void setInterestOpsNow(int interestOps) {
    }

    public ChannelFuture write(Object message) {
        return getUnsupportedOperationFuture();
    }

    public ChannelFuture write(Object message, SocketAddress remoteAddress) {
        return getUnsupportedOperationFuture();
    }

    public boolean isConnected() {
        return false;
    }
}