package org.jboss.netty.handler.execution;

import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.util.ObjectSizeEstimator;

public final class OrderedDownstreamThreadPoolExecutor extends OrderedMemoryAwareThreadPoolExecutor {
    public OrderedDownstreamThreadPoolExecutor(int corePoolSize) {
        super(corePoolSize, 0, 0);
    }

    public OrderedDownstreamThreadPoolExecutor(int corePoolSize, long keepAliveTime, TimeUnit unit) {
        super(corePoolSize, 0, 0, keepAliveTime, unit);
    }

    public OrderedDownstreamThreadPoolExecutor(int corePoolSize, long keepAliveTime, TimeUnit unit, ThreadFactory threadFactory) {
        super(corePoolSize, 0, 0, keepAliveTime, unit, threadFactory);
    }

    public ObjectSizeEstimator getObjectSizeEstimator() {
        return null;
    }

    public void setObjectSizeEstimator(ObjectSizeEstimator objectSizeEstimator) {
        throw new UnsupportedOperationException("Not supported by this implementation");
    }

    public long getMaxChannelMemorySize() {
        return 0;
    }

    public void setMaxChannelMemorySize(long maxChannelMemorySize) {
        throw new UnsupportedOperationException("Not supported by this implementation");
    }

    public long getMaxTotalMemorySize() {
        return 0;
    }

    @Deprecated
    public void setMaxTotalMemorySize(long maxTotalMemorySize) {
        throw new UnsupportedOperationException("Not supported by this implementation");
    }

    /* access modifiers changed from: protected */
    public boolean shouldCount(Runnable task) {
        return false;
    }

    public void execute(Runnable command) {
        if (command instanceof ChannelUpstreamEventRunnable) {
            throw new RejectedExecutionException("command must be enclosed with an downstream event.");
        }
        doExecute(command);
    }

    /* access modifiers changed from: protected */
    public Executor getChildExecutor(ChannelEvent e) {
        final Object key = getChildExecutorKey(e);
        Executor executor = (Executor) this.childExecutors.get(key);
        if (executor != null) {
            return executor;
        }
        Executor executor2 = new ChildExecutor();
        Executor oldExecutor = (Executor) this.childExecutors.putIfAbsent(key, executor2);
        if (oldExecutor != null) {
            return oldExecutor;
        }
        e.getChannel().getCloseFuture().addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture future) throws Exception {
                OrderedDownstreamThreadPoolExecutor.this.removeChildExecutor(key);
            }
        });
        return executor2;
    }
}