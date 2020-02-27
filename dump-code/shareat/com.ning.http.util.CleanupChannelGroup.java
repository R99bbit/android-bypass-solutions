package com.ning.http.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.channel.group.ChannelGroupFuture;
import org.jboss.netty.channel.group.DefaultChannelGroup;
import org.jboss.netty.channel.group.DefaultChannelGroupFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CleanupChannelGroup extends DefaultChannelGroup {
    private static final Logger logger = LoggerFactory.getLogger(CleanupChannelGroup.class);
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public CleanupChannelGroup() {
    }

    public CleanupChannelGroup(String name) {
        super(name);
    }

    public ChannelGroupFuture close() {
        this.lock.writeLock().lock();
        try {
            if (!this.closed.getAndSet(true)) {
                return super.close();
            }
            Collection<ChannelFuture> futures = new ArrayList<>();
            logger.debug("CleanupChannelGroup Already closed");
            DefaultChannelGroupFuture defaultChannelGroupFuture = new DefaultChannelGroupFuture(ChannelGroup.class.cast(this), futures);
            this.lock.writeLock().unlock();
            return defaultChannelGroupFuture;
        } finally {
            this.lock.writeLock().unlock();
        }
    }

    public boolean add(Channel channel) {
        this.lock.readLock().lock();
        try {
            if (this.closed.get()) {
                channel.close();
                return false;
            }
            boolean add = super.add(channel);
            this.lock.readLock().unlock();
            return add;
        } finally {
            this.lock.readLock().unlock();
        }
    }
}