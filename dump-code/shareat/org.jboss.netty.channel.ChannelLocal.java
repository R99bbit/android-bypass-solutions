package org.jboss.netty.channel;

import java.util.Collections;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentMap;
import org.jboss.netty.util.internal.ConcurrentIdentityWeakKeyHashMap;

public class ChannelLocal<T> implements Iterable<Entry<Channel, T>> {
    private final ConcurrentMap<Channel, T> map;
    private final boolean removeOnClose;
    private final ChannelFutureListener remover;

    public ChannelLocal() {
        this(false);
    }

    public ChannelLocal(boolean removeOnClose2) {
        this.map = new ConcurrentIdentityWeakKeyHashMap();
        this.remover = new ChannelFutureListener() {
            public void operationComplete(ChannelFuture future) throws Exception {
                ChannelLocal.this.remove(future.getChannel());
            }
        };
        this.removeOnClose = removeOnClose2;
    }

    /* access modifiers changed from: protected */
    public T initialValue(Channel channel) {
        return null;
    }

    public T get(Channel channel) {
        if (channel == null) {
            throw new NullPointerException("channel");
        }
        T value = this.map.get(channel);
        if (value != null) {
            return value;
        }
        T value2 = initialValue(channel);
        if (value2 == null) {
            return value2;
        }
        T oldValue = setIfAbsent(channel, value2);
        if (oldValue != null) {
            return oldValue;
        }
        return value2;
    }

    public T set(Channel channel, T value) {
        if (value == null) {
            return remove(channel);
        }
        if (channel == null) {
            throw new NullPointerException("channel");
        }
        T put = this.map.put(channel, value);
        if (!this.removeOnClose) {
            return put;
        }
        channel.getCloseFuture().addListener(this.remover);
        return put;
    }

    public T setIfAbsent(Channel channel, T value) {
        if (value == null) {
            return get(channel);
        }
        if (channel == null) {
            throw new NullPointerException("channel");
        }
        T mapping = this.map.putIfAbsent(channel, value);
        if (!this.removeOnClose || mapping != null) {
            return mapping;
        }
        channel.getCloseFuture().addListener(this.remover);
        return mapping;
    }

    public T remove(Channel channel) {
        if (channel == null) {
            throw new NullPointerException("channel");
        }
        T removed = this.map.remove(channel);
        if (removed == null) {
            return initialValue(channel);
        }
        if (!this.removeOnClose) {
            return removed;
        }
        channel.getCloseFuture().removeListener(this.remover);
        return removed;
    }

    public Iterator<Entry<Channel, T>> iterator() {
        return Collections.unmodifiableSet(this.map.entrySet()).iterator();
    }
}