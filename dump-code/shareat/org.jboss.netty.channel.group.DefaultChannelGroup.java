package org.jboss.netty.channel.group;

import java.net.SocketAddress;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ServerChannel;
import org.jboss.netty.util.internal.ConcurrentHashMap;

public class DefaultChannelGroup extends AbstractSet<Channel> implements ChannelGroup {
    private static final AtomicInteger nextId = new AtomicInteger();
    private final String name;
    private final ConcurrentMap<Integer, Channel> nonServerChannels;
    private final ChannelFutureListener remover;
    private final ConcurrentMap<Integer, Channel> serverChannels;

    public DefaultChannelGroup() {
        this("group-0x" + Integer.toHexString(nextId.incrementAndGet()));
    }

    public DefaultChannelGroup(String name2) {
        this.serverChannels = new ConcurrentHashMap();
        this.nonServerChannels = new ConcurrentHashMap();
        this.remover = new ChannelFutureListener() {
            public void operationComplete(ChannelFuture future) throws Exception {
                DefaultChannelGroup.this.remove(future.getChannel());
            }
        };
        if (name2 == null) {
            throw new NullPointerException("name");
        }
        this.name = name2;
    }

    public String getName() {
        return this.name;
    }

    public boolean isEmpty() {
        return this.nonServerChannels.isEmpty() && this.serverChannels.isEmpty();
    }

    public int size() {
        return this.nonServerChannels.size() + this.serverChannels.size();
    }

    public Channel find(Integer id) {
        Channel c = (Channel) this.nonServerChannels.get(id);
        return c != null ? c : (Channel) this.serverChannels.get(id);
    }

    public boolean contains(Object o) {
        if (o instanceof Integer) {
            if (this.nonServerChannels.containsKey(o) || this.serverChannels.containsKey(o)) {
                return true;
            }
            return false;
        } else if (!(o instanceof Channel)) {
            return false;
        } else {
            Channel c = (Channel) o;
            if (o instanceof ServerChannel) {
                return this.serverChannels.containsKey(c.getId());
            }
            return this.nonServerChannels.containsKey(c.getId());
        }
    }

    public boolean add(Channel channel) {
        boolean added = (channel instanceof ServerChannel ? this.serverChannels : this.nonServerChannels).putIfAbsent(channel.getId(), channel) == null;
        if (added) {
            channel.getCloseFuture().addListener(this.remover);
        }
        return added;
    }

    public boolean remove(Object o) {
        Channel c = null;
        if (o instanceof Integer) {
            c = (Channel) this.nonServerChannels.remove(o);
            if (c == null) {
                c = (Channel) this.serverChannels.remove(o);
            }
        } else if (o instanceof Channel) {
            Channel c2 = (Channel) o;
            if (c2 instanceof ServerChannel) {
                c = (Channel) this.serverChannels.remove(c2.getId());
            } else {
                c = (Channel) this.nonServerChannels.remove(c2.getId());
            }
        }
        if (c == null) {
            return false;
        }
        c.getCloseFuture().removeListener(this.remover);
        return true;
    }

    public void clear() {
        this.nonServerChannels.clear();
        this.serverChannels.clear();
    }

    public Iterator<Channel> iterator() {
        return new CombinedIterator(this.serverChannels.values().iterator(), this.nonServerChannels.values().iterator());
    }

    public Object[] toArray() {
        Collection<Channel> channels = new ArrayList<>(size());
        channels.addAll(this.serverChannels.values());
        channels.addAll(this.nonServerChannels.values());
        return channels.toArray();
    }

    public <T> T[] toArray(T[] a) {
        Collection<Channel> channels = new ArrayList<>(size());
        channels.addAll(this.serverChannels.values());
        channels.addAll(this.nonServerChannels.values());
        return channels.toArray(a);
    }

    public ChannelGroupFuture close() {
        Map<Integer, ChannelFuture> futures = new LinkedHashMap<>(size());
        for (Channel c : this.serverChannels.values()) {
            futures.put(c.getId(), c.close().awaitUninterruptibly());
        }
        for (Channel c2 : this.nonServerChannels.values()) {
            futures.put(c2.getId(), c2.close());
        }
        return new DefaultChannelGroupFuture((ChannelGroup) this, futures);
    }

    public ChannelGroupFuture disconnect() {
        Map<Integer, ChannelFuture> futures = new LinkedHashMap<>(size());
        for (Channel c : this.serverChannels.values()) {
            futures.put(c.getId(), c.disconnect().awaitUninterruptibly());
        }
        for (Channel c2 : this.nonServerChannels.values()) {
            futures.put(c2.getId(), c2.disconnect());
        }
        return new DefaultChannelGroupFuture((ChannelGroup) this, futures);
    }

    public ChannelGroupFuture setInterestOps(int interestOps) {
        Map<Integer, ChannelFuture> futures = new LinkedHashMap<>(size());
        for (Channel c : this.serverChannels.values()) {
            futures.put(c.getId(), c.setInterestOps(interestOps).awaitUninterruptibly());
        }
        for (Channel c2 : this.nonServerChannels.values()) {
            futures.put(c2.getId(), c2.setInterestOps(interestOps));
        }
        return new DefaultChannelGroupFuture((ChannelGroup) this, futures);
    }

    public ChannelGroupFuture setReadable(boolean readable) {
        Map<Integer, ChannelFuture> futures = new LinkedHashMap<>(size());
        for (Channel c : this.serverChannels.values()) {
            futures.put(c.getId(), c.setReadable(readable).awaitUninterruptibly());
        }
        for (Channel c2 : this.nonServerChannels.values()) {
            futures.put(c2.getId(), c2.setReadable(readable));
        }
        return new DefaultChannelGroupFuture((ChannelGroup) this, futures);
    }

    public ChannelGroupFuture unbind() {
        Map<Integer, ChannelFuture> futures = new LinkedHashMap<>(size());
        for (Channel c : this.serverChannels.values()) {
            futures.put(c.getId(), c.unbind().awaitUninterruptibly());
        }
        for (Channel c2 : this.nonServerChannels.values()) {
            futures.put(c2.getId(), c2.unbind());
        }
        return new DefaultChannelGroupFuture((ChannelGroup) this, futures);
    }

    public ChannelGroupFuture write(Object message) {
        Map<Integer, ChannelFuture> futures = new LinkedHashMap<>(size());
        if (message instanceof ChannelBuffer) {
            ChannelBuffer buf = (ChannelBuffer) message;
            for (Channel c : this.nonServerChannels.values()) {
                futures.put(c.getId(), c.write(buf.duplicate()));
            }
        } else {
            for (Channel c2 : this.nonServerChannels.values()) {
                futures.put(c2.getId(), c2.write(message));
            }
        }
        return new DefaultChannelGroupFuture((ChannelGroup) this, futures);
    }

    public ChannelGroupFuture write(Object message, SocketAddress remoteAddress) {
        Map<Integer, ChannelFuture> futures = new LinkedHashMap<>(size());
        if (message instanceof ChannelBuffer) {
            ChannelBuffer buf = (ChannelBuffer) message;
            for (Channel c : this.nonServerChannels.values()) {
                futures.put(c.getId(), c.write(buf.duplicate(), remoteAddress));
            }
        } else {
            for (Channel c2 : this.nonServerChannels.values()) {
                futures.put(c2.getId(), c2.write(message, remoteAddress));
            }
        }
        return new DefaultChannelGroupFuture((ChannelGroup) this, futures);
    }

    public int hashCode() {
        return System.identityHashCode(this);
    }

    public boolean equals(Object o) {
        return this == o;
    }

    public int compareTo(ChannelGroup o) {
        int v = getName().compareTo(o.getName());
        return v != 0 ? v : System.identityHashCode(this) - System.identityHashCode(o);
    }

    public String toString() {
        return getClass().getSimpleName() + "(name: " + getName() + ", size: " + size() + ')';
    }
}