package org.jboss.netty.channel.local;

import java.util.concurrent.ConcurrentMap;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.util.internal.ConcurrentHashMap;

final class LocalChannelRegistry {
    private static final ConcurrentMap<LocalAddress, Channel> map = new ConcurrentHashMap();

    static boolean isRegistered(LocalAddress address) {
        return map.containsKey(address);
    }

    static Channel getChannel(LocalAddress address) {
        return (Channel) map.get(address);
    }

    static boolean register(LocalAddress address, Channel channel) {
        return map.putIfAbsent(address, channel) == null;
    }

    static boolean unregister(LocalAddress address) {
        return map.remove(address) != null;
    }

    private LocalChannelRegistry() {
    }
}