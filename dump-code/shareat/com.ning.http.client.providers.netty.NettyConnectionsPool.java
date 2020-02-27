package com.ning.http.client.providers.netty;

import com.kakao.util.helper.CommonProtocol;
import com.ning.http.client.ConnectionsPool;
import com.ning.http.util.DateUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.util.HashedWheelTimer;
import org.jboss.netty.util.Timeout;
import org.jboss.netty.util.TimerTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NettyConnectionsPool implements ConnectionsPool<String, Channel> {
    /* access modifiers changed from: private */
    public static final Logger log = LoggerFactory.getLogger(NettyConnectionsPool.class);
    private final ConcurrentHashMap<Channel, Long> channel2CreationDate;
    /* access modifiers changed from: private */
    public final ConcurrentHashMap<Channel, IdleChannel> channel2IdleChannel;
    /* access modifiers changed from: private */
    public final ConcurrentHashMap<String, ConcurrentLinkedQueue<IdleChannel>> connectionsPool;
    private final HashedWheelTimer hashedWheelTimer;
    /* access modifiers changed from: private */
    public final AtomicBoolean isClosed;
    private final int maxConnectionLifeTimeInMs;
    private final int maxConnectionPerHost;
    /* access modifiers changed from: private */
    public final long maxIdleTime;
    private final int maxTotalConnections;
    private final boolean sslConnectionPoolEnabled;

    private static class IdleChannel {
        final Channel channel;
        final long start = DateUtil.millisTime();
        final String uri;

        IdleChannel(String uri2, Channel channel2) {
            this.uri = uri2;
            this.channel = channel2;
        }

        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof IdleChannel)) {
                return false;
            }
            IdleChannel that = (IdleChannel) o;
            if (this.channel != null) {
                if (this.channel.equals(that.channel)) {
                    return true;
                }
            } else if (that.channel == null) {
                return true;
            }
            return false;
        }

        public int hashCode() {
            if (this.channel != null) {
                return this.channel.hashCode();
            }
            return 0;
        }
    }

    private class IdleChannelDetector implements TimerTask {
        private IdleChannelDetector() {
        }

        public void run(Timeout timeout) throws Exception {
            try {
                if (!NettyConnectionsPool.this.isClosed.get()) {
                    if (NettyConnectionsPool.log.isDebugEnabled()) {
                        for (String s : NettyConnectionsPool.this.connectionsPool.keySet()) {
                            NettyConnectionsPool.log.debug((String) "Entry count for : {} : {}", (Object) s, (Object) Integer.valueOf(((ConcurrentLinkedQueue) NettyConnectionsPool.this.connectionsPool.get(s)).size()));
                        }
                    }
                    List<IdleChannel> channelsInTimeout = new ArrayList<>();
                    long currentTime = DateUtil.millisTime();
                    for (IdleChannel idleChannel : NettyConnectionsPool.this.channel2IdleChannel.values()) {
                        if (currentTime - idleChannel.start > NettyConnectionsPool.this.maxIdleTime) {
                            NettyConnectionsPool.log.debug((String) "Adding Candidate Idle Channel {}", (Object) idleChannel.channel);
                            channelsInTimeout.add(idleChannel);
                        }
                    }
                    long endConcurrentLoop = DateUtil.millisTime();
                    for (IdleChannel idleChannel2 : channelsInTimeout) {
                        Object attachment = idleChannel2.channel.getPipeline().getContext(NettyAsyncHttpProvider.class).getAttachment();
                        if (attachment instanceof NettyResponseFuture) {
                            NettyResponseFuture nettyResponseFuture = (NettyResponseFuture) attachment;
                            if (!nettyResponseFuture.isDone() && !nettyResponseFuture.isCancelled()) {
                                NettyConnectionsPool.log.debug((String) "Future not in appropriate state %s\n", (Object) nettyResponseFuture);
                            }
                        }
                        if (NettyConnectionsPool.this.remove(idleChannel2)) {
                            NettyConnectionsPool.log.debug((String) "Closing Idle Channel {}", (Object) idleChannel2.channel);
                            NettyConnectionsPool.this.close(idleChannel2.channel);
                        }
                    }
                    if (NettyConnectionsPool.log.isTraceEnabled()) {
                        int openChannels = 0;
                        for (ConcurrentLinkedQueue<IdleChannel> hostChannels : NettyConnectionsPool.this.connectionsPool.values()) {
                            openChannels += hostChannels.size();
                        }
                        NettyConnectionsPool.log.trace(String.format("%d channel open, %d idle channels closed (times: 1st-loop=%d, 2nd-loop=%d).\n", new Object[]{Integer.valueOf(openChannels), Integer.valueOf(channelsInTimeout.size()), Long.valueOf(endConcurrentLoop - currentTime), Long.valueOf(DateUtil.millisTime() - endConcurrentLoop)}));
                    }
                    NettyConnectionsPool.this.scheduleNewIdleChannelDetector(timeout.getTask());
                }
            } catch (Throwable t) {
                NettyConnectionsPool.log.error((String) "uncaught exception!", t);
            }
        }
    }

    public NettyConnectionsPool(NettyAsyncHttpProvider provider, HashedWheelTimer hashedWheelTimer2) {
        this(provider.getConfig().getMaxTotalConnections(), provider.getConfig().getMaxConnectionPerHost(), (long) provider.getConfig().getIdleConnectionInPoolTimeoutInMs(), provider.getConfig().getMaxConnectionLifeTimeInMs(), provider.getConfig().isSslConnectionPoolEnabled(), hashedWheelTimer2);
    }

    public NettyConnectionsPool(int maxTotalConnections2, int maxConnectionPerHost2, long maxIdleTime2, int maxConnectionLifeTimeInMs2, boolean sslConnectionPoolEnabled2, HashedWheelTimer hashedWheelTimer2) {
        this.connectionsPool = new ConcurrentHashMap<>();
        this.channel2IdleChannel = new ConcurrentHashMap<>();
        this.channel2CreationDate = new ConcurrentHashMap<>();
        this.isClosed = new AtomicBoolean(false);
        this.maxTotalConnections = maxTotalConnections2;
        this.maxConnectionPerHost = maxConnectionPerHost2;
        this.sslConnectionPoolEnabled = sslConnectionPoolEnabled2;
        this.maxIdleTime = maxIdleTime2;
        this.maxConnectionLifeTimeInMs = maxConnectionLifeTimeInMs2;
        this.hashedWheelTimer = hashedWheelTimer2;
        scheduleNewIdleChannelDetector(new IdleChannelDetector());
    }

    /* access modifiers changed from: private */
    public void scheduleNewIdleChannelDetector(TimerTask task) {
        this.hashedWheelTimer.newTimeout(task, this.maxIdleTime, TimeUnit.MILLISECONDS);
    }

    public boolean offer(String uri, Channel channel) {
        boolean add;
        if (this.isClosed.get()) {
            return false;
        }
        if (!this.sslConnectionPoolEnabled && uri.startsWith(CommonProtocol.URL_SCHEME)) {
            return false;
        }
        Long createTime = this.channel2CreationDate.get(channel);
        if (createTime == null) {
            this.channel2CreationDate.putIfAbsent(channel, Long.valueOf(DateUtil.millisTime()));
        } else if (this.maxConnectionLifeTimeInMs != -1 && createTime.longValue() + ((long) this.maxConnectionLifeTimeInMs) < DateUtil.millisTime()) {
            log.debug((String) "Channel {} expired", (Object) channel);
            return false;
        }
        log.debug((String) "Adding uri: {} for channel {}", (Object) uri, (Object) channel);
        channel.getPipeline().getContext(NettyAsyncHttpProvider.class).setAttachment(new DiscardEvent());
        ConcurrentLinkedQueue<IdleChannel> idleConnectionForHost = this.connectionsPool.get(uri);
        if (idleConnectionForHost == null) {
            ConcurrentLinkedQueue<IdleChannel> newPool = new ConcurrentLinkedQueue<>();
            idleConnectionForHost = this.connectionsPool.putIfAbsent(uri, newPool);
            if (idleConnectionForHost == null) {
                idleConnectionForHost = newPool;
            }
        }
        int size = idleConnectionForHost.size();
        if (this.maxConnectionPerHost == -1 || size < this.maxConnectionPerHost) {
            IdleChannel idleChannel = new IdleChannel(uri, channel);
            synchronized (idleConnectionForHost) {
                add = idleConnectionForHost.add(idleChannel);
                if (this.channel2IdleChannel.put(channel, idleChannel) != null) {
                    log.error((String) "Channel {} already exists in the connections pool!", (Object) channel);
                }
            }
            return add;
        }
        log.debug((String) "Maximum number of requests per host reached {} for {}", (Object) Integer.valueOf(this.maxConnectionPerHost), (Object) uri);
        return false;
    }

    public Channel poll(String uri) {
        if (!this.sslConnectionPoolEnabled && uri.startsWith(CommonProtocol.URL_SCHEME)) {
            return null;
        }
        IdleChannel idleChannel = null;
        ConcurrentLinkedQueue<IdleChannel> idleConnectionForHost = this.connectionsPool.get(uri);
        if (idleConnectionForHost != null) {
            boolean poolEmpty = false;
            while (!poolEmpty && idleChannel == null) {
                if (!idleConnectionForHost.isEmpty()) {
                    synchronized (idleConnectionForHost) {
                        idleChannel = (IdleChannel) idleConnectionForHost.poll();
                        if (idleChannel != null) {
                            this.channel2IdleChannel.remove(idleChannel.channel);
                        }
                    }
                }
                if (idleChannel == null) {
                    poolEmpty = true;
                } else if (!idleChannel.channel.isConnected() || !idleChannel.channel.isOpen()) {
                    idleChannel = null;
                    log.trace("Channel not connected or not opened!");
                }
            }
        }
        return idleChannel != null ? idleChannel.channel : null;
    }

    /* access modifiers changed from: private */
    public boolean remove(IdleChannel pooledChannel) {
        boolean z = false;
        if (pooledChannel == null || this.isClosed.get()) {
            return false;
        }
        boolean isRemoved = false;
        ConcurrentLinkedQueue<IdleChannel> pooledConnectionForHost = this.connectionsPool.get(pooledChannel.uri);
        if (pooledConnectionForHost != null) {
            isRemoved = pooledConnectionForHost.remove(pooledChannel);
        }
        if (this.channel2IdleChannel.remove(pooledChannel.channel) != null) {
            z = true;
        }
        return isRemoved | z;
    }

    public boolean removeAll(Channel channel) {
        this.channel2CreationDate.remove(channel);
        return !this.isClosed.get() && remove(this.channel2IdleChannel.get(channel));
    }

    public boolean canCacheConnection() {
        if (this.isClosed.get() || this.maxTotalConnections == -1 || this.channel2IdleChannel.size() < this.maxTotalConnections) {
            return true;
        }
        return false;
    }

    public void destroy() {
        if (!this.isClosed.getAndSet(true)) {
            for (Channel channel : this.channel2IdleChannel.keySet()) {
                close(channel);
            }
            this.connectionsPool.clear();
            this.channel2IdleChannel.clear();
            this.channel2CreationDate.clear();
        }
    }

    /* access modifiers changed from: private */
    public void close(Channel channel) {
        try {
            channel.getPipeline().getContext(NettyAsyncHttpProvider.class).setAttachment(new DiscardEvent());
            this.channel2CreationDate.remove(channel);
            channel.close();
        } catch (Throwable th) {
        }
    }

    public final String toString() {
        return String.format("NettyConnectionPool: {pool-size: %d}", new Object[]{Integer.valueOf(this.channel2IdleChannel.size())});
    }
}