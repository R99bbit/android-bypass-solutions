package com.ning.http.client.providers.grizzly;

import com.kakao.util.helper.CommonProtocol;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.ConnectionsPool;
import com.ning.http.util.DateUtil;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.glassfish.grizzly.CloseListener;
import org.glassfish.grizzly.CloseType;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.Grizzly;
import org.glassfish.grizzly.attributes.Attribute;
import org.glassfish.grizzly.utils.DataStructures;
import org.glassfish.grizzly.utils.NullaryFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GrizzlyConnectionsPool implements ConnectionsPool<String, Connection> {
    /* access modifiers changed from: private */
    public static final Logger LOG = LoggerFactory.getLogger(GrizzlyConnectionsPool.class);
    private final boolean cacheSSLConnections;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final ConcurrentHashMap<String, IdleConnectionQueue> connectionsPool = new ConcurrentHashMap<>();
    private final DelayedExecutor delayedExecutor;
    private final CloseListener listener = new CloseListener<Connection, CloseType>() {
        public void onClosed(Connection connection, CloseType closeType) throws IOException {
            if (closeType == CloseType.REMOTELY && GrizzlyConnectionsPool.LOG.isInfoEnabled()) {
                GrizzlyConnectionsPool.LOG.info((String) "Remote closed connection ({}).  Removing from cache", (Object) connection.toString());
            }
            GrizzlyConnectionsPool.this.removeAll(connection);
        }
    };
    private final long maxConnectionLifeTimeInMs;
    private final int maxConnections;
    private final int maxConnectionsPerHost;
    private final boolean ownsDelayedExecutor;
    private final long timeout;
    /* access modifiers changed from: private */
    public final AtomicInteger totalCachedConnections = new AtomicInteger(0);
    private final boolean unlimitedConnections;

    public static final class DelayedExecutor {
        public static final long UNSET_TIMEOUT = -1;
        /* access modifiers changed from: private */
        public final long checkIntervalMs;
        /* access modifiers changed from: private */
        public volatile boolean isStarted;
        /* access modifiers changed from: private */
        public final BlockingQueue<IdleConnectionQueue> queues;
        private final DelayedRunnable runnable;
        /* access modifiers changed from: private */
        public final Object sync;
        private final ExecutorService threadPool;
        /* access modifiers changed from: private */
        public final AtomicInteger totalCachedConnections;

        private class DelayedRunnable implements Runnable {
            private DelayedRunnable() {
            }

            public void run() {
                while (DelayedExecutor.this.isStarted) {
                    long currentTimeMs = DateUtil.millisTime();
                    for (IdleConnectionQueue delayQueue : DelayedExecutor.this.queues) {
                        if (!delayQueue.queue.isEmpty()) {
                            TimeoutResolver resolver = delayQueue.resolver;
                            Iterator<Connection> it = delayQueue.queue.iterator();
                            while (it.hasNext()) {
                                Connection element = it.next();
                                Long timeoutMs = Long.valueOf(resolver.getTimeoutMs(element));
                                if (timeoutMs.longValue() == -1) {
                                    it.remove();
                                    if (DelayedExecutor.wasModified(timeoutMs.longValue(), resolver.getTimeoutMs(element))) {
                                        delayQueue.queue.offer(element);
                                    }
                                } else if (currentTimeMs - timeoutMs.longValue() >= 0) {
                                    it.remove();
                                    if (DelayedExecutor.wasModified(timeoutMs.longValue(), resolver.getTimeoutMs(element))) {
                                        delayQueue.queue.offer(element);
                                    } else {
                                        try {
                                            if (GrizzlyConnectionsPool.LOG.isDebugEnabled()) {
                                                GrizzlyConnectionsPool.LOG.debug((String) "Idle connection ({}) detected.  Removing from cache.", (Object) element.toString());
                                            }
                                            DelayedExecutor.this.totalCachedConnections.decrementAndGet();
                                            element.close();
                                        } catch (Exception e) {
                                        }
                                    }
                                }
                            }
                        }
                    }
                    synchronized (DelayedExecutor.this.sync) {
                        if (DelayedExecutor.this.isStarted) {
                            try {
                                DelayedExecutor.this.sync.wait(DelayedExecutor.this.checkIntervalMs);
                            } catch (InterruptedException e2) {
                            }
                        } else {
                            return;
                        }
                    }
                }
            }
        }

        final class IdleConnectionQueue {
            final AtomicInteger count = new AtomicInteger(0);
            final long maxConnectionLifeTimeInMs;
            final ConcurrentLinkedQueue<Connection> queue = new ConcurrentLinkedQueue<>();
            final TimeoutResolver resolver = new TimeoutResolver();
            final long timeout;

            public IdleConnectionQueue(long timeout2, long maxConnectionLifeTimeInMs2) {
                this.timeout = timeout2;
                this.maxConnectionLifeTimeInMs = maxConnectionLifeTimeInMs2;
            }

            /* access modifiers changed from: 0000 */
            public void offer(Connection c) {
                long timeoutMs = -1;
                long currentTime = DateUtil.millisTime();
                if (this.maxConnectionLifeTimeInMs < 0 && this.timeout >= 0) {
                    timeoutMs = currentTime + this.timeout;
                } else if (this.maxConnectionLifeTimeInMs >= 0) {
                    long t = this.resolver.getTimeoutMs(c);
                    if (t == -1) {
                        timeoutMs = this.timeout >= 0 ? currentTime + Math.min(this.maxConnectionLifeTimeInMs, this.timeout) : currentTime + this.maxConnectionLifeTimeInMs;
                    } else if (this.timeout >= 0) {
                        timeoutMs = Math.min(t, this.timeout + currentTime);
                    }
                }
                this.resolver.setTimeoutMs(c, timeoutMs);
                this.queue.offer(c);
                this.count.incrementAndGet();
            }

            /* access modifiers changed from: 0000 */
            public Connection poll() {
                this.count.decrementAndGet();
                return this.queue.poll();
            }

            /* access modifiers changed from: 0000 */
            public boolean remove(Connection c) {
                if (this.timeout >= 0) {
                    this.resolver.removeTimeout(c);
                }
                this.count.decrementAndGet();
                return this.queue.remove(c);
            }

            /* access modifiers changed from: 0000 */
            public int size() {
                return this.count.get();
            }

            /* access modifiers changed from: 0000 */
            public boolean isEmpty() {
                return this.count.get() == 0;
            }

            /* access modifiers changed from: 0000 */
            public void destroy() {
                Iterator i$ = this.queue.iterator();
                while (i$.hasNext()) {
                    i$.next().close();
                }
                this.queue.clear();
                DelayedExecutor.this.queues.remove(this);
            }
        }

        static final class TimeoutResolver {
            private static final Attribute<IdleRecord> IDLE_ATTR = Grizzly.DEFAULT_ATTRIBUTE_BUILDER.createAttribute(IDLE_ATTRIBUTE_NAME, new NullaryFunction<IdleRecord>() {
                public IdleRecord evaluate() {
                    return new IdleRecord();
                }
            });
            private static final String IDLE_ATTRIBUTE_NAME = "grizzly-ahc-conn-pool-idle-attribute";

            static final class IdleRecord {
                volatile long timeoutMs = -1;

                IdleRecord() {
                }
            }

            TimeoutResolver() {
            }

            /* access modifiers changed from: 0000 */
            public boolean removeTimeout(Connection c) {
                ((IdleRecord) IDLE_ATTR.get(c)).timeoutMs = 0;
                return true;
            }

            /* access modifiers changed from: 0000 */
            public long getTimeoutMs(Connection c) {
                return ((IdleRecord) IDLE_ATTR.get(c)).timeoutMs;
            }

            /* access modifiers changed from: 0000 */
            public void setTimeoutMs(Connection c, long timeoutMs) {
                ((IdleRecord) IDLE_ATTR.get(c)).timeoutMs = timeoutMs;
            }
        }

        public DelayedExecutor(ExecutorService threadPool2, GrizzlyConnectionsPool connectionsPool) {
            this(threadPool2, 1000, TimeUnit.MILLISECONDS, connectionsPool);
        }

        public DelayedExecutor(ExecutorService threadPool2, long checkInterval, TimeUnit timeunit, GrizzlyConnectionsPool connectionsPool) {
            this.runnable = new DelayedRunnable();
            this.queues = DataStructures.getLTQInstance(IdleConnectionQueue.class);
            this.sync = new Object();
            this.threadPool = threadPool2;
            this.checkIntervalMs = TimeUnit.MILLISECONDS.convert(checkInterval, timeunit);
            this.totalCachedConnections = connectionsPool.totalCachedConnections;
        }

        /* access modifiers changed from: private */
        public void start() {
            synchronized (this.sync) {
                if (!this.isStarted) {
                    this.isStarted = true;
                    this.threadPool.execute(this.runnable);
                }
            }
        }

        /* access modifiers changed from: private */
        public void stop() {
            synchronized (this.sync) {
                if (this.isStarted) {
                    this.isStarted = false;
                    this.sync.notify();
                }
            }
        }

        /* access modifiers changed from: private */
        public ExecutorService getThreadPool() {
            return this.threadPool;
        }

        /* access modifiers changed from: private */
        public IdleConnectionQueue createIdleConnectionQueue(long timeout, long maxConnectionLifeTimeInMs) {
            IdleConnectionQueue queue = new IdleConnectionQueue(timeout, maxConnectionLifeTimeInMs);
            this.queues.add(queue);
            return queue;
        }

        /* access modifiers changed from: private */
        public static boolean wasModified(long l1, long l2) {
            return l1 != l2;
        }
    }

    public GrizzlyConnectionsPool(boolean cacheSSLConnections2, int timeout2, int maxConnectionLifeTimeInMs2, int maxConnectionsPerHost2, int maxConnections2, DelayedExecutor delayedExecutor2) {
        this.cacheSSLConnections = cacheSSLConnections2;
        this.timeout = (long) timeout2;
        this.maxConnectionLifeTimeInMs = (long) maxConnectionLifeTimeInMs2;
        this.maxConnectionsPerHost = maxConnectionsPerHost2;
        this.maxConnections = maxConnections2;
        this.unlimitedConnections = maxConnections2 == -1;
        if (delayedExecutor2 != null) {
            this.delayedExecutor = delayedExecutor2;
            this.ownsDelayedExecutor = false;
        } else {
            this.delayedExecutor = new DelayedExecutor(Executors.newSingleThreadExecutor(), this);
            this.ownsDelayedExecutor = true;
        }
        if (!this.delayedExecutor.isStarted) {
            this.delayedExecutor.start();
        }
    }

    public GrizzlyConnectionsPool(AsyncHttpClientConfig config) {
        boolean z = false;
        this.cacheSSLConnections = config.isSslConnectionPoolEnabled();
        this.timeout = (long) config.getIdleConnectionInPoolTimeoutInMs();
        this.maxConnectionLifeTimeInMs = (long) config.getMaxConnectionLifeTimeInMs();
        this.maxConnectionsPerHost = config.getMaxConnectionPerHost();
        this.maxConnections = config.getMaxTotalConnections();
        this.unlimitedConnections = this.maxConnections == -1 ? true : z;
        this.delayedExecutor = new DelayedExecutor(Executors.newSingleThreadExecutor(), this);
        this.delayedExecutor.start();
        this.ownsDelayedExecutor = true;
    }

    public boolean offer(String uri, Connection connection) {
        if (isSecure(uri) && !this.cacheSSLConnections) {
            return false;
        }
        IdleConnectionQueue conQueue = this.connectionsPool.get(uri);
        if (conQueue == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug((String) "Creating new Connection queue for uri [{}] and connection [{}]", uri, connection);
            }
            IdleConnectionQueue newPool = this.delayedExecutor.createIdleConnectionQueue(this.timeout, this.maxConnectionLifeTimeInMs);
            conQueue = this.connectionsPool.putIfAbsent(uri, newPool);
            if (conQueue == null) {
                conQueue = newPool;
            }
        }
        int size = conQueue.size();
        if (this.maxConnectionsPerHost == -1 || size < this.maxConnectionsPerHost) {
            conQueue.offer(connection);
            connection.addCloseListener(this.listener);
            int total = this.totalCachedConnections.incrementAndGet();
            if (LOG.isDebugEnabled()) {
                LOG.debug((String) "[offer] Pooling connection [{}] for uri [{}].  Current size (for host; before pooling): [{}].  Max size (for host): [{}].  Total number of cached connections: [{}].", connection, uri, Integer.valueOf(size), Integer.valueOf(this.maxConnectionsPerHost), Integer.valueOf(total));
            }
            return true;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug((String) "[offer] Unable to pool connection [{}] for uri [{}]. Current size (for host): [{}].  Max size (for host): [{}].  Total number of cached connections: [{}].", connection, uri, Integer.valueOf(size), Integer.valueOf(this.maxConnectionsPerHost), Integer.valueOf(this.totalCachedConnections.get()));
        }
        return false;
    }

    public Connection poll(String uri) {
        if (!this.cacheSSLConnections && isSecure(uri)) {
            return null;
        }
        Connection connection = null;
        IdleConnectionQueue conQueue = this.connectionsPool.get(uri);
        if (conQueue != null) {
            boolean poolEmpty = false;
            while (!poolEmpty && connection == null) {
                if (!conQueue.isEmpty()) {
                    connection = conQueue.poll();
                }
                if (connection == null) {
                    poolEmpty = true;
                } else if (!connection.isOpen()) {
                    removeAll(connection);
                    connection = null;
                }
            }
        } else if (LOG.isDebugEnabled()) {
            LOG.debug((String) "[poll] No existing queue for uri [{}].", uri);
        }
        if (connection == null) {
            return connection;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug((String) "[poll] Found pooled connection [{}] for uri [{}].", connection, uri);
        }
        this.totalCachedConnections.decrementAndGet();
        connection.removeCloseListener(this.listener);
        return connection;
    }

    public boolean removeAll(Connection connection) {
        if (connection == null || this.closed.get()) {
            return false;
        }
        connection.removeCloseListener(this.listener);
        boolean isRemoved = false;
        for (Entry<String, IdleConnectionQueue> entry : this.connectionsPool.entrySet()) {
            isRemoved |= entry.getValue().remove(connection);
        }
        if (!isRemoved) {
            return isRemoved;
        }
        this.totalCachedConnections.decrementAndGet();
        return isRemoved;
    }

    public boolean canCacheConnection() {
        return this.closed.get() || this.unlimitedConnections || this.totalCachedConnections.get() < this.maxConnections;
    }

    public void destroy() {
        if (!this.closed.getAndSet(true)) {
            for (Entry<String, IdleConnectionQueue> entry : this.connectionsPool.entrySet()) {
                entry.getValue().destroy();
            }
            this.connectionsPool.clear();
            if (this.ownsDelayedExecutor) {
                this.delayedExecutor.stop();
                this.delayedExecutor.getThreadPool().shutdownNow();
            }
        }
    }

    private boolean isSecure(String uri) {
        return uri.startsWith(CommonProtocol.URL_SCHEME) || uri.startsWith("wss");
    }
}