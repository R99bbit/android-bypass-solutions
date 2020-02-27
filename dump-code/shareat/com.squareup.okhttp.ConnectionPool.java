package com.squareup.okhttp;

import com.squareup.okhttp.internal.Platform;
import com.squareup.okhttp.internal.Util;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public final class ConnectionPool {
    private static final long DEFAULT_KEEP_ALIVE_DURATION_MS = 300000;
    private static final ConnectionPool systemDefault;
    private final LinkedList<Connection> connections = new LinkedList<>();
    private final Runnable connectionsCleanupRunnable = new Runnable() {
        public void run() {
            ConnectionPool.this.runCleanupUntilPoolIsEmpty();
        }
    };
    private Executor executor = new ThreadPoolExecutor(0, 1, 60, TimeUnit.SECONDS, new LinkedBlockingQueue(), Util.threadFactory("OkHttp ConnectionPool", true));
    private final long keepAliveDurationNs;
    private final int maxIdleConnections;

    static {
        String keepAlive = System.getProperty("http.keepAlive");
        String keepAliveDuration = System.getProperty("http.keepAliveDuration");
        String maxIdleConnections2 = System.getProperty("http.maxConnections");
        long keepAliveDurationMs = keepAliveDuration != null ? Long.parseLong(keepAliveDuration) : DEFAULT_KEEP_ALIVE_DURATION_MS;
        if (keepAlive != null && !Boolean.parseBoolean(keepAlive)) {
            systemDefault = new ConnectionPool(0, keepAliveDurationMs);
        } else if (maxIdleConnections2 != null) {
            systemDefault = new ConnectionPool(Integer.parseInt(maxIdleConnections2), keepAliveDurationMs);
        } else {
            systemDefault = new ConnectionPool(5, keepAliveDurationMs);
        }
    }

    public ConnectionPool(int maxIdleConnections2, long keepAliveDurationMs) {
        this.maxIdleConnections = maxIdleConnections2;
        this.keepAliveDurationNs = keepAliveDurationMs * 1000 * 1000;
    }

    public static ConnectionPool getDefault() {
        return systemDefault;
    }

    public synchronized int getConnectionCount() {
        return this.connections.size();
    }

    @Deprecated
    public synchronized int getSpdyConnectionCount() {
        return getMultiplexedConnectionCount();
    }

    public synchronized int getMultiplexedConnectionCount() {
        int total;
        total = 0;
        Iterator it = this.connections.iterator();
        while (it.hasNext()) {
            if (((Connection) it.next()).isSpdy()) {
                total++;
            }
        }
        return total;
    }

    public synchronized int getHttpConnectionCount() {
        return this.connections.size() - getMultiplexedConnectionCount();
    }

    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0051, code lost:
        r2 = r0;
     */
    public synchronized Connection get(Address address) {
        Connection foundConnection;
        foundConnection = null;
        ListIterator<Connection> listIterator = this.connections.listIterator(this.connections.size());
        while (true) {
            if (!listIterator.hasPrevious()) {
                break;
            }
            Connection connection = listIterator.previous();
            if (connection.getRoute().getAddress().equals(address) && connection.isAlive() && System.nanoTime() - connection.getIdleStartTimeNs() < this.keepAliveDurationNs) {
                listIterator.remove();
                if (connection.isSpdy()) {
                    break;
                }
                try {
                    Platform.get().tagSocket(connection.getSocket());
                    break;
                } catch (SocketException e) {
                    Util.closeQuietly(connection.getSocket());
                    Platform.get().logW("Unable to tagSocket(): " + e);
                }
            }
        }
        if (foundConnection != null) {
            if (foundConnection.isSpdy()) {
                this.connections.addFirst(foundConnection);
            }
        }
        return foundConnection;
    }

    /* access modifiers changed from: 0000 */
    public void recycle(Connection connection) {
        if (connection.isSpdy() || !connection.clearOwner()) {
            return;
        }
        if (!connection.isAlive()) {
            Util.closeQuietly(connection.getSocket());
            return;
        }
        try {
            Platform.get().untagSocket(connection.getSocket());
            synchronized (this) {
                addConnection(connection);
                connection.incrementRecycleCount();
                connection.resetIdleStartTime();
            }
        } catch (SocketException e) {
            Platform.get().logW("Unable to untagSocket(): " + e);
            Util.closeQuietly(connection.getSocket());
        }
    }

    private void addConnection(Connection connection) {
        boolean empty = this.connections.isEmpty();
        this.connections.addFirst(connection);
        if (empty) {
            this.executor.execute(this.connectionsCleanupRunnable);
        } else {
            notifyAll();
        }
    }

    /* access modifiers changed from: 0000 */
    public void share(Connection connection) {
        if (!connection.isSpdy()) {
            throw new IllegalArgumentException();
        } else if (connection.isAlive()) {
            synchronized (this) {
                addConnection(connection);
            }
        }
    }

    public void evictAll() {
        List<Connection> toEvict;
        synchronized (this) {
            toEvict = new ArrayList<>(this.connections);
            this.connections.clear();
            notifyAll();
        }
        int size = toEvict.size();
        for (int i = 0; i < size; i++) {
            Util.closeQuietly(toEvict.get(i).getSocket());
        }
    }

    /* access modifiers changed from: private */
    public void runCleanupUntilPoolIsEmpty() {
        do {
        } while (performCleanup());
    }

    /* access modifiers changed from: 0000 */
    /* JADX WARNING: No exception handlers in catch block: Catch:{  } */
    public boolean performCleanup() {
        synchronized (this) {
            if (this.connections.isEmpty()) {
                return false;
            }
            List<Connection> evictableConnections = new ArrayList<>();
            int idleConnectionCount = 0;
            long now = System.nanoTime();
            long nanosUntilNextEviction = this.keepAliveDurationNs;
            ListIterator<Connection> listIterator = this.connections.listIterator(this.connections.size());
            while (listIterator.hasPrevious()) {
                Connection connection = listIterator.previous();
                long nanosUntilEviction = (connection.getIdleStartTimeNs() + this.keepAliveDurationNs) - now;
                if (nanosUntilEviction <= 0 || !connection.isAlive()) {
                    listIterator.remove();
                    evictableConnections.add(connection);
                } else if (connection.isIdle()) {
                    idleConnectionCount++;
                    nanosUntilNextEviction = Math.min(nanosUntilNextEviction, nanosUntilEviction);
                }
            }
            ListIterator<Connection> listIterator2 = this.connections.listIterator(this.connections.size());
            while (listIterator2.hasPrevious() && idleConnectionCount > this.maxIdleConnections) {
                Connection connection2 = listIterator2.previous();
                if (connection2.isIdle()) {
                    evictableConnections.add(connection2);
                    listIterator2.remove();
                    idleConnectionCount--;
                }
            }
            if (evictableConnections.isEmpty()) {
                try {
                    long millisUntilNextEviction = nanosUntilNextEviction / 1000000;
                    wait(millisUntilNextEviction, (int) (nanosUntilNextEviction - (1000000 * millisUntilNextEviction)));
                    return true;
                } catch (InterruptedException e) {
                    int size = evictableConnections.size();
                    for (int i = 0; i < size; i++) {
                        Util.closeQuietly(evictableConnections.get(i).getSocket());
                    }
                    return true;
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void replaceCleanupExecutorForTests(Executor cleanupExecutor) {
        this.executor = cleanupExecutor;
    }

    /* access modifiers changed from: 0000 */
    public synchronized List<Connection> getConnections() {
        return new ArrayList(this.connections);
    }
}