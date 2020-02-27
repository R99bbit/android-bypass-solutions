package com.ning.http.client;

public interface ConnectionsPool<U, V> {
    boolean canCacheConnection();

    void destroy();

    boolean offer(U u, V v);

    V poll(U u);

    boolean removeAll(V v);
}