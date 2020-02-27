package com.ning.http.client;

import java.util.concurrent.Executor;
import java.util.concurrent.Future;

public interface ListenableFuture<V> extends Future<V> {
    void abort(Throwable th);

    ListenableFuture<V> addListener(Runnable runnable, Executor executor);

    void content(V v);

    void done();

    boolean getAndSetWriteBody(boolean z);

    boolean getAndSetWriteHeaders(boolean z);

    void touch();
}