package com.ning.http.client.extra;

import com.google.common.util.concurrent.ListenableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class ListenableFutureAdapter {
    public static <V> ListenableFuture<V> asGuavaFuture(final com.ning.http.client.ListenableFuture<V> future) {
        return new ListenableFuture<V>() {
            public boolean cancel(boolean mayInterruptIfRunning) {
                return future.cancel(mayInterruptIfRunning);
            }

            public V get() throws InterruptedException, ExecutionException {
                return future.get();
            }

            public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
                return future.get(timeout, unit);
            }

            public boolean isCancelled() {
                return future.isCancelled();
            }

            public boolean isDone() {
                return future.isDone();
            }

            public void addListener(Runnable runnable, Executor executor) {
                future.addListener(runnable, executor);
            }
        };
    }
}