package com.ning.http.client.providers.grizzly;

import com.ning.http.client.AsyncHandler;
import com.ning.http.client.ProxyServer;
import com.ning.http.client.Request;
import com.ning.http.client.listenable.AbstractListenableFuture;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.impl.FutureImpl;

public class GrizzlyResponseFuture<V> extends AbstractListenableFuture<V> {
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private Connection connection;
    FutureImpl<V> delegate;
    private final AtomicBoolean done = new AtomicBoolean(false);
    private final AsyncHandler handler;
    private final GrizzlyAsyncHttpProvider provider;
    private final ProxyServer proxy;
    private final Request request;

    GrizzlyResponseFuture(GrizzlyAsyncHttpProvider provider2, Request request2, AsyncHandler handler2, ProxyServer proxy2) {
        this.provider = provider2;
        this.request = request2;
        this.handler = handler2;
        this.proxy = proxy2;
    }

    public void done() {
        if (this.done.compareAndSet(false, true) && !this.cancelled.get()) {
            runListeners();
        }
    }

    public void abort(Throwable t) {
        if (!this.done.get() && this.cancelled.compareAndSet(false, true)) {
            this.delegate.failure(t);
            if (this.handler != null) {
                try {
                    this.handler.onThrowable(t);
                } catch (Throwable th) {
                }
            }
            closeConnection();
            runListeners();
        }
    }

    public void content(V v) {
        this.delegate.result(v);
    }

    public void touch() {
        this.provider.touchConnection(this.connection, this.request);
    }

    public boolean getAndSetWriteHeaders(boolean writeHeaders) {
        return writeHeaders;
    }

    public boolean getAndSetWriteBody(boolean writeBody) {
        return writeBody;
    }

    public boolean cancel(boolean mayInterruptIfRunning) {
        if (this.done.get() || !this.cancelled.compareAndSet(false, true)) {
            return false;
        }
        if (this.handler != null) {
            try {
                this.handler.onThrowable(new CancellationException());
            } catch (Throwable th) {
            }
        }
        runListeners();
        return this.delegate.cancel(mayInterruptIfRunning);
    }

    public boolean isCancelled() {
        return this.delegate.isCancelled();
    }

    public boolean isDone() {
        return this.delegate.isDone();
    }

    public V get() throws InterruptedException, ExecutionException {
        return this.delegate.get();
    }

    public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        if (!this.delegate.isCancelled() || !this.delegate.isDone()) {
            return this.delegate.get(timeout, unit);
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public void setConnection(Connection connection2) {
        this.connection = connection2;
    }

    /* access modifiers changed from: 0000 */
    public void setDelegate(FutureImpl<V> delegate2) {
        this.delegate = delegate2;
    }

    private void closeConnection() {
        if (this.connection != null && this.connection.isOpen()) {
            this.connection.close().markForRecycle(true);
        }
    }

    public ProxyServer getProxy() {
        return this.proxy;
    }
}