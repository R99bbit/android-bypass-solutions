package com.ning.http.client.providers.jdk;

import com.ning.http.client.AsyncHandler;
import com.ning.http.client.ListenableFuture;
import com.ning.http.util.DateUtil;
import java.net.HttpURLConnection;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class JDKDelegateFuture<V> extends JDKFuture<V> {
    private final ListenableFuture<V> delegateFuture;

    public JDKDelegateFuture(AsyncHandler<V> asyncHandler, int responseTimeoutInMs, ListenableFuture<V> delegateFuture2, HttpURLConnection urlConnection) {
        super(asyncHandler, responseTimeoutInMs, urlConnection);
        this.delegateFuture = delegateFuture2;
    }

    public void done() {
        this.delegateFuture.done();
        super.done();
    }

    public void abort(Throwable t) {
        if (this.innerFuture != null) {
            this.innerFuture.cancel(true);
        }
        this.delegateFuture.abort(t);
    }

    public boolean cancel(boolean mayInterruptIfRunning) {
        this.delegateFuture.cancel(mayInterruptIfRunning);
        if (this.innerFuture != null) {
            return this.innerFuture.cancel(mayInterruptIfRunning);
        }
        return false;
    }

    public boolean isCancelled() {
        if (this.innerFuture != null) {
            return this.innerFuture.isCancelled();
        }
        return false;
    }

    public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        V content = null;
        try {
            if (this.innerFuture != null) {
                content = this.innerFuture.get(timeout, unit);
            }
        } catch (Throwable t) {
            if (!this.contentProcessed.get() && timeout != -1 && DateUtil.millisTime() - this.touch.get() <= ((long) this.responseTimeoutInMs)) {
                return get(timeout, unit);
            }
            this.timedOut.set(true);
            this.delegateFuture.abort(t);
        }
        if (this.exception.get() != null) {
            this.delegateFuture.abort(new ExecutionException((Throwable) this.exception.get()));
        }
        this.delegateFuture.content(content);
        this.delegateFuture.done();
        return content;
    }
}