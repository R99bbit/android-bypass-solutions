package com.ning.http.client.providers.jdk;

import com.ning.http.client.AsyncHandler;
import com.ning.http.client.listenable.AbstractListenableFuture;
import com.ning.http.util.DateUtil;
import java.net.HttpURLConnection;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JDKFuture<V> extends AbstractListenableFuture<V> {
    private static final Logger logger = LoggerFactory.getLogger(JDKFuture.class);
    protected final AsyncHandler<V> asyncHandler;
    protected final AtomicBoolean cancelled = new AtomicBoolean(false);
    protected final AtomicBoolean contentProcessed = new AtomicBoolean(false);
    protected final AtomicReference<Throwable> exception = new AtomicReference<>();
    protected Future<V> innerFuture;
    protected final AtomicBoolean isDone = new AtomicBoolean(false);
    protected final int responseTimeoutInMs;
    protected final AtomicBoolean timedOut = new AtomicBoolean(false);
    protected final AtomicLong touch = new AtomicLong(DateUtil.millisTime());
    protected final HttpURLConnection urlConnection;
    private boolean writeBody;
    private boolean writeHeaders;

    public JDKFuture(AsyncHandler<V> asyncHandler2, int responseTimeoutInMs2, HttpURLConnection urlConnection2) {
        this.asyncHandler = asyncHandler2;
        this.responseTimeoutInMs = responseTimeoutInMs2;
        this.urlConnection = urlConnection2;
        this.writeHeaders = true;
        this.writeBody = true;
    }

    /* access modifiers changed from: protected */
    public void setInnerFuture(Future<V> innerFuture2) {
        this.innerFuture = innerFuture2;
    }

    public void done() {
        this.isDone.set(true);
        runListeners();
    }

    public void abort(Throwable t) {
        this.exception.set(t);
        if (this.innerFuture != null) {
            this.innerFuture.cancel(true);
        }
        if (!this.timedOut.get() && !this.cancelled.get()) {
            try {
                this.asyncHandler.onThrowable(t);
            } catch (Throwable te) {
                logger.debug((String) "asyncHandler.onThrowable", te);
            }
        }
        runListeners();
    }

    public void content(V v) {
    }

    public boolean cancel(boolean mayInterruptIfRunning) {
        if (this.cancelled.get() || this.innerFuture == null) {
            runListeners();
            return false;
        }
        this.urlConnection.disconnect();
        try {
            this.asyncHandler.onThrowable(new CancellationException());
        } catch (Throwable te) {
            logger.debug((String) "asyncHandler.onThrowable", te);
        }
        this.cancelled.set(true);
        runListeners();
        return this.innerFuture.cancel(mayInterruptIfRunning);
    }

    public boolean isCancelled() {
        if (this.innerFuture != null) {
            return this.innerFuture.isCancelled();
        }
        return false;
    }

    public boolean isDone() {
        this.contentProcessed.set(true);
        return this.innerFuture.isDone();
    }

    public V get() throws InterruptedException, ExecutionException {
        try {
            return get((long) this.responseTimeoutInMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            throw new ExecutionException(e);
        }
    }

    public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        V content = null;
        try {
            if (this.innerFuture != null) {
                content = this.innerFuture.get(timeout, unit);
            }
        } catch (TimeoutException e) {
            if (!this.contentProcessed.get() && timeout != -1 && DateUtil.millisTime() - this.touch.get() <= ((long) this.responseTimeoutInMs)) {
                return get(timeout, unit);
            }
            if (this.exception.get() == null) {
                this.timedOut.set(true);
                throw new ExecutionException(new TimeoutException(String.format("No response received after %s", new Object[]{Integer.valueOf(this.responseTimeoutInMs)})));
            }
        } catch (CancellationException e2) {
        }
        if (this.exception.get() == null) {
            return content;
        }
        throw new ExecutionException(this.exception.get());
    }

    public boolean hasExpired() {
        return this.responseTimeoutInMs != -1 && DateUtil.millisTime() - this.touch.get() > ((long) this.responseTimeoutInMs);
    }

    public void touch() {
        this.touch.set(DateUtil.millisTime());
    }

    public boolean getAndSetWriteHeaders(boolean writeHeaders2) {
        boolean b = this.writeHeaders;
        this.writeHeaders = writeHeaders2;
        return b;
    }

    public boolean getAndSetWriteBody(boolean writeBody2) {
        boolean b = this.writeBody;
        this.writeBody = writeBody2;
        return b;
    }
}