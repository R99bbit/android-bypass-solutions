package com.ning.http.client.providers.apache;

import com.ning.http.client.AsyncHandler;
import com.ning.http.client.Request;
import com.ning.http.client.listenable.AbstractListenableFuture;
import com.ning.http.util.DateUtil;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.commons.httpclient.HttpMethodBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ApacheResponseFuture<V> extends AbstractListenableFuture<V> {
    private static final Logger logger = LoggerFactory.getLogger(ApacheResponseFuture.class);
    private final AsyncHandler<V> asyncHandler;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final AtomicBoolean contentProcessed = new AtomicBoolean(false);
    private final AtomicReference<Throwable> exception = new AtomicReference<>();
    private Future<V> innerFuture;
    private final AtomicBoolean isDone = new AtomicBoolean(false);
    private final HttpMethodBase method;
    private Future<?> reaperFuture;
    private final Request request;
    private final int responseTimeoutInMs;
    private final AtomicBoolean timedOut = new AtomicBoolean(false);
    private final AtomicLong touch = new AtomicLong(DateUtil.millisTime());
    private boolean writeBody;
    private boolean writeHeaders;

    public ApacheResponseFuture(AsyncHandler<V> asyncHandler2, int responseTimeoutInMs2, Request request2, HttpMethodBase method2) {
        this.asyncHandler = asyncHandler2;
        this.responseTimeoutInMs = responseTimeoutInMs2 == -1 ? ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED : responseTimeoutInMs2;
        this.request = request2;
        this.method = method2;
        this.writeHeaders = true;
        this.writeBody = true;
    }

    /* access modifiers changed from: protected */
    public void setInnerFuture(Future<V> innerFuture2) {
        this.innerFuture = innerFuture2;
    }

    public void done() {
        this.isDone.set(true);
        if (this.reaperFuture != null) {
            this.reaperFuture.cancel(true);
        }
        runListeners();
    }

    public void content(V v) {
    }

    /* access modifiers changed from: protected */
    public void setReaperFuture(Future<?> reaperFuture2) {
        if (this.reaperFuture != null) {
            this.reaperFuture.cancel(true);
        }
        this.reaperFuture = reaperFuture2;
    }

    public String toString() {
        return "ApacheResponseFuture{innerFuture=" + this.innerFuture + ", asyncHandler=" + this.asyncHandler + ", responseTimeoutInMs=" + this.responseTimeoutInMs + ", cancelled=" + this.cancelled + ", timedOut=" + this.timedOut + ", isDone=" + this.isDone + ", exception=" + this.exception + ", touch=" + this.touch + ", contentProcessed=" + this.contentProcessed + ", request=" + this.request + ", method=" + this.method + ", reaperFuture=" + this.reaperFuture + '}';
    }

    public void abort(Throwable t) {
        this.exception.set(t);
        if (this.innerFuture != null) {
            this.innerFuture.cancel(true);
        }
        if (this.method != null) {
            this.method.abort();
        }
        if (this.reaperFuture != null) {
            this.reaperFuture.cancel(true);
        }
        if (!this.timedOut.get() && !this.cancelled.get()) {
            try {
                this.asyncHandler.onThrowable(t);
            } catch (Throwable t2) {
                logger.debug((String) "asyncHandler.onThrowable", t2);
            }
        }
        runListeners();
    }

    public boolean cancel(boolean mayInterruptIfRunning) {
        if (this.cancelled.get() || this.innerFuture == null) {
            runListeners();
            return false;
        }
        this.method.abort();
        try {
            this.asyncHandler.onThrowable(new CancellationException());
        } catch (Throwable t) {
            logger.debug((String) "asyncHandler.onThrowable", t);
        }
        this.cancelled.set(true);
        if (this.reaperFuture != null) {
            this.reaperFuture.cancel(true);
        }
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
        return this.responseTimeoutInMs != -1 && DateUtil.millisTime() - this.touch.get() >= ((long) this.responseTimeoutInMs);
    }

    public void touch() {
        this.touch.set(DateUtil.millisTime());
    }

    public Request getRequest() {
        return this.request;
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