package com.ning.http.client.extra;

import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.filter.FilterContext;
import com.ning.http.client.filter.FilterContext.FilterContextBuilder;
import com.ning.http.client.filter.FilterException;
import com.ning.http.client.filter.RequestFilter;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ThrottleRequestFilter implements RequestFilter {
    /* access modifiers changed from: private */
    public static final Logger logger = LoggerFactory.getLogger(ThrottleRequestFilter.class);
    /* access modifiers changed from: private */
    public final Semaphore available;
    private final int maxConnections;
    private final int maxWait;

    private class AsyncHandlerWrapper<T> implements AsyncHandler {
        private final AsyncHandler<T> asyncHandler;

        public AsyncHandlerWrapper(AsyncHandler<T> asyncHandler2) {
            this.asyncHandler = asyncHandler2;
        }

        public void onThrowable(Throwable t) {
            try {
                this.asyncHandler.onThrowable(t);
            } finally {
                ThrottleRequestFilter.this.available.release();
                if (ThrottleRequestFilter.logger.isDebugEnabled()) {
                    r2 = "Current Throttling Status after onThrowable {}";
                    ThrottleRequestFilter.logger.debug(r2, (Object) Integer.valueOf(ThrottleRequestFilter.this.available.availablePermits()));
                }
            }
        }

        public STATE onBodyPartReceived(HttpResponseBodyPart bodyPart) throws Exception {
            return this.asyncHandler.onBodyPartReceived(bodyPart);
        }

        public STATE onStatusReceived(HttpResponseStatus responseStatus) throws Exception {
            return this.asyncHandler.onStatusReceived(responseStatus);
        }

        public STATE onHeadersReceived(HttpResponseHeaders headers) throws Exception {
            return this.asyncHandler.onHeadersReceived(headers);
        }

        public T onCompleted() throws Exception {
            ThrottleRequestFilter.this.available.release();
            if (ThrottleRequestFilter.logger.isDebugEnabled()) {
                ThrottleRequestFilter.logger.debug((String) "Current Throttling Status {}", (Object) Integer.valueOf(ThrottleRequestFilter.this.available.availablePermits()));
            }
            return this.asyncHandler.onCompleted();
        }
    }

    public ThrottleRequestFilter(int maxConnections2) {
        this.maxConnections = maxConnections2;
        this.maxWait = ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        this.available = new Semaphore(maxConnections2, true);
    }

    public ThrottleRequestFilter(int maxConnections2, int maxWait2) {
        this.maxConnections = maxConnections2;
        this.maxWait = maxWait2;
        this.available = new Semaphore(maxConnections2, true);
    }

    public FilterContext filter(FilterContext ctx) throws FilterException {
        try {
            if (logger.isDebugEnabled()) {
                logger.debug((String) "Current Throttling Status {}", (Object) Integer.valueOf(this.available.availablePermits()));
            }
            if (this.available.tryAcquire((long) this.maxWait, TimeUnit.MILLISECONDS)) {
                return new FilterContextBuilder(ctx).asyncHandler(new AsyncHandlerWrapper(ctx.getAsyncHandler())).build();
            }
            throw new FilterException(String.format("No slot available for processing Request %s with AsyncHandler %s", new Object[]{ctx.getRequest(), ctx.getAsyncHandler()}));
        } catch (InterruptedException e) {
            throw new FilterException(String.format("Interrupted Request %s with AsyncHandler %s", new Object[]{ctx.getRequest(), ctx.getAsyncHandler()}));
        }
    }
}