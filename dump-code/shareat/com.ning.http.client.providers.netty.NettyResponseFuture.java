package com.ning.http.client.providers.netty;

import com.kakao.util.helper.CommonProtocol;
import com.ning.http.client.AsyncHandler;
import com.ning.http.client.ConnectionPoolKeyStrategy;
import com.ning.http.client.ProxyServer;
import com.ning.http.client.Request;
import com.ning.http.client.listenable.AbstractListenableFuture;
import com.ning.http.client.providers.netty.timeout.TimeoutsHolder;
import com.ning.http.util.DateUtil;
import java.net.URI;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class NettyResponseFuture<V> extends AbstractListenableFuture<V> {
    public static final String MAX_RETRY = "com.ning.http.client.providers.netty.maxRetry";
    private static final Logger logger = LoggerFactory.getLogger(NettyResponseFuture.class);
    private boolean allowConnect = false;
    private AsyncHandler<V> asyncHandler;
    private final NettyAsyncHttpProvider asyncHttpProvider;
    private Channel channel;
    private final ConnectionPoolKeyStrategy connectionPoolKeyStrategy;
    private final AtomicReference<V> content = new AtomicReference<>();
    private final AtomicBoolean contentProcessed = new AtomicBoolean(false);
    private final AtomicInteger currentRetry = new AtomicInteger(0);
    private final AtomicReference<ExecutionException> exEx = new AtomicReference<>();
    private HttpResponse httpResponse;
    private final int idleConnectionTimeoutInMs;
    private volatile boolean idleConnectionTimeoutReached;
    private final AtomicBoolean inAuth = new AtomicBoolean(false);
    private final AtomicBoolean isCancelled = new AtomicBoolean(false);
    private final AtomicBoolean isDone = new AtomicBoolean(false);
    private boolean keepAlive = true;
    private final CountDownLatch latch = new CountDownLatch(1);
    private final int maxRetry;
    private HttpRequest nettyRequest;
    private final AtomicBoolean onThrowableCalled = new AtomicBoolean(false);
    private final ProxyServer proxyServer;
    private final AtomicInteger redirectCount = new AtomicInteger();
    private Request request;
    private final int requestTimeoutInMs;
    private volatile boolean requestTimeoutReached;
    private boolean reuseChannel = false;
    private final long start = DateUtil.millisTime();
    private final AtomicReference<STATE> state = new AtomicReference<>(STATE.NEW);
    private final AtomicBoolean statusReceived = new AtomicBoolean(false);
    private volatile TimeoutsHolder timeoutsHolder;
    private final AtomicLong touch = new AtomicLong(DateUtil.millisTime());
    private URI uri;
    private boolean writeBody;
    private boolean writeHeaders;

    enum STATE {
        NEW,
        POOLED,
        RECONNECTED,
        CLOSED
    }

    public NettyResponseFuture(URI uri2, Request request2, AsyncHandler<V> asyncHandler2, HttpRequest nettyRequest2, int requestTimeoutInMs2, int idleConnectionTimeoutInMs2, NettyAsyncHttpProvider asyncHttpProvider2, ConnectionPoolKeyStrategy connectionPoolKeyStrategy2, ProxyServer proxyServer2) {
        this.asyncHandler = asyncHandler2;
        this.requestTimeoutInMs = requestTimeoutInMs2;
        this.idleConnectionTimeoutInMs = idleConnectionTimeoutInMs2;
        this.request = request2;
        this.nettyRequest = nettyRequest2;
        this.uri = uri2;
        this.asyncHttpProvider = asyncHttpProvider2;
        this.connectionPoolKeyStrategy = connectionPoolKeyStrategy2;
        this.proxyServer = proxyServer2;
        if (System.getProperty(MAX_RETRY) != null) {
            this.maxRetry = Integer.valueOf(System.getProperty(MAX_RETRY)).intValue();
        } else {
            this.maxRetry = asyncHttpProvider2.getConfig().getMaxRequestRetry();
        }
        this.writeHeaders = true;
        this.writeBody = true;
    }

    /* access modifiers changed from: protected */
    public URI getURI() {
        return this.uri;
    }

    /* access modifiers changed from: protected */
    public void setURI(URI uri2) {
        this.uri = uri2;
    }

    public ConnectionPoolKeyStrategy getConnectionPoolKeyStrategy() {
        return this.connectionPoolKeyStrategy;
    }

    public ProxyServer getProxyServer() {
        return this.proxyServer;
    }

    public boolean isDone() {
        return this.isDone.get() || this.isCancelled.get();
    }

    public boolean isCancelled() {
        return this.isCancelled.get();
    }

    /* access modifiers changed from: 0000 */
    public void setAsyncHandler(AsyncHandler<V> asyncHandler2) {
        this.asyncHandler = asyncHandler2;
    }

    public boolean cancel(boolean force) {
        cancelTimeouts();
        if (this.isCancelled.getAndSet(true)) {
            return false;
        }
        try {
            this.channel.getPipeline().getContext(NettyAsyncHttpProvider.class).setAttachment(new DiscardEvent());
            this.channel.close();
        } catch (Throwable th) {
        }
        if (!this.onThrowableCalled.getAndSet(true)) {
            try {
                this.asyncHandler.onThrowable(new CancellationException());
            } catch (Throwable t) {
                logger.warn((String) "cancel", t);
            }
        }
        this.latch.countDown();
        runListeners();
        return true;
    }

    public boolean hasExpired() {
        return this.requestTimeoutReached || this.idleConnectionTimeoutReached;
    }

    public void setRequestTimeoutReached() {
        this.requestTimeoutReached = true;
    }

    public boolean isRequestTimeoutReached() {
        return this.requestTimeoutReached;
    }

    public void setIdleConnectionTimeoutReached() {
        this.idleConnectionTimeoutReached = true;
    }

    public boolean isIdleConnectionTimeoutReached() {
        return this.idleConnectionTimeoutReached;
    }

    public void setTimeoutsHolder(TimeoutsHolder timeoutsHolder2) {
        this.timeoutsHolder = timeoutsHolder2;
    }

    public V get() throws InterruptedException, ExecutionException {
        try {
            return get((long) this.requestTimeoutInMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            cancelTimeouts();
            throw new ExecutionException(e);
        }
    }

    public void cancelTimeouts() {
        if (this.timeoutsHolder != null) {
            this.timeoutsHolder.cancel();
            this.timeoutsHolder = null;
        }
    }

    public V get(long l, TimeUnit tu) throws InterruptedException, TimeoutException, ExecutionException {
        TimeoutException te;
        if (!isDone() && !isCancelled()) {
            boolean expired = false;
            if (l == -1) {
                this.latch.await();
            } else {
                expired = !this.latch.await(l, tu);
            }
            if (expired) {
                this.isCancelled.set(true);
                try {
                    this.channel.getPipeline().getContext(NettyAsyncHttpProvider.class).setAttachment(new DiscardEvent());
                    this.channel.close();
                } catch (Throwable th) {
                }
                if (!this.onThrowableCalled.getAndSet(true)) {
                    try {
                        te = new TimeoutException(String.format("No response received after %s", new Object[]{Long.valueOf(l)}));
                        this.asyncHandler.onThrowable(te);
                    } catch (Throwable th2) {
                        cancelTimeouts();
                        throw th2;
                    }
                    throw new ExecutionException(te);
                }
            }
            this.isDone.set(true);
            ExecutionException e = this.exEx.getAndSet(null);
            if (e != null) {
                throw e;
            }
        }
        return getContent();
    }

    /* access modifiers changed from: 0000 */
    public V getContent() throws ExecutionException {
        ExecutionException e = this.exEx.getAndSet(null);
        if (e != null) {
            throw e;
        }
        V update = this.content.get();
        this.currentRetry.set(this.maxRetry);
        if (this.exEx.get() == null && !this.contentProcessed.getAndSet(true)) {
            try {
                update = this.asyncHandler.onCompleted();
            } catch (Throwable th) {
                cancelTimeouts();
                throw th;
            }
            this.content.compareAndSet(null, update);
        }
        return update;
        throw new RuntimeException(ex);
    }

    public final void done() {
        Throwable exception;
        cancelTimeouts();
        try {
            if (this.exEx.get() == null) {
                getContent();
                this.isDone.set(true);
                this.latch.countDown();
                runListeners();
            }
        } catch (ExecutionException e) {
        } catch (RuntimeException t) {
            if (t.getCause() != null) {
                exception = t.getCause();
            } else {
                exception = t;
            }
            this.exEx.compareAndSet(null, new ExecutionException(exception));
        } finally {
            this.latch.countDown();
        }
    }

    public final void abort(Throwable t) {
        cancelTimeouts();
        if (!this.isDone.get() && !this.isCancelled.getAndSet(true)) {
            this.isCancelled.set(true);
            this.exEx.compareAndSet(null, new ExecutionException(t));
            if (this.onThrowableCalled.compareAndSet(false, true)) {
                try {
                    this.asyncHandler.onThrowable(t);
                } catch (Throwable te) {
                    logger.debug((String) "asyncHandler.onThrowable", te);
                }
            }
            this.latch.countDown();
            runListeners();
        }
    }

    public void content(V v) {
        this.content.set(v);
    }

    /* access modifiers changed from: protected */
    public final Request getRequest() {
        return this.request;
    }

    public final HttpRequest getNettyRequest() {
        return this.nettyRequest;
    }

    /* access modifiers changed from: protected */
    public final void setNettyRequest(HttpRequest nettyRequest2) {
        this.nettyRequest = nettyRequest2;
    }

    /* access modifiers changed from: protected */
    public final AsyncHandler<V> getAsyncHandler() {
        return this.asyncHandler;
    }

    /* access modifiers changed from: protected */
    public final boolean getKeepAlive() {
        return this.keepAlive;
    }

    /* access modifiers changed from: protected */
    public final void setKeepAlive(boolean keepAlive2) {
        this.keepAlive = keepAlive2;
    }

    /* access modifiers changed from: protected */
    public final HttpResponse getHttpResponse() {
        return this.httpResponse;
    }

    /* access modifiers changed from: protected */
    public final void setHttpResponse(HttpResponse httpResponse2) {
        this.httpResponse = httpResponse2;
    }

    /* access modifiers changed from: protected */
    public int incrementAndGetCurrentRedirectCount() {
        return this.redirectCount.incrementAndGet();
    }

    /* access modifiers changed from: protected */
    public boolean isInAuth() {
        return this.inAuth.get();
    }

    /* access modifiers changed from: protected */
    public boolean getAndSetAuth(boolean inDigestAuth) {
        return this.inAuth.getAndSet(inDigestAuth);
    }

    /* access modifiers changed from: protected */
    public STATE getState() {
        return this.state.get();
    }

    /* access modifiers changed from: protected */
    public void setState(STATE state2) {
        this.state.set(state2);
    }

    public boolean getAndSetStatusReceived(boolean sr) {
        return this.statusReceived.getAndSet(sr);
    }

    public void touch() {
        this.touch.set(DateUtil.millisTime());
    }

    public long getLastTouch() {
        return this.touch.get();
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

    /* access modifiers changed from: protected */
    public NettyAsyncHttpProvider provider() {
        return this.asyncHttpProvider;
    }

    /* access modifiers changed from: protected */
    public void attachChannel(Channel channel2) {
        this.channel = channel2;
    }

    public void setReuseChannel(boolean reuseChannel2) {
        this.reuseChannel = reuseChannel2;
    }

    public boolean isConnectAllowed() {
        return this.allowConnect;
    }

    public void setConnectAllowed(boolean allowConnect2) {
        this.allowConnect = allowConnect2;
    }

    /* access modifiers changed from: protected */
    public void attachChannel(Channel channel2, boolean reuseChannel2) {
        this.channel = channel2;
        this.reuseChannel = reuseChannel2;
    }

    /* access modifiers changed from: protected */
    public Channel channel() {
        return this.channel;
    }

    /* access modifiers changed from: protected */
    public boolean reuseChannel() {
        return this.reuseChannel;
    }

    /* access modifiers changed from: protected */
    public boolean canRetry() {
        if (this.currentRetry.incrementAndGet() > this.maxRetry) {
            return false;
        }
        return true;
    }

    public void setRequest(Request request2) {
        this.request = request2;
    }

    public boolean cannotBeReplay() {
        return isDone() || !canRetry() || isCancelled() || !(channel() == null || !channel().isOpen() || this.uri.getScheme().compareToIgnoreCase(CommonProtocol.URL_SCHEME) == 0) || isInAuth();
    }

    public long getStart() {
        return this.start;
    }

    public long getRequestTimeoutInMs() {
        return (long) this.requestTimeoutInMs;
    }

    public long getIdleConnectionTimeoutInMs() {
        return (long) this.idleConnectionTimeoutInMs;
    }

    public String toString() {
        return "NettyResponseFuture{currentRetry=" + this.currentRetry + ",\n\tisDone=" + this.isDone + ",\n\tisCancelled=" + this.isCancelled + ",\n\tasyncHandler=" + this.asyncHandler + ",\n\trequestTimeoutInMs=" + this.requestTimeoutInMs + ",\n\tnettyRequest=" + this.nettyRequest + ",\n\tcontent=" + this.content + ",\n\turi=" + this.uri + ",\n\tkeepAlive=" + this.keepAlive + ",\n\thttpResponse=" + this.httpResponse + ",\n\texEx=" + this.exEx + ",\n\tredirectCount=" + this.redirectCount + ",\n\ttimeoutsHolder=" + this.timeoutsHolder + ",\n\tinAuth=" + this.inAuth + ",\n\tstatusReceived=" + this.statusReceived + ",\n\ttouch=" + this.touch + '}';
    }
}