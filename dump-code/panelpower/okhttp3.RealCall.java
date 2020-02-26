package okhttp3;

import androidx.core.app.NotificationCompat;
import java.io.IOException;
import java.util.ArrayList;
import okhttp3.internal.NamedRunnable;
import okhttp3.internal.cache.CacheInterceptor;
import okhttp3.internal.connection.ConnectInterceptor;
import okhttp3.internal.connection.StreamAllocation;
import okhttp3.internal.http.BridgeInterceptor;
import okhttp3.internal.http.CallServerInterceptor;
import okhttp3.internal.http.RealInterceptorChain;
import okhttp3.internal.http.RetryAndFollowUpInterceptor;
import okhttp3.internal.platform.Platform;

final class RealCall implements Call {
    final OkHttpClient client;
    /* access modifiers changed from: private */
    public EventListener eventListener;
    private boolean executed;
    final boolean forWebSocket;
    final Request originalRequest;
    final RetryAndFollowUpInterceptor retryAndFollowUpInterceptor;

    final class AsyncCall extends NamedRunnable {
        private final Callback responseCallback;

        AsyncCall(Callback callback) {
            super("OkHttp %s", RealCall.this.redactedUrl());
            this.responseCallback = callback;
        }

        /* access modifiers changed from: 0000 */
        public String host() {
            return RealCall.this.originalRequest.url().host();
        }

        /* access modifiers changed from: 0000 */
        public Request request() {
            return RealCall.this.originalRequest;
        }

        /* access modifiers changed from: 0000 */
        public RealCall get() {
            return RealCall.this;
        }

        /* access modifiers changed from: protected */
        /* JADX WARNING: Removed duplicated region for block: B:13:0x003d A[SYNTHETIC, Splitter:B:13:0x003d] */
        /* JADX WARNING: Removed duplicated region for block: B:15:0x005d A[Catch:{ all -> 0x0036 }] */
        public void execute() {
            IOException e;
            boolean z = true;
            try {
                Response responseWithInterceptorChain = RealCall.this.getResponseWithInterceptorChain();
                if (RealCall.this.retryAndFollowUpInterceptor.isCanceled()) {
                    try {
                        this.responseCallback.onFailure(RealCall.this, new IOException("Canceled"));
                    } catch (IOException e2) {
                        e = e2;
                        if (!z) {
                        }
                        RealCall.this.client.dispatcher().finished(this);
                    }
                } else {
                    this.responseCallback.onResponse(RealCall.this, responseWithInterceptorChain);
                }
            } catch (IOException e3) {
                e = e3;
                z = false;
                if (!z) {
                    try {
                        Platform platform = Platform.get();
                        StringBuilder sb = new StringBuilder();
                        sb.append("Callback failure for ");
                        sb.append(RealCall.this.toLoggableString());
                        platform.log(4, sb.toString(), e);
                    } catch (Throwable th) {
                        RealCall.this.client.dispatcher().finished(this);
                        throw th;
                    }
                } else {
                    RealCall.this.eventListener.callFailed(RealCall.this, e);
                    this.responseCallback.onFailure(RealCall.this, e);
                }
                RealCall.this.client.dispatcher().finished(this);
            }
            RealCall.this.client.dispatcher().finished(this);
        }
    }

    private RealCall(OkHttpClient okHttpClient, Request request, boolean z) {
        this.client = okHttpClient;
        this.originalRequest = request;
        this.forWebSocket = z;
        this.retryAndFollowUpInterceptor = new RetryAndFollowUpInterceptor(okHttpClient, z);
    }

    static RealCall newRealCall(OkHttpClient okHttpClient, Request request, boolean z) {
        RealCall realCall = new RealCall(okHttpClient, request, z);
        realCall.eventListener = okHttpClient.eventListenerFactory().create(realCall);
        return realCall;
    }

    public Request request() {
        return this.originalRequest;
    }

    public Response execute() throws IOException {
        synchronized (this) {
            if (!this.executed) {
                this.executed = true;
            } else {
                throw new IllegalStateException("Already Executed");
            }
        }
        captureCallStackTrace();
        this.eventListener.callStart(this);
        try {
            this.client.dispatcher().executed(this);
            Response responseWithInterceptorChain = getResponseWithInterceptorChain();
            if (responseWithInterceptorChain != null) {
                this.client.dispatcher().finished(this);
                return responseWithInterceptorChain;
            }
            throw new IOException("Canceled");
        } catch (IOException e) {
            this.eventListener.callFailed(this, e);
            throw e;
        } catch (Throwable th) {
            this.client.dispatcher().finished(this);
            throw th;
        }
    }

    private void captureCallStackTrace() {
        this.retryAndFollowUpInterceptor.setCallStackTrace(Platform.get().getStackTraceForCloseable("response.body().close()"));
    }

    public void enqueue(Callback callback) {
        synchronized (this) {
            if (!this.executed) {
                this.executed = true;
            } else {
                throw new IllegalStateException("Already Executed");
            }
        }
        captureCallStackTrace();
        this.eventListener.callStart(this);
        this.client.dispatcher().enqueue(new AsyncCall(callback));
    }

    public void cancel() {
        this.retryAndFollowUpInterceptor.cancel();
    }

    public synchronized boolean isExecuted() {
        return this.executed;
    }

    public boolean isCanceled() {
        return this.retryAndFollowUpInterceptor.isCanceled();
    }

    public RealCall clone() {
        return newRealCall(this.client, this.originalRequest, this.forWebSocket);
    }

    /* access modifiers changed from: 0000 */
    public StreamAllocation streamAllocation() {
        return this.retryAndFollowUpInterceptor.streamAllocation();
    }

    /* access modifiers changed from: 0000 */
    public String toLoggableString() {
        StringBuilder sb = new StringBuilder();
        sb.append(isCanceled() ? "canceled " : "");
        sb.append(this.forWebSocket ? "web socket" : NotificationCompat.CATEGORY_CALL);
        sb.append(" to ");
        sb.append(redactedUrl());
        return sb.toString();
    }

    /* access modifiers changed from: 0000 */
    public String redactedUrl() {
        return this.originalRequest.url().redact();
    }

    /* access modifiers changed from: 0000 */
    public Response getResponseWithInterceptorChain() throws IOException {
        ArrayList arrayList = new ArrayList();
        arrayList.addAll(this.client.interceptors());
        arrayList.add(this.retryAndFollowUpInterceptor);
        arrayList.add(new BridgeInterceptor(this.client.cookieJar()));
        arrayList.add(new CacheInterceptor(this.client.internalCache()));
        arrayList.add(new ConnectInterceptor(this.client));
        if (!this.forWebSocket) {
            arrayList.addAll(this.client.networkInterceptors());
        }
        arrayList.add(new CallServerInterceptor(this.forWebSocket));
        RealInterceptorChain realInterceptorChain = new RealInterceptorChain(arrayList, null, null, null, 0, this.originalRequest, this, this.eventListener, this.client.connectTimeoutMillis(), this.client.readTimeoutMillis(), this.client.writeTimeoutMillis());
        return realInterceptorChain.proceed(this.originalRequest);
    }
}