package okhttp3.internal.http;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Connection;
import okhttp3.EventListener;
import okhttp3.Interceptor;
import okhttp3.Interceptor.Chain;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.internal.Util;
import okhttp3.internal.connection.RealConnection;
import okhttp3.internal.connection.StreamAllocation;

public final class RealInterceptorChain implements Chain {
    private final Call call;
    private int calls;
    private final int connectTimeout;
    private final RealConnection connection;
    private final EventListener eventListener;
    private final HttpCodec httpCodec;
    private final int index;
    private final List<Interceptor> interceptors;
    private final int readTimeout;
    private final Request request;
    private final StreamAllocation streamAllocation;
    private final int writeTimeout;

    public RealInterceptorChain(List<Interceptor> list, StreamAllocation streamAllocation2, HttpCodec httpCodec2, RealConnection realConnection, int i, Request request2, Call call2, EventListener eventListener2, int i2, int i3, int i4) {
        this.interceptors = list;
        this.connection = realConnection;
        this.streamAllocation = streamAllocation2;
        this.httpCodec = httpCodec2;
        this.index = i;
        this.request = request2;
        this.call = call2;
        this.eventListener = eventListener2;
        this.connectTimeout = i2;
        this.readTimeout = i3;
        this.writeTimeout = i4;
    }

    public Connection connection() {
        return this.connection;
    }

    public int connectTimeoutMillis() {
        return this.connectTimeout;
    }

    public Chain withConnectTimeout(int i, TimeUnit timeUnit) {
        RealInterceptorChain realInterceptorChain = new RealInterceptorChain(this.interceptors, this.streamAllocation, this.httpCodec, this.connection, this.index, this.request, this.call, this.eventListener, Util.checkDuration("timeout", (long) i, timeUnit), this.readTimeout, this.writeTimeout);
        return realInterceptorChain;
    }

    public int readTimeoutMillis() {
        return this.readTimeout;
    }

    public Chain withReadTimeout(int i, TimeUnit timeUnit) {
        RealInterceptorChain realInterceptorChain = new RealInterceptorChain(this.interceptors, this.streamAllocation, this.httpCodec, this.connection, this.index, this.request, this.call, this.eventListener, this.connectTimeout, Util.checkDuration("timeout", (long) i, timeUnit), this.writeTimeout);
        return realInterceptorChain;
    }

    public int writeTimeoutMillis() {
        return this.writeTimeout;
    }

    public Chain withWriteTimeout(int i, TimeUnit timeUnit) {
        RealInterceptorChain realInterceptorChain = new RealInterceptorChain(this.interceptors, this.streamAllocation, this.httpCodec, this.connection, this.index, this.request, this.call, this.eventListener, this.connectTimeout, this.readTimeout, Util.checkDuration("timeout", (long) i, timeUnit));
        return realInterceptorChain;
    }

    public StreamAllocation streamAllocation() {
        return this.streamAllocation;
    }

    public HttpCodec httpStream() {
        return this.httpCodec;
    }

    public Call call() {
        return this.call;
    }

    public EventListener eventListener() {
        return this.eventListener;
    }

    public Request request() {
        return this.request;
    }

    public Response proceed(Request request2) throws IOException {
        return proceed(request2, this.streamAllocation, this.httpCodec, this.connection);
    }

    public Response proceed(Request request2, StreamAllocation streamAllocation2, HttpCodec httpCodec2, RealConnection realConnection) throws IOException {
        if (this.index < this.interceptors.size()) {
            this.calls++;
            if (this.httpCodec != null && !this.connection.supportsUrl(request2.url())) {
                StringBuilder sb = new StringBuilder();
                sb.append("network interceptor ");
                sb.append(this.interceptors.get(this.index - 1));
                sb.append(" must retain the same host and port");
                throw new IllegalStateException(sb.toString());
            } else if (this.httpCodec == null || this.calls <= 1) {
                StreamAllocation streamAllocation3 = streamAllocation2;
                HttpCodec httpCodec3 = httpCodec2;
                RealConnection realConnection2 = realConnection;
                RealInterceptorChain realInterceptorChain = new RealInterceptorChain(this.interceptors, streamAllocation3, httpCodec3, realConnection2, this.index + 1, request2, this.call, this.eventListener, this.connectTimeout, this.readTimeout, this.writeTimeout);
                Interceptor interceptor = this.interceptors.get(this.index);
                Response intercept = interceptor.intercept(realInterceptorChain);
                if (httpCodec2 != null && this.index + 1 < this.interceptors.size() && realInterceptorChain.calls != 1) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("network interceptor ");
                    sb2.append(interceptor);
                    sb2.append(" must call proceed() exactly once");
                    throw new IllegalStateException(sb2.toString());
                } else if (intercept == null) {
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("interceptor ");
                    sb3.append(interceptor);
                    sb3.append(" returned null");
                    throw new NullPointerException(sb3.toString());
                } else if (intercept.body() != null) {
                    return intercept;
                } else {
                    StringBuilder sb4 = new StringBuilder();
                    sb4.append("interceptor ");
                    sb4.append(interceptor);
                    sb4.append(" returned a response with no body");
                    throw new IllegalStateException(sb4.toString());
                }
            } else {
                StringBuilder sb5 = new StringBuilder();
                sb5.append("network interceptor ");
                sb5.append(this.interceptors.get(this.index - 1));
                sb5.append(" must call proceed() exactly once");
                throw new IllegalStateException(sb5.toString());
            }
        } else {
            throw new AssertionError();
        }
    }
}