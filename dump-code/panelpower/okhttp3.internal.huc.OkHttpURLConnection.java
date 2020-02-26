package okhttp3.internal.huc;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.SocketPermission;
import java.net.URL;
import java.security.Permission;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Dispatcher;
import okhttp3.Handshake;
import okhttp3.Headers;
import okhttp3.Headers.Builder;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.Interceptor.Chain;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.internal.Internal;
import okhttp3.internal.JavaNetHeaders;
import okhttp3.internal.URLFilter;
import okhttp3.internal.Util;
import okhttp3.internal.Version;
import okhttp3.internal.http.HttpDate;
import okhttp3.internal.http.HttpHeaders;
import okhttp3.internal.http.HttpMethod;
import okhttp3.internal.http.StatusLine;
import okhttp3.internal.platform.Platform;

public final class OkHttpURLConnection extends HttpURLConnection implements Callback {
    private static final Set<String> METHODS = new LinkedHashSet(Arrays.asList(new String[]{"OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "PATCH"}));
    public static final String RESPONSE_SOURCE;
    public static final String SELECTED_PROTOCOL;
    Call call;
    private Throwable callFailure;
    OkHttpClient client;
    boolean connectPending;
    private boolean executed;
    private long fixedContentLength;
    Handshake handshake;
    /* access modifiers changed from: private */
    public final Object lock;
    private final NetworkInterceptor networkInterceptor;
    Response networkResponse;
    Proxy proxy;
    private Builder requestHeaders;
    private Response response;
    private Headers responseHeaders;
    URLFilter urlFilter;

    final class NetworkInterceptor implements Interceptor {
        private boolean proceed;

        NetworkInterceptor() {
        }

        public void proceed() {
            synchronized (OkHttpURLConnection.this.lock) {
                this.proceed = true;
                OkHttpURLConnection.this.lock.notifyAll();
            }
        }

        /* JADX WARNING: Can't wrap try/catch for region: R(3:25|26|27) */
        /* JADX WARNING: Code restructure failed: missing block: B:27:0x0095, code lost:
            throw new java.io.InterruptedIOException();
         */
        /* JADX WARNING: Missing exception handler attribute for start block: B:25:0x0090 */
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            if (OkHttpURLConnection.this.urlFilter != null) {
                OkHttpURLConnection.this.urlFilter.checkURLPermitted(request.url().url());
            }
            synchronized (OkHttpURLConnection.this.lock) {
                OkHttpURLConnection.this.connectPending = false;
                OkHttpURLConnection.this.proxy = chain.connection().route().proxy();
                OkHttpURLConnection.this.handshake = chain.connection().handshake();
                OkHttpURLConnection.this.lock.notifyAll();
                while (true) {
                    if (this.proceed) {
                        break;
                    }
                    OkHttpURLConnection.this.lock.wait();
                }
            }
            if (request.body() instanceof OutputStreamRequestBody) {
                request = ((OutputStreamRequestBody) request.body()).prepareToSendRequest(request);
            }
            Response proceed2 = chain.proceed(request);
            synchronized (OkHttpURLConnection.this.lock) {
                OkHttpURLConnection.this.networkResponse = proceed2;
                OkHttpURLConnection.this.url = proceed2.request().url().url();
            }
            return proceed2;
        }
    }

    static final class UnexpectedException extends IOException {
        static final Interceptor INTERCEPTOR = new Interceptor() {
            public Response intercept(Chain chain) throws IOException {
                try {
                    return chain.proceed(chain.request());
                } catch (Error | RuntimeException e) {
                    throw new UnexpectedException(e);
                }
            }
        };

        public UnexpectedException(Throwable th) {
            super(th);
        }
    }

    static {
        StringBuilder sb = new StringBuilder();
        sb.append(Platform.get().getPrefix());
        sb.append("-Selected-Protocol");
        SELECTED_PROTOCOL = sb.toString();
        StringBuilder sb2 = new StringBuilder();
        sb2.append(Platform.get().getPrefix());
        sb2.append("-Response-Source");
        RESPONSE_SOURCE = sb2.toString();
    }

    public OkHttpURLConnection(URL url, OkHttpClient okHttpClient) {
        super(url);
        this.networkInterceptor = new NetworkInterceptor();
        this.requestHeaders = new Builder();
        this.fixedContentLength = -1;
        this.lock = new Object();
        this.connectPending = true;
        this.client = okHttpClient;
    }

    public OkHttpURLConnection(URL url, OkHttpClient okHttpClient, URLFilter uRLFilter) {
        this(url, okHttpClient);
        this.urlFilter = uRLFilter;
    }

    /* JADX WARNING: Can't wrap try/catch for region: R(3:22|23|24) */
    /* JADX WARNING: Code restructure failed: missing block: B:24:0x0038, code lost:
        throw new java.io.InterruptedIOException();
     */
    /* JADX WARNING: Missing exception handler attribute for start block: B:22:0x0033 */
    public void connect() throws IOException {
        if (!this.executed) {
            Call buildCall = buildCall();
            this.executed = true;
            buildCall.enqueue(this);
            synchronized (this.lock) {
                while (true) {
                    if (this.connectPending && this.response == null && this.callFailure == null) {
                        this.lock.wait();
                    }
                }
                if (this.callFailure != null) {
                    throw propagate(this.callFailure);
                }
            }
        }
    }

    public void disconnect() {
        if (this.call != null) {
            this.networkInterceptor.proceed();
            this.call.cancel();
        }
    }

    public InputStream getErrorStream() {
        try {
            Response response2 = getResponse(true);
            if (HttpHeaders.hasBody(response2) && response2.code() >= 400) {
                return response2.body().byteStream();
            }
        } catch (IOException unused) {
        }
        return null;
    }

    private Headers getHeaders() throws IOException {
        if (this.responseHeaders == null) {
            Response response2 = getResponse(true);
            this.responseHeaders = response2.headers().newBuilder().add(SELECTED_PROTOCOL, response2.protocol().toString()).add(RESPONSE_SOURCE, responseSourceHeader(response2)).build();
        }
        return this.responseHeaders;
    }

    private static String responseSourceHeader(Response response2) {
        if (response2.networkResponse() == null) {
            if (response2.cacheResponse() == null) {
                return "NONE";
            }
            StringBuilder sb = new StringBuilder();
            sb.append("CACHE ");
            sb.append(response2.code());
            return sb.toString();
        } else if (response2.cacheResponse() == null) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("NETWORK ");
            sb2.append(response2.code());
            return sb2.toString();
        } else {
            StringBuilder sb3 = new StringBuilder();
            sb3.append("CONDITIONAL_CACHE ");
            sb3.append(response2.networkResponse().code());
            return sb3.toString();
        }
    }

    public String getHeaderField(int i) {
        try {
            Headers headers = getHeaders();
            if (i >= 0) {
                if (i < headers.size()) {
                    return headers.value(i);
                }
            }
        } catch (IOException unused) {
        }
        return null;
    }

    public String getHeaderField(String str) {
        String str2;
        if (str == null) {
            try {
                str2 = StatusLine.get(getResponse(true)).toString();
            } catch (IOException unused) {
                return null;
            }
        } else {
            str2 = getHeaders().get(str);
        }
        return str2;
    }

    public String getHeaderFieldKey(int i) {
        try {
            Headers headers = getHeaders();
            if (i >= 0) {
                if (i < headers.size()) {
                    return headers.name(i);
                }
            }
        } catch (IOException unused) {
        }
        return null;
    }

    public Map<String, List<String>> getHeaderFields() {
        try {
            return JavaNetHeaders.toMultimap(getHeaders(), StatusLine.get(getResponse(true)).toString());
        } catch (IOException unused) {
            return Collections.emptyMap();
        }
    }

    public Map<String, List<String>> getRequestProperties() {
        if (!this.connected) {
            return JavaNetHeaders.toMultimap(this.requestHeaders.build(), null);
        }
        throw new IllegalStateException("Cannot access request header fields after connection is set");
    }

    public InputStream getInputStream() throws IOException {
        if (this.doInput) {
            Response response2 = getResponse(false);
            if (response2.code() < 400) {
                return response2.body().byteStream();
            }
            throw new FileNotFoundException(this.url.toString());
        }
        throw new ProtocolException("This protocol does not support input");
    }

    public OutputStream getOutputStream() throws IOException {
        OutputStreamRequestBody outputStreamRequestBody = (OutputStreamRequestBody) buildCall().request().body();
        if (outputStreamRequestBody != null) {
            if (outputStreamRequestBody instanceof StreamedRequestBody) {
                connect();
                this.networkInterceptor.proceed();
            }
            if (!outputStreamRequestBody.isClosed()) {
                return outputStreamRequestBody.outputStream();
            }
            throw new ProtocolException("cannot write request body after response has been read");
        }
        StringBuilder sb = new StringBuilder();
        sb.append("method does not support a request body: ");
        sb.append(this.method);
        throw new ProtocolException(sb.toString());
    }

    public Permission getPermission() throws IOException {
        int i;
        URL url = getURL();
        String host = url.getHost();
        if (url.getPort() != -1) {
            i = url.getPort();
        } else {
            i = HttpUrl.defaultPort(url.getProtocol());
        }
        if (usingProxy()) {
            InetSocketAddress inetSocketAddress = (InetSocketAddress) this.client.proxy().address();
            host = inetSocketAddress.getHostName();
            i = inetSocketAddress.getPort();
        }
        StringBuilder sb = new StringBuilder();
        sb.append(host);
        sb.append(":");
        sb.append(i);
        return new SocketPermission(sb.toString(), "connect, resolve");
    }

    public String getRequestProperty(String str) {
        if (str == null) {
            return null;
        }
        return this.requestHeaders.get(str);
    }

    public void setConnectTimeout(int i) {
        this.client = this.client.newBuilder().connectTimeout((long) i, TimeUnit.MILLISECONDS).build();
    }

    public void setInstanceFollowRedirects(boolean z) {
        this.client = this.client.newBuilder().followRedirects(z).build();
    }

    public boolean getInstanceFollowRedirects() {
        return this.client.followRedirects();
    }

    public int getConnectTimeout() {
        return this.client.connectTimeoutMillis();
    }

    public void setReadTimeout(int i) {
        this.client = this.client.newBuilder().readTimeout((long) i, TimeUnit.MILLISECONDS).build();
    }

    public int getReadTimeout() {
        return this.client.readTimeoutMillis();
    }

    private Call buildCall() throws IOException {
        OutputStreamRequestBody outputStreamRequestBody;
        Call call2 = this.call;
        if (call2 != null) {
            return call2;
        }
        boolean z = true;
        this.connected = true;
        if (this.doOutput) {
            if (this.method.equals("GET")) {
                this.method = "POST";
            } else if (!HttpMethod.permitsRequestBody(this.method)) {
                StringBuilder sb = new StringBuilder();
                sb.append(this.method);
                sb.append(" does not support writing");
                throw new ProtocolException(sb.toString());
            }
        }
        if (this.requestHeaders.get("User-Agent") == null) {
            this.requestHeaders.add("User-Agent", defaultUserAgent());
        }
        if (HttpMethod.permitsRequestBody(this.method)) {
            if (this.requestHeaders.get("Content-Type") == null) {
                this.requestHeaders.add("Content-Type", "application/x-www-form-urlencoded");
            }
            long j = -1;
            if (this.fixedContentLength == -1 && this.chunkLength <= 0) {
                z = false;
            }
            String str = this.requestHeaders.get("Content-Length");
            long j2 = this.fixedContentLength;
            if (j2 != -1) {
                j = j2;
            } else if (str != null) {
                j = Long.parseLong(str);
            }
            outputStreamRequestBody = z ? new StreamedRequestBody(j) : new BufferedRequestBody(j);
            outputStreamRequestBody.timeout().timeout((long) this.client.writeTimeoutMillis(), TimeUnit.MILLISECONDS);
        } else {
            outputStreamRequestBody = null;
        }
        Request build = new Request.Builder().url(Internal.instance.getHttpUrlChecked(getURL().toString())).headers(this.requestHeaders.build()).method(this.method, outputStreamRequestBody).build();
        URLFilter uRLFilter = this.urlFilter;
        if (uRLFilter != null) {
            uRLFilter.checkURLPermitted(build.url().url());
        }
        OkHttpClient.Builder newBuilder = this.client.newBuilder();
        newBuilder.interceptors().clear();
        newBuilder.interceptors().add(UnexpectedException.INTERCEPTOR);
        newBuilder.networkInterceptors().clear();
        newBuilder.networkInterceptors().add(this.networkInterceptor);
        newBuilder.dispatcher(new Dispatcher(this.client.dispatcher().executorService()));
        if (!getUseCaches()) {
            newBuilder.cache(null);
        }
        Call newCall = newBuilder.build().newCall(build);
        this.call = newCall;
        return newCall;
    }

    private String defaultUserAgent() {
        String property = System.getProperty("http.agent");
        return property != null ? Util.toHumanReadableAscii(property) : Version.userAgent();
    }

    /* JADX WARNING: Code restructure failed: missing block: B:19:0x0021, code lost:
        r3 = buildCall();
        r2.networkInterceptor.proceed();
        r0 = (okhttp3.internal.huc.OutputStreamRequestBody) r3.request().body();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:0x0034, code lost:
        if (r0 == null) goto L_0x003d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:21:0x0036, code lost:
        r0.outputStream().close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:23:0x003f, code lost:
        if (r2.executed == false) goto L_0x005e;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:24:0x0041, code lost:
        r0 = r2.lock;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x0043, code lost:
        monitor-enter(r0);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:0x0046, code lost:
        if (r2.response != null) goto L_0x0052;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x004a, code lost:
        if (r2.callFailure != null) goto L_0x0052;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:31:0x004c, code lost:
        r2.lock.wait();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:33:?, code lost:
        monitor-exit(r0);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:35:0x0054, code lost:
        r3 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:0x005b, code lost:
        throw new java.io.InterruptedIOException();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:41:0x005d, code lost:
        throw r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:42:0x005e, code lost:
        r2.executed = true;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:44:?, code lost:
        onResponse(r3, r3.execute());
     */
    /* JADX WARNING: Code restructure failed: missing block: B:45:0x0069, code lost:
        r0 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:46:0x006a, code lost:
        onFailure(r3, r0);
     */
    private Response getResponse(boolean z) throws IOException {
        synchronized (this.lock) {
            if (this.response != null) {
                Response response2 = this.response;
                return response2;
            } else if (this.callFailure != null) {
                if (!z || this.networkResponse == null) {
                    throw propagate(this.callFailure);
                }
                Response response3 = this.networkResponse;
                return response3;
            }
        }
        synchronized (this.lock) {
            if (this.callFailure != null) {
                throw propagate(this.callFailure);
            } else if (this.response != null) {
                Response response4 = this.response;
                return response4;
            } else {
                throw new AssertionError();
            }
        }
    }

    public boolean usingProxy() {
        boolean z = true;
        if (this.proxy != null) {
            return true;
        }
        Proxy proxy2 = this.client.proxy();
        if (proxy2 == null || proxy2.type() == Type.DIRECT) {
            z = false;
        }
        return z;
    }

    public String getResponseMessage() throws IOException {
        return getResponse(true).message();
    }

    public int getResponseCode() throws IOException {
        return getResponse(true).code();
    }

    public void setRequestProperty(String str, String str2) {
        if (this.connected) {
            throw new IllegalStateException("Cannot set request property after connection is made");
        } else if (str == null) {
            throw new NullPointerException("field == null");
        } else if (str2 == null) {
            Platform platform = Platform.get();
            StringBuilder sb = new StringBuilder();
            sb.append("Ignoring header ");
            sb.append(str);
            sb.append(" because its value was null.");
            platform.log(5, sb.toString(), null);
        } else {
            this.requestHeaders.set(str, str2);
        }
    }

    public void setIfModifiedSince(long j) {
        super.setIfModifiedSince(j);
        if (this.ifModifiedSince != 0) {
            this.requestHeaders.set("If-Modified-Since", HttpDate.format(new Date(this.ifModifiedSince)));
        } else {
            this.requestHeaders.removeAll("If-Modified-Since");
        }
    }

    public void addRequestProperty(String str, String str2) {
        if (this.connected) {
            throw new IllegalStateException("Cannot add request property after connection is made");
        } else if (str == null) {
            throw new NullPointerException("field == null");
        } else if (str2 == null) {
            Platform platform = Platform.get();
            StringBuilder sb = new StringBuilder();
            sb.append("Ignoring header ");
            sb.append(str);
            sb.append(" because its value was null.");
            platform.log(5, sb.toString(), null);
        } else {
            this.requestHeaders.add(str, str2);
        }
    }

    public void setRequestMethod(String str) throws ProtocolException {
        if (METHODS.contains(str)) {
            this.method = str;
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Expected one of ");
        sb.append(METHODS);
        sb.append(" but was ");
        sb.append(str);
        throw new ProtocolException(sb.toString());
    }

    public void setFixedLengthStreamingMode(int i) {
        setFixedLengthStreamingMode((long) i);
    }

    public void setFixedLengthStreamingMode(long j) {
        if (this.connected) {
            throw new IllegalStateException("Already connected");
        } else if (this.chunkLength > 0) {
            throw new IllegalStateException("Already in chunked mode");
        } else if (j >= 0) {
            this.fixedContentLength = j;
            this.fixedContentLength = (int) Math.min(j, 2147483647L);
        } else {
            throw new IllegalArgumentException("contentLength < 0");
        }
    }

    /* JADX WARNING: type inference failed for: r3v2, types: [java.lang.Throwable] */
    /* JADX WARNING: type inference failed for: r3v4, types: [java.lang.Throwable] */
    /* JADX WARNING: Multi-variable type inference failed */
    /* JADX WARNING: Unknown variable types count: 1 */
    public void onFailure(Call call2, IOException iOException) {
        synchronized (this.lock) {
            if (iOException instanceof UnexpectedException) {
                iOException = iOException.getCause();
            }
            this.callFailure = iOException;
            this.lock.notifyAll();
        }
    }

    public void onResponse(Call call2, Response response2) {
        synchronized (this.lock) {
            this.response = response2;
            this.handshake = response2.handshake();
            this.url = response2.request().url().url();
            this.lock.notifyAll();
        }
    }

    private static IOException propagate(Throwable th) throws IOException {
        if (th instanceof IOException) {
            throw ((IOException) th);
        } else if (th instanceof Error) {
            throw ((Error) th);
        } else if (th instanceof RuntimeException) {
            throw ((RuntimeException) th);
        } else {
            throw new AssertionError();
        }
    }
}