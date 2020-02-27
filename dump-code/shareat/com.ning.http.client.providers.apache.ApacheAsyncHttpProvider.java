package com.ning.http.client.providers.apache;

import com.kakao.util.helper.CommonProtocol;
import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.AsyncHttpProviderConfig;
import com.ning.http.client.Body;
import com.ning.http.client.ByteArrayPart;
import com.ning.http.client.FilePart;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.MaxRedirectException;
import com.ning.http.client.Part;
import com.ning.http.client.PerRequestConfig;
import com.ning.http.client.ProgressAsyncHandler;
import com.ning.http.client.ProxyServer;
import com.ning.http.client.Realm;
import com.ning.http.client.Request;
import com.ning.http.client.Request.EntityWriter;
import com.ning.http.client.RequestBuilder;
import com.ning.http.client.Response;
import com.ning.http.client.StringPart;
import com.ning.http.client.cookie.CookieEncoder;
import com.ning.http.client.filter.FilterContext;
import com.ning.http.client.filter.FilterContext.FilterContextBuilder;
import com.ning.http.client.filter.FilterException;
import com.ning.http.client.filter.IOExceptionFilter;
import com.ning.http.client.filter.ResponseFilter;
import com.ning.http.client.listener.TransferCompletionHandler;
import com.ning.http.client.resumable.ResumableAsyncHandler;
import com.ning.http.util.AsyncHttpProviderUtils;
import com.ning.http.util.MiscUtil;
import com.ning.http.util.ProxyUtils;
import com.ning.http.util.UTF8UrlEncoder;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.httpclient.CircularRedirectException;
import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.NoHttpResponseException;
import org.apache.commons.httpclient.ProxyHost;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.DeleteMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.HeadMethod;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.OptionsMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.methods.multipart.ByteArrayPartSource;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.httpclient.util.IdleConnectionTimeoutThread;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ApacheAsyncHttpProvider implements AsyncHttpProvider {
    /* access modifiers changed from: private */
    public static final Logger logger = LoggerFactory.getLogger(ApacheAsyncHttpProvider.class);
    /* access modifiers changed from: private */
    public final AsyncHttpClientConfig config;
    private final MultiThreadedHttpConnectionManager connectionManager;
    private IdleConnectionTimeoutThread idleConnectionTimeoutThread;
    private final AtomicBoolean isClose = new AtomicBoolean(false);
    /* access modifiers changed from: private */
    public final AtomicInteger maxConnections = new AtomicInteger();
    private final HttpClientParams params;
    /* access modifiers changed from: private */
    public final ScheduledExecutorService reaper;

    public class ApacheClientRunnable<T> implements Callable<T> {
        private final AsyncHandler<T> asyncHandler;
        private int currentRedirectCount;
        private final ApacheResponseFuture<T> future;
        private final HttpClient httpClient;
        private AtomicBoolean isAuth = new AtomicBoolean(false);
        /* access modifiers changed from: private */
        public HttpMethodBase method;
        private Request request;
        private boolean terminate = true;

        public ApacheClientRunnable(Request request2, AsyncHandler<T> asyncHandler2, HttpMethodBase method2, ApacheResponseFuture<T> future2, HttpClient httpClient2) {
            this.asyncHandler = asyncHandler2;
            this.method = method2;
            this.future = future2;
            this.request = request2;
            this.httpClient = httpClient2;
        }

        /* JADX WARNING: type inference failed for: r21v0, types: [java.io.InputStream] */
        /* JADX WARNING: type inference failed for: r21v1 */
        /* JADX WARNING: type inference failed for: r37v1 */
        /* JADX WARNING: type inference failed for: r0v84, types: [java.io.InputStream] */
        /* JADX WARNING: type inference failed for: r0v95, types: [java.io.InputStream] */
        /* JADX WARNING: type inference failed for: r1v5, types: [java.io.InputStream] */
        /* JADX WARNING: type inference failed for: r21v2 */
        /* JADX WARNING: Multi-variable type inference failed */
        /* JADX WARNING: Unknown variable types count: 4 */
        public T call() {
            URI uri;
            FilterContext fc;
            int statusCode;
            int leftBytes;
            int read;
            this.terminate = true;
            STATE state = STATE.ABORT;
            try {
                uri = AsyncHttpProviderUtils.createUri(this.request.getRawUrl());
            } catch (IllegalArgumentException e) {
                uri = AsyncHttpProviderUtils.createUri(this.request.getUrl());
            }
            try {
                int delay = ApacheAsyncHttpProvider.requestTimeout(ApacheAsyncHttpProvider.this.config, this.future.getRequest().getPerRequestConfig());
                if (delay != -1) {
                    ReaperFuture reaperFuture = new ReaperFuture(this.future);
                    reaperFuture.setScheduledFuture(ApacheAsyncHttpProvider.this.reaper.scheduleAtFixedRate(reaperFuture, (long) delay, 500, TimeUnit.MILLISECONDS));
                    this.future.setReaperFuture(reaperFuture);
                }
                if (this.asyncHandler instanceof TransferCompletionHandler) {
                    throw new IllegalStateException(TransferCompletionHandler.class.getName() + "not supported by this provider");
                }
                try {
                    statusCode = this.httpClient.executeMethod(this.method);
                } catch (CircularRedirectException e2) {
                    statusCode = 302;
                    this.currentRedirectCount = ApacheAsyncHttpProvider.this.config.getMaxRedirects();
                }
                ApacheResponseStatus apacheResponseStatus = new ApacheResponseStatus(uri, this.method, ApacheAsyncHttpProvider.this);
                FilterContext fc2 = new FilterContextBuilder().asyncHandler(this.asyncHandler).request(this.request).responseStatus(apacheResponseStatus).build();
                for (ResponseFilter asyncFilter : ApacheAsyncHttpProvider.this.config.getResponseFilters()) {
                    fc2 = asyncFilter.filter(fc2);
                    if (fc2 == null) {
                        throw new NullPointerException("FilterContext is null");
                    }
                }
                if (fc2.replayRequest()) {
                    this.request = fc2.getRequest();
                    this.method = ApacheAsyncHttpProvider.this.createMethod(this.httpClient, this.request);
                    this.terminate = false;
                    T call = call();
                    if (!this.terminate) {
                        return call;
                    }
                    if (ApacheAsyncHttpProvider.this.config.getMaxTotalConnections() != -1) {
                        ApacheAsyncHttpProvider.this.maxConnections.decrementAndGet();
                    }
                    this.future.done();
                    ApacheAsyncHttpProvider.this.config.executorService().submit(new Runnable() {
                        public void run() {
                            ApacheClientRunnable.this.method.releaseConnection();
                        }
                    });
                    return call;
                }
                ApacheAsyncHttpProvider.logger.debug((String) "\n\nRequest {}\n\nResponse {}\n", (Object) this.request, (Object) this.method);
                if ((this.request.isRedirectEnabled() || ApacheAsyncHttpProvider.this.config.isRedirectEnabled()) && (statusCode == 302 || statusCode == 301)) {
                    this.isAuth.set(false);
                    int i = this.currentRedirectCount;
                    this.currentRedirectCount = i + 1;
                    if (i < ApacheAsyncHttpProvider.this.config.getMaxRedirects()) {
                        String newUrl = AsyncHttpProviderUtils.getRedirectUri(uri, this.method.getResponseHeader("Location").getValue()).toString();
                        if (!newUrl.equals(uri.toString())) {
                            RequestBuilder builder = new RequestBuilder(this.request);
                            ApacheAsyncHttpProvider.logger.debug((String) "Redirecting to {}", (Object) newUrl);
                            this.request = builder.setUrl(newUrl).build();
                            this.method = ApacheAsyncHttpProvider.this.createMethod(this.httpClient, this.request);
                            this.terminate = false;
                            T call2 = call();
                            if (!this.terminate) {
                                return call2;
                            }
                            if (ApacheAsyncHttpProvider.this.config.getMaxTotalConnections() != -1) {
                                ApacheAsyncHttpProvider.this.maxConnections.decrementAndGet();
                            }
                            this.future.done();
                            ApacheAsyncHttpProvider.this.config.executorService().submit(new Runnable() {
                                public void run() {
                                    ApacheClientRunnable.this.method.releaseConnection();
                                }
                            });
                            return call2;
                        }
                    } else {
                        throw new MaxRedirectException("Maximum redirect reached: " + ApacheAsyncHttpProvider.this.config.getMaxRedirects());
                    }
                }
                STATE state2 = this.asyncHandler.onStatusReceived(apacheResponseStatus);
                if (state2 == STATE.CONTINUE) {
                    state2 = this.asyncHandler.onHeadersReceived(new ApacheResponseHeaders(uri, this.method, ApacheAsyncHttpProvider.this));
                }
                if (state2 == STATE.CONTINUE) {
                    ? responseBodyAsStream = this.method.getResponseBodyAsStream();
                    if (responseBodyAsStream != 0) {
                        Header h = this.method.getResponseHeader("Content-Encoding");
                        if (h != null) {
                            String contentEncoding = h.getValue();
                            if (contentEncoding == null ? false : "gzip".equalsIgnoreCase(contentEncoding)) {
                                GZIPInputStream gZIPInputStream = new GZIPInputStream(responseBodyAsStream);
                                responseBodyAsStream = gZIPInputStream;
                            }
                        }
                        int byteToRead = (int) this.method.getResponseContentLength();
                        ByteArrayInputStream byteArrayInputStream = responseBodyAsStream;
                        if (byteToRead <= 0) {
                            int[] lengthWrapper = new int[1];
                            ByteArrayInputStream byteArrayInputStream2 = new ByteArrayInputStream(AsyncHttpProviderUtils.readFully(responseBodyAsStream, lengthWrapper), 0, lengthWrapper[0]);
                            byteToRead = lengthWrapper[0];
                            byteArrayInputStream = byteArrayInputStream2;
                        }
                        if (byteToRead > 0) {
                            int minBytes = Math.min(8192, byteToRead);
                            byte[] bytes = new byte[minBytes];
                            if (minBytes < 8192) {
                                leftBytes = minBytes;
                            } else {
                                leftBytes = byteToRead;
                            }
                            while (leftBytes > -1) {
                                try {
                                    read = byteArrayInputStream.read(bytes);
                                } catch (IOException ex) {
                                    ApacheAsyncHttpProvider.logger.warn((String) "Connection closed", (Throwable) ex);
                                    read = -1;
                                }
                                if (read == -1) {
                                    break;
                                }
                                this.future.touch();
                                byte[] b = new byte[read];
                                System.arraycopy(bytes, 0, b, 0, read);
                                leftBytes -= read;
                                this.asyncHandler.onBodyPartReceived(new ApacheResponseBodyPart(uri, b, ApacheAsyncHttpProvider.this, leftBytes > -1));
                            }
                        }
                    }
                    if (this.method.getName().equalsIgnoreCase(HttpRequest.METHOD_HEAD)) {
                        this.asyncHandler.onBodyPartReceived(new ApacheResponseBodyPart(uri, "".getBytes(), ApacheAsyncHttpProvider.this, true));
                    }
                }
                if (this.asyncHandler instanceof ProgressAsyncHandler) {
                    ProgressAsyncHandler progressAsyncHandler = (ProgressAsyncHandler) this.asyncHandler;
                    progressAsyncHandler.onHeaderWriteCompleted();
                    progressAsyncHandler.onContentWriteCompleted();
                }
                T onCompleted = this.asyncHandler.onCompleted();
                if (!this.terminate) {
                    return onCompleted;
                }
                if (ApacheAsyncHttpProvider.this.config.getMaxTotalConnections() != -1) {
                    ApacheAsyncHttpProvider.this.maxConnections.decrementAndGet();
                }
                this.future.done();
                ApacheAsyncHttpProvider.this.config.executorService().submit(new Runnable() {
                    public void run() {
                        ApacheClientRunnable.this.method.releaseConnection();
                    }
                });
                return onCompleted;
            } catch (Throwable t2) {
                ApacheAsyncHttpProvider.logger.error(t2.getMessage(), t2);
            }
            if (this.terminate) {
                if (ApacheAsyncHttpProvider.this.config.getMaxTotalConnections() != -1) {
                    ApacheAsyncHttpProvider.this.maxConnections.decrementAndGet();
                }
                this.future.done();
                ApacheAsyncHttpProvider.this.config.executorService().submit(new Runnable() {
                    public void run() {
                        ApacheClientRunnable.this.method.releaseConnection();
                    }
                });
            }
            return null;
        }

        private Throwable filterException(Throwable t) {
            if (t instanceof UnknownHostException) {
                return new ConnectException(t.getMessage());
            }
            if (t instanceof NoHttpResponseException) {
                int responseTimeoutInMs = ApacheAsyncHttpProvider.this.config.getRequestTimeoutInMs();
                if (!(this.request.getPerRequestConfig() == null || this.request.getPerRequestConfig().getRequestTimeoutInMs() == -1)) {
                    responseTimeoutInMs = this.request.getPerRequestConfig().getRequestTimeoutInMs();
                }
                return new TimeoutException(String.format("No response received after %s", new Object[]{Integer.valueOf(responseTimeoutInMs)}));
            } else if (!(t instanceof SSLHandshakeException)) {
                return t;
            } else {
                Throwable t2 = new ConnectException();
                t2.initCause(t);
                return t2;
            }
        }

        private FilterContext handleIoException(FilterContext fc) throws FilterException {
            for (IOExceptionFilter asyncFilter : ApacheAsyncHttpProvider.this.config.getIOExceptionFilters()) {
                fc = asyncFilter.filter(fc);
                if (fc == null) {
                    throw new NullPointerException("FilterContext is null");
                }
            }
            return fc;
        }
    }

    public class EntityWriterRequestEntity implements RequestEntity {
        private long contentLength;
        private EntityWriter entityWriter;

        public EntityWriterRequestEntity(EntityWriter entityWriter2, long contentLength2) {
            this.entityWriter = entityWriter2;
            this.contentLength = contentLength2;
        }

        public long getContentLength() {
            return this.contentLength;
        }

        public String getContentType() {
            return null;
        }

        public boolean isRepeatable() {
            return false;
        }

        public void writeRequest(OutputStream out) throws IOException {
            this.entityWriter.writeEntity(out);
        }
    }

    private final class ReaperFuture implements Future, Runnable {
        private ApacheResponseFuture<?> apacheResponseFuture;
        private Future scheduledFuture;

        public ReaperFuture(ApacheResponseFuture<?> apacheResponseFuture2) {
            this.apacheResponseFuture = apacheResponseFuture2;
        }

        public void setScheduledFuture(Future scheduledFuture2) {
            this.scheduledFuture = scheduledFuture2;
        }

        public synchronized boolean cancel(boolean mayInterruptIfRunning) {
            this.apacheResponseFuture = null;
            return this.scheduledFuture.cancel(mayInterruptIfRunning);
        }

        public Object get() throws InterruptedException, ExecutionException {
            return this.scheduledFuture.get();
        }

        public Object get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            return this.scheduledFuture.get(timeout, unit);
        }

        public boolean isCancelled() {
            return this.scheduledFuture.isCancelled();
        }

        public boolean isDone() {
            return this.scheduledFuture.isDone();
        }

        public synchronized void run() {
            if (this.apacheResponseFuture != null && this.apacheResponseFuture.hasExpired()) {
                ApacheAsyncHttpProvider.logger.debug("Request Timeout expired for " + this.apacheResponseFuture);
                int requestTimeout = ApacheAsyncHttpProvider.this.config.getRequestTimeoutInMs();
                PerRequestConfig p = this.apacheResponseFuture.getRequest().getPerRequestConfig();
                if (!(p == null || p.getRequestTimeoutInMs() == -1)) {
                    requestTimeout = p.getRequestTimeoutInMs();
                }
                this.apacheResponseFuture.abort(new TimeoutException(String.format("No response received after %s", new Object[]{Integer.valueOf(requestTimeout)})));
                this.apacheResponseFuture = null;
            }
        }
    }

    private static class TrustEveryoneTrustManager implements X509TrustManager {
        private TrustEveryoneTrustManager() {
        }

        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    private static class TrustingSSLSocketFactory extends SSLSocketFactory {
        private SSLSocketFactory delegate;

        private TrustingSSLSocketFactory() {
            try {
                SSLContext sslcontext = SSLContext.getInstance("SSL");
                sslcontext.init(null, new TrustManager[]{new TrustEveryoneTrustManager()}, new SecureRandom());
                this.delegate = sslcontext.getSocketFactory();
            } catch (KeyManagementException e) {
                throw new IllegalStateException();
            } catch (NoSuchAlgorithmException e2) {
                throw new IllegalStateException();
            }
        }

        public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
            return this.delegate.createSocket(s, i);
        }

        public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException, UnknownHostException {
            return this.delegate.createSocket(s, i, inetAddress, i1);
        }

        public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
            return this.delegate.createSocket(inetAddress, i);
        }

        public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
            return this.delegate.createSocket(inetAddress, i, inetAddress1, i1);
        }

        public String[] getDefaultCipherSuites() {
            return this.delegate.getDefaultCipherSuites();
        }

        public String[] getSupportedCipherSuites() {
            return this.delegate.getSupportedCipherSuites();
        }

        public Socket createSocket(Socket socket, String s, int i, boolean b) throws IOException {
            return this.delegate.createSocket(socket, s, i, b);
        }
    }

    static {
        final SocketFactory factory = new TrustingSSLSocketFactory();
        Protocol.registerProtocol(CommonProtocol.URL_SCHEME, new Protocol(CommonProtocol.URL_SCHEME, new ProtocolSocketFactory() {
            public Socket createSocket(String string, int i, InetAddress inetAddress, int i1) throws IOException {
                return factory.createSocket(string, i, inetAddress, i1);
            }

            public Socket createSocket(String string, int i, InetAddress inetAddress, int i1, HttpConnectionParams httpConnectionParams) throws IOException {
                return factory.createSocket(string, i, inetAddress, i1);
            }

            public Socket createSocket(String string, int i) throws IOException {
                return factory.createSocket(string, i);
            }
        }, 443));
    }

    public ApacheAsyncHttpProvider(AsyncHttpClientConfig config2) {
        this.config = config2;
        this.connectionManager = new MultiThreadedHttpConnectionManager();
        this.params = new HttpClientParams();
        this.params.setParameter("http.protocol.single-cookie-header", Boolean.TRUE);
        this.params.setCookiePolicy("compatibility");
        this.params.setParameter("http.method.retry-handler", new DefaultHttpMethodRetryHandler());
        this.reaper = getReaper(config2.getAsyncHttpProviderConfig());
    }

    private ScheduledExecutorService getReaper(AsyncHttpProviderConfig<?, ?> providerConfig) {
        ScheduledExecutorService reaper2 = null;
        if (providerConfig instanceof ApacheAsyncHttpProvider) {
            reaper2 = ApacheAsyncHttpProviderConfig.class.cast(providerConfig).getReaper();
        }
        if (reaper2 == null) {
            return Executors.newScheduledThreadPool(Runtime.getRuntime().availableProcessors(), new ThreadFactory() {
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "AsyncHttpClient-Reaper");
                    t.setDaemon(true);
                    return t;
                }
            });
        }
        return reaper2;
    }

    public <T> ListenableFuture<T> execute(Request request, AsyncHandler<T> handler) throws IOException {
        if (this.isClose.get()) {
            throw new IOException("Closed");
        }
        if (handler instanceof ResumableAsyncHandler) {
            request = ResumableAsyncHandler.class.cast(handler).adjustRequestRange(request);
        }
        if (this.config.getMaxTotalConnections() <= -1 || this.maxConnections.get() + 1 <= this.config.getMaxTotalConnections()) {
            if (this.idleConnectionTimeoutThread != null) {
                this.idleConnectionTimeoutThread.shutdown();
                this.idleConnectionTimeoutThread = null;
            }
            int requestTimeout = requestTimeout(this.config, request.getPerRequestConfig());
            if (this.config.getIdleConnectionTimeoutInMs() > 0 && requestTimeout != -1 && requestTimeout < this.config.getIdleConnectionTimeoutInMs()) {
                this.idleConnectionTimeoutThread = new IdleConnectionTimeoutThread();
                this.idleConnectionTimeoutThread.setConnectionTimeout((long) this.config.getIdleConnectionTimeoutInMs());
                this.idleConnectionTimeoutThread.addConnectionManager(this.connectionManager);
                this.idleConnectionTimeoutThread.start();
            }
            HttpClient httpClient = new HttpClient(this.params, this.connectionManager);
            Realm realm = request.getRealm() != null ? request.getRealm() : this.config.getRealm();
            if (realm != null) {
                httpClient.getParams().setAuthenticationPreemptive(realm.getUsePreemptiveAuth());
                httpClient.getState().setCredentials(new AuthScope(null, -1, AuthScope.ANY_REALM), new UsernamePasswordCredentials(realm.getPrincipal(), realm.getPassword()));
            }
            HttpMethodBase method = createMethod(httpClient, request);
            ApacheResponseFuture f = new ApacheResponseFuture(handler, requestTimeout, request, method);
            f.touch();
            f.setInnerFuture(this.config.executorService().submit(new ApacheClientRunnable(request, handler, method, f, httpClient)));
            this.maxConnections.incrementAndGet();
            return f;
        }
        throw new IOException(String.format("Too many connections %s", new Object[]{Integer.valueOf(this.config.getMaxTotalConnections())}));
    }

    public void close() {
        this.reaper.shutdown();
        if (this.idleConnectionTimeoutThread != null) {
            this.idleConnectionTimeoutThread.shutdown();
            this.idleConnectionTimeoutThread = null;
        }
        if (this.connectionManager != null) {
            try {
                this.connectionManager.shutdown();
            } catch (Exception e) {
                logger.error((String) "Error shutting down connection manager", (Throwable) e);
            }
        }
    }

    public Response prepareResponse(HttpResponseStatus status, HttpResponseHeaders headers, List<HttpResponseBodyPart> bodyParts) {
        return new ApacheResponse(status, headers, bodyParts);
    }

    /* access modifiers changed from: private */
    public HttpMethodBase createMethod(HttpClient client, Request request) throws IOException, FileNotFoundException {
        HttpMethodBase method;
        ProxyHost proxyHost;
        String methodName = request.getMethod();
        if (methodName.equalsIgnoreCase(HttpRequest.METHOD_POST) || methodName.equalsIgnoreCase(HttpRequest.METHOD_PUT)) {
            HttpMethodBase putMethod = methodName.equalsIgnoreCase(HttpRequest.METHOD_POST) ? new PostMethod(request.getUrl()) : new PutMethod(request.getUrl());
            String bodyCharset = request.getBodyEncoding() == null ? "ISO-8859-1" : request.getBodyEncoding();
            putMethod.getParams().setContentCharset("ISO-8859-1");
            if (request.getByteData() != null) {
                putMethod.setRequestEntity(new ByteArrayRequestEntity(request.getByteData()));
                putMethod.setRequestHeader("Content-Length", String.valueOf(request.getByteData().length));
            } else if (request.getStringData() != null) {
                StringRequestEntity stringRequestEntity = new StringRequestEntity(request.getStringData(), "text/xml", bodyCharset);
                putMethod.setRequestEntity(stringRequestEntity);
                putMethod.setRequestHeader("Content-Length", String.valueOf(request.getStringData().getBytes(bodyCharset).length));
            } else if (request.getStreamData() != null) {
                InputStreamRequestEntity inputStreamRequestEntity = new InputStreamRequestEntity(request.getStreamData());
                putMethod.setRequestEntity(inputStreamRequestEntity);
                putMethod.setRequestHeader("Content-Length", String.valueOf(inputStreamRequestEntity.getContentLength()));
            } else if (request.getParams() != null) {
                StringBuilder sb = new StringBuilder();
                Iterator<Entry<String, List<String>>> it = request.getParams().iterator();
                while (it.hasNext()) {
                    Entry<String, List<String>> paramEntry = it.next();
                    String key = paramEntry.getKey();
                    for (String value : paramEntry.getValue()) {
                        if (sb.length() > 0) {
                            sb.append("&");
                        }
                        UTF8UrlEncoder.appendEncoded(sb, key);
                        sb.append("=");
                        UTF8UrlEncoder.appendEncoded(sb, value);
                    }
                }
                putMethod.setRequestHeader("Content-Length", String.valueOf(sb.length()));
                putMethod.setRequestEntity(new StringRequestEntity(sb.toString(), "text/xml", "ISO-8859-1"));
                if (!request.getHeaders().containsKey("Content-Type")) {
                    putMethod.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                }
            } else if (request.getParts() != null) {
                MultipartRequestEntity mre = createMultipartRequestEntity(bodyCharset, request.getParts(), putMethod.getParams());
                putMethod.setRequestEntity(mre);
                putMethod.setRequestHeader("Content-Type", mre.getContentType());
                putMethod.setRequestHeader("Content-Length", String.valueOf(mre.getContentLength()));
            } else if (request.getEntityWriter() != null) {
                EntityWriterRequestEntity entityWriterRequestEntity = new EntityWriterRequestEntity(request.getEntityWriter(), (long) computeAndSetContentLength(request, putMethod));
                putMethod.setRequestEntity(entityWriterRequestEntity);
            } else if (request.getFile() != null) {
                File file = request.getFile();
                if (!file.isFile()) {
                    throw new IOException(String.format(Thread.currentThread() + "File %s is not a file or doesn't exist", new Object[]{file.getAbsolutePath()}));
                }
                putMethod.setRequestHeader("Content-Length", String.valueOf(file.length()));
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    InputStreamRequestEntity inputStreamRequestEntity2 = new InputStreamRequestEntity(fileInputStream);
                    putMethod.setRequestEntity(inputStreamRequestEntity2);
                    putMethod.setRequestHeader("Content-Length", String.valueOf(inputStreamRequestEntity2.getContentLength()));
                } finally {
                    fileInputStream.close();
                }
            } else if (request.getBodyGenerator() != null) {
                Body body = request.getBodyGenerator().createBody();
                try {
                    int length = (int) body.getContentLength();
                    if (length < 0) {
                        length = (int) request.getContentLength();
                    }
                    if (length >= 0) {
                        putMethod.setRequestHeader("Content-Length", String.valueOf(length));
                        byte[] bytes = new byte[length];
                        ByteBuffer buffer = ByteBuffer.wrap(bytes);
                        do {
                            buffer.clear();
                        } while (body.read(buffer) >= 0);
                        ByteArrayRequestEntity byteArrayRequestEntity = new ByteArrayRequestEntity(bytes);
                        putMethod.setRequestEntity(byteArrayRequestEntity);
                    }
                    try {
                    } catch (IOException e) {
                        logger.warn((String) "Failed to close request body: {}", (Object) e.getMessage(), (Object) e);
                    }
                } finally {
                    try {
                        body.close();
                    } catch (IOException e2) {
                        logger.warn((String) "Failed to close request body: {}", (Object) e2.getMessage(), (Object) e2);
                    }
                }
            }
            if (request.getHeaders().getFirstValue(Names.EXPECT) != null && request.getHeaders().getFirstValue(Names.EXPECT).equalsIgnoreCase("100-Continue")) {
                putMethod.setUseExpectHeader(true);
            }
            method = putMethod;
        } else if (methodName.equalsIgnoreCase(HttpRequest.METHOD_DELETE)) {
            method = new DeleteMethod(request.getUrl());
        } else if (methodName.equalsIgnoreCase(HttpRequest.METHOD_HEAD)) {
            method = new HeadMethod(request.getUrl());
        } else if (methodName.equalsIgnoreCase(HttpRequest.METHOD_GET)) {
            method = new GetMethod(request.getUrl());
        } else if (methodName.equalsIgnoreCase(HttpRequest.METHOD_OPTIONS)) {
            method = new OptionsMethod(request.getUrl());
        } else {
            throw new IllegalStateException(String.format("Invalid Method", new Object[]{methodName}));
        }
        ProxyServer proxyServer = ProxyUtils.getProxyServer(this.config, request);
        if (proxyServer != null) {
            if (proxyServer.getPrincipal() != null) {
                client.getState().setProxyCredentials(new AuthScope(null, -1, AuthScope.ANY_REALM), new UsernamePasswordCredentials(proxyServer.getPrincipal(), proxyServer.getPassword()));
            }
            if (proxyServer == null) {
                proxyHost = null;
            } else {
                proxyHost = new ProxyHost(proxyServer.getHost(), proxyServer.getPort());
            }
            client.getHostConfiguration().setProxyHost(proxyHost);
        }
        if (request.getLocalAddress() != null) {
            client.getHostConfiguration().setLocalAddress(request.getLocalAddress());
        }
        method.setFollowRedirects(false);
        if (MiscUtil.isNonEmpty(request.getCookies())) {
            method.setRequestHeader(Names.COOKIE, CookieEncoder.encode(request.getCookies()));
        }
        if (request.getHeaders() != null) {
            for (String name : request.getHeaders().keySet()) {
                if (!"host".equalsIgnoreCase(name)) {
                    for (String value2 : request.getHeaders().get((Object) name)) {
                        method.setRequestHeader(name, value2);
                    }
                }
            }
        }
        if (request.getHeaders().getFirstValue("User-Agent") != null) {
            method.setRequestHeader("User-Agent", request.getHeaders().getFirstValue("User-Agent"));
        } else if (this.config.getUserAgent() != null) {
            method.setRequestHeader("User-Agent", this.config.getUserAgent());
        } else {
            method.setRequestHeader("User-Agent", AsyncHttpProviderUtils.constructUserAgent(ApacheAsyncHttpProvider.class));
        }
        if (this.config.isCompressionEnabled()) {
            Header acceptableEncodingHeader = method.getRequestHeader("Accept-Encoding");
            if (acceptableEncodingHeader != null) {
                String acceptableEncodings = acceptableEncodingHeader.getValue();
                if (acceptableEncodings.indexOf("gzip") == -1) {
                    StringBuilder buf = new StringBuilder(acceptableEncodings);
                    if (buf.length() > 1) {
                        buf.append(",");
                    }
                    buf.append("gzip");
                    method.setRequestHeader("Accept-Encoding", buf.toString());
                }
            } else {
                method.setRequestHeader("Accept-Encoding", "gzip");
            }
        }
        if (request.getVirtualHost() != null) {
            String vs = request.getVirtualHost();
            int index = vs.indexOf(":");
            if (index > 0) {
                vs = vs.substring(0, index);
            }
            method.getParams().setVirtualHost(vs);
        }
        return method;
    }

    private static final int computeAndSetContentLength(Request request, HttpMethodBase m) {
        int lenght = (int) request.getContentLength();
        if (lenght == -1 && m.getRequestHeader("Content-Length") != null) {
            lenght = Integer.valueOf(m.getRequestHeader("Content-Length").getValue()).intValue();
        }
        if (lenght != -1) {
            m.setRequestHeader("Content-Length", String.valueOf(lenght));
        }
        return lenght;
    }

    private MultipartRequestEntity createMultipartRequestEntity(String charset, List<Part> params2, HttpMethodParams methodParams) throws FileNotFoundException {
        org.apache.commons.httpclient.methods.multipart.Part[] parts = new org.apache.commons.httpclient.methods.multipart.Part[params2.size()];
        int i = 0;
        for (Part part : params2) {
            if (part instanceof StringPart) {
                parts[i] = new org.apache.commons.httpclient.methods.multipart.StringPart(part.getName(), ((StringPart) part).getValue(), charset);
            } else if (part instanceof FilePart) {
                parts[i] = new org.apache.commons.httpclient.methods.multipart.FilePart(part.getName(), ((FilePart) part).getFile(), ((FilePart) part).getMimeType(), ((FilePart) part).getCharSet());
            } else if (part instanceof ByteArrayPart) {
                parts[i] = new org.apache.commons.httpclient.methods.multipart.FilePart(part.getName(), new ByteArrayPartSource(((ByteArrayPart) part).getFileName(), ((ByteArrayPart) part).getData()), ((ByteArrayPart) part).getMimeType(), ((ByteArrayPart) part).getCharSet());
            } else if (part == null) {
                throw new NullPointerException("Part cannot be null");
            } else {
                throw new IllegalArgumentException(String.format("Unsupported part type for multipart parameter %s", new Object[]{part.getName()}));
            }
            i++;
        }
        return new MultipartRequestEntity(parts, methodParams);
    }

    protected static int requestTimeout(AsyncHttpClientConfig config2, PerRequestConfig perRequestConfig) {
        if (perRequestConfig == null) {
            return config2.getRequestTimeoutInMs();
        }
        int prRequestTimeout = perRequestConfig.getRequestTimeoutInMs();
        return prRequestTimeout != 0 ? prRequestTimeout : config2.getRequestTimeoutInMs();
    }
}