package com.ning.http.client;

import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.ProxyServer.Protocol;
import com.ning.http.client.Realm.AuthScheme;
import com.ning.http.client.Realm.RealmBuilder;
import com.ning.http.client.cookie.Cookie;
import com.ning.http.client.resumable.ResumableAsyncHandler;
import com.ning.http.client.resumable.ResumableIOExceptionFilter;
import com.ning.http.client.simple.HeaderMap;
import com.ning.http.client.simple.SimpleAHCTransferListener;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import javax.net.ssl.SSLContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleAsyncHttpClient {
    /* access modifiers changed from: private */
    public static final Logger logger = LoggerFactory.getLogger(SimpleAsyncHttpClient.class);
    private AsyncHttpClient asyncHttpClient;
    private final AsyncHttpClientConfig config;
    /* access modifiers changed from: private */
    public final ThrowableHandler defaultThrowableHandler;
    private final boolean derived;
    /* access modifiers changed from: private */
    public final ErrorDocumentBehaviour errorDocumentBehaviour;
    /* access modifiers changed from: private */
    public final SimpleAHCTransferListener listener;
    private String providerClass;
    /* access modifiers changed from: private */
    public final RequestBuilder requestBuilder;
    /* access modifiers changed from: private */
    public final boolean resumeEnabled;

    private static final class BodyConsumerAsyncHandler extends AsyncCompletionHandlerBase {
        private boolean accumulateBody = false;
        private int amount = 0;
        private final BodyConsumer bodyConsumer;
        private final ErrorDocumentBehaviour errorDocumentBehaviour;
        private final ThrowableHandler exceptionHandler;
        private final SimpleAHCTransferListener listener;
        private boolean omitBody = false;
        private long total = -1;
        private final String url;

        public BodyConsumerAsyncHandler(BodyConsumer bodyConsumer2, ThrowableHandler exceptionHandler2, ErrorDocumentBehaviour errorDocumentBehaviour2, String url2, SimpleAHCTransferListener listener2) {
            this.bodyConsumer = bodyConsumer2;
            this.exceptionHandler = exceptionHandler2;
            this.errorDocumentBehaviour = errorDocumentBehaviour2;
            this.url = url2;
            this.listener = listener2;
        }

        public void onThrowable(Throwable t) {
            try {
                if (this.exceptionHandler != null) {
                    this.exceptionHandler.onThrowable(t);
                } else {
                    super.onThrowable(t);
                }
            } finally {
                closeConsumer();
            }
        }

        public STATE onBodyPartReceived(HttpResponseBodyPart content) throws Exception {
            fireReceived(content);
            if (this.omitBody) {
                return STATE.CONTINUE;
            }
            if (this.accumulateBody || this.bodyConsumer == null) {
                return super.onBodyPartReceived(content);
            }
            this.bodyConsumer.consume(content.getBodyByteBuffer());
            return STATE.CONTINUE;
        }

        public Response onCompleted(Response response) throws Exception {
            fireCompleted(response);
            closeConsumer();
            return super.onCompleted(response);
        }

        private void closeConsumer() {
            try {
                if (this.bodyConsumer != null) {
                    this.bodyConsumer.close();
                }
            } catch (IOException e) {
                SimpleAsyncHttpClient.logger.warn((String) "Unable to close a BodyConsumer {}", (Object) this.bodyConsumer);
            }
        }

        public STATE onStatusReceived(HttpResponseStatus status) throws Exception {
            fireStatus(status);
            if (isErrorStatus(status)) {
                switch (this.errorDocumentBehaviour) {
                    case ACCUMULATE:
                        this.accumulateBody = true;
                        break;
                    case OMIT:
                        this.omitBody = true;
                        break;
                }
            }
            return super.onStatusReceived(status);
        }

        private boolean isErrorStatus(HttpResponseStatus status) {
            return status.getStatusCode() >= 400;
        }

        public STATE onHeadersReceived(HttpResponseHeaders headers) throws Exception {
            calculateTotal(headers);
            fireHeaders(headers);
            return super.onHeadersReceived(headers);
        }

        private void calculateTotal(HttpResponseHeaders headers) {
            try {
                this.total = (long) Integer.valueOf(headers.getHeaders().getFirstValue("Content-Length")).intValue();
            } catch (Exception e) {
                this.total = -1;
            }
        }

        public STATE onContentWriteProgress(long amount2, long current, long total2) {
            fireSent(this.url, amount2, current, total2);
            return super.onContentWriteProgress(amount2, current, total2);
        }

        private void fireStatus(HttpResponseStatus status) {
            if (this.listener != null) {
                this.listener.onStatus(this.url, status.getStatusCode(), status.getStatusText());
            }
        }

        private void fireReceived(HttpResponseBodyPart content) {
            int remaining = content.getBodyByteBuffer().remaining();
            this.amount += remaining;
            if (this.listener != null) {
                this.listener.onBytesReceived(this.url, (long) this.amount, (long) remaining, this.total);
            }
        }

        private void fireHeaders(HttpResponseHeaders headers) {
            if (this.listener != null) {
                this.listener.onHeaders(this.url, new HeaderMap(headers.getHeaders()));
            }
        }

        private void fireSent(String url2, long amount2, long current, long total2) {
            if (this.listener != null) {
                this.listener.onBytesSent(url2, amount2, current, total2);
            }
        }

        private void fireCompleted(Response response) {
            if (this.listener != null) {
                this.listener.onCompleted(this.url, response.getStatusCode(), response.getStatusText());
            }
        }
    }

    public static final class Builder implements DerivedBuilder {
        private AsyncHttpClient ahc;
        private final com.ning.http.client.AsyncHttpClientConfig.Builder configBuilder;
        private ThrowableHandler defaultThrowableHandler;
        private boolean enableResumableDownload;
        private ErrorDocumentBehaviour errorDocumentBehaviour;
        private SimpleAHCTransferListener listener;
        private String providerClass;
        private String proxyHost;
        private String proxyPassword;
        private int proxyPort;
        private String proxyPrincipal;
        private Protocol proxyProtocol;
        private RealmBuilder realmBuilder;
        private final RequestBuilder requestBuilder;

        public Builder() {
            this.configBuilder = new com.ning.http.client.AsyncHttpClientConfig.Builder();
            this.realmBuilder = null;
            this.proxyProtocol = null;
            this.proxyHost = null;
            this.proxyPrincipal = null;
            this.proxyPassword = null;
            this.proxyPort = 80;
            this.defaultThrowableHandler = null;
            this.enableResumableDownload = false;
            this.errorDocumentBehaviour = ErrorDocumentBehaviour.WRITE;
            this.ahc = null;
            this.listener = null;
            this.providerClass = null;
            this.requestBuilder = new RequestBuilder(HttpRequest.METHOD_GET, false);
        }

        private Builder(SimpleAsyncHttpClient client) {
            this.configBuilder = new com.ning.http.client.AsyncHttpClientConfig.Builder();
            this.realmBuilder = null;
            this.proxyProtocol = null;
            this.proxyHost = null;
            this.proxyPrincipal = null;
            this.proxyPassword = null;
            this.proxyPort = 80;
            this.defaultThrowableHandler = null;
            this.enableResumableDownload = false;
            this.errorDocumentBehaviour = ErrorDocumentBehaviour.WRITE;
            this.ahc = null;
            this.listener = null;
            this.providerClass = null;
            this.requestBuilder = new RequestBuilder(client.requestBuilder.build());
            this.defaultThrowableHandler = client.defaultThrowableHandler;
            this.errorDocumentBehaviour = client.errorDocumentBehaviour;
            this.enableResumableDownload = client.resumeEnabled;
            this.ahc = client.asyncHttpClient();
            this.listener = client.listener;
        }

        public Builder addBodyPart(Part part) throws IllegalArgumentException {
            this.requestBuilder.addBodyPart(part);
            return this;
        }

        public Builder addCookie(Cookie cookie) {
            this.requestBuilder.addCookie(cookie);
            return this;
        }

        public Builder addHeader(String name, String value) {
            this.requestBuilder.addHeader(name, value);
            return this;
        }

        public Builder addParameter(String key, String value) throws IllegalArgumentException {
            this.requestBuilder.addParameter(key, value);
            return this;
        }

        public Builder addQueryParameter(String name, String value) {
            this.requestBuilder.addQueryParameter(name, value);
            return this;
        }

        public Builder setHeader(String name, String value) {
            this.requestBuilder.setHeader(name, value);
            return this;
        }

        public Builder setHeaders(FluentCaseInsensitiveStringsMap headers) {
            this.requestBuilder.setHeaders(headers);
            return this;
        }

        public Builder setHeaders(Map<String, Collection<String>> headers) {
            this.requestBuilder.setHeaders(headers);
            return this;
        }

        public Builder setParameters(Map<String, Collection<String>> parameters) throws IllegalArgumentException {
            this.requestBuilder.setParameters(parameters);
            return this;
        }

        public Builder setParameters(FluentStringsMap parameters) throws IllegalArgumentException {
            this.requestBuilder.setParameters(parameters);
            return this;
        }

        public Builder setUrl(String url) {
            this.requestBuilder.setUrl(url);
            return this;
        }

        public Builder setVirtualHost(String virtualHost) {
            this.requestBuilder.setVirtualHost(virtualHost);
            return this;
        }

        public Builder setFollowRedirects(boolean followRedirects) {
            this.requestBuilder.setFollowRedirects(followRedirects);
            return this;
        }

        public Builder setMaximumConnectionsTotal(int defaultMaxTotalConnections) {
            this.configBuilder.setMaximumConnectionsTotal(defaultMaxTotalConnections);
            return this;
        }

        public Builder setMaximumConnectionsPerHost(int defaultMaxConnectionPerHost) {
            this.configBuilder.setMaximumConnectionsPerHost(defaultMaxConnectionPerHost);
            return this;
        }

        public Builder setConnectionTimeoutInMs(int connectionTimeuot) {
            this.configBuilder.setConnectionTimeoutInMs(connectionTimeuot);
            return this;
        }

        public Builder setIdleConnectionInPoolTimeoutInMs(int defaultIdleConnectionInPoolTimeoutInMs) {
            this.configBuilder.setIdleConnectionInPoolTimeoutInMs(defaultIdleConnectionInPoolTimeoutInMs);
            return this;
        }

        public Builder setRequestTimeoutInMs(int defaultRequestTimeoutInMs) {
            this.configBuilder.setRequestTimeoutInMs(defaultRequestTimeoutInMs);
            return this;
        }

        public Builder setMaximumNumberOfRedirects(int maxDefaultRedirects) {
            this.configBuilder.setMaximumNumberOfRedirects(maxDefaultRedirects);
            return this;
        }

        public Builder setCompressionEnabled(boolean compressionEnabled) {
            this.configBuilder.setCompressionEnabled(compressionEnabled);
            return this;
        }

        public Builder setUserAgent(String userAgent) {
            this.configBuilder.setUserAgent(userAgent);
            return this;
        }

        public Builder setAllowPoolingConnection(boolean allowPoolingConnection) {
            this.configBuilder.setAllowPoolingConnection(allowPoolingConnection);
            return this;
        }

        public Builder setExecutorService(ExecutorService applicationThreadPool) {
            this.configBuilder.setExecutorService(applicationThreadPool);
            return this;
        }

        public Builder setSSLEngineFactory(SSLEngineFactory sslEngineFactory) {
            this.configBuilder.setSSLEngineFactory(sslEngineFactory);
            return this;
        }

        public Builder setSSLContext(SSLContext sslContext) {
            this.configBuilder.setSSLContext(sslContext);
            return this;
        }

        public Builder setRequestCompressionLevel(int requestCompressionLevel) {
            this.configBuilder.setRequestCompressionLevel(requestCompressionLevel);
            return this;
        }

        public Builder setRealmDomain(String domain) {
            realm().setDomain(domain);
            return this;
        }

        public Builder setRealmPrincipal(String principal) {
            realm().setPrincipal(principal);
            return this;
        }

        public Builder setRealmPassword(String password) {
            realm().setPassword(password);
            return this;
        }

        public Builder setRealmScheme(AuthScheme scheme) {
            realm().setScheme(scheme);
            return this;
        }

        public Builder setRealmName(String realmName) {
            realm().setRealmName(realmName);
            return this;
        }

        public Builder setRealmUsePreemptiveAuth(boolean usePreemptiveAuth) {
            realm().setUsePreemptiveAuth(usePreemptiveAuth);
            return this;
        }

        public Builder setRealmEnconding(String enc) {
            realm().setEnconding(enc);
            return this;
        }

        public Builder setProxyProtocol(Protocol protocol) {
            this.proxyProtocol = protocol;
            return this;
        }

        public Builder setProxyHost(String host) {
            this.proxyHost = host;
            return this;
        }

        public Builder setProxyPrincipal(String principal) {
            this.proxyPrincipal = principal;
            return this;
        }

        public Builder setProxyPassword(String password) {
            this.proxyPassword = password;
            return this;
        }

        public Builder setProxyPort(int port) {
            this.proxyPort = port;
            return this;
        }

        public Builder setDefaultThrowableHandler(ThrowableHandler throwableHandler) {
            this.defaultThrowableHandler = throwableHandler;
            return this;
        }

        public Builder setErrorDocumentBehaviour(ErrorDocumentBehaviour behaviour) {
            this.errorDocumentBehaviour = behaviour;
            return this;
        }

        public Builder setResumableDownload(boolean enableResumableDownload2) {
            this.enableResumableDownload = enableResumableDownload2;
            return this;
        }

        private RealmBuilder realm() {
            if (this.realmBuilder == null) {
                this.realmBuilder = new RealmBuilder();
            }
            return this.realmBuilder;
        }

        public Builder setListener(SimpleAHCTransferListener listener2) {
            this.listener = listener2;
            return this;
        }

        public Builder setMaxRequestRetry(int maxRequestRetry) {
            this.configBuilder.setMaxRequestRetry(maxRequestRetry);
            return this;
        }

        public Builder setProviderClass(String providerClass2) {
            this.providerClass = providerClass2;
            return this;
        }

        public SimpleAsyncHttpClient build() {
            if (this.realmBuilder != null) {
                this.configBuilder.setRealm(this.realmBuilder.build());
            }
            if (this.proxyHost != null) {
                this.configBuilder.setProxyServer(new ProxyServer(this.proxyProtocol, this.proxyHost, this.proxyPort, this.proxyPrincipal, this.proxyPassword));
            }
            this.configBuilder.addIOExceptionFilter(new ResumableIOExceptionFilter());
            return new SimpleAsyncHttpClient(this.configBuilder.build(), this.requestBuilder, this.defaultThrowableHandler, this.errorDocumentBehaviour, this.enableResumableDownload, this.ahc, this.listener, this.providerClass);
        }
    }

    public interface DerivedBuilder {
        DerivedBuilder addBodyPart(Part part) throws IllegalArgumentException;

        DerivedBuilder addCookie(Cookie cookie);

        DerivedBuilder addHeader(String str, String str2);

        DerivedBuilder addParameter(String str, String str2) throws IllegalArgumentException;

        DerivedBuilder addQueryParameter(String str, String str2);

        SimpleAsyncHttpClient build();

        DerivedBuilder setFollowRedirects(boolean z);

        DerivedBuilder setHeader(String str, String str2);

        DerivedBuilder setHeaders(FluentCaseInsensitiveStringsMap fluentCaseInsensitiveStringsMap);

        DerivedBuilder setHeaders(Map<String, Collection<String>> map);

        DerivedBuilder setParameters(FluentStringsMap fluentStringsMap) throws IllegalArgumentException;

        DerivedBuilder setParameters(Map<String, Collection<String>> map) throws IllegalArgumentException;

        DerivedBuilder setResumableDownload(boolean z);

        DerivedBuilder setUrl(String str);

        DerivedBuilder setVirtualHost(String str);
    }

    public enum ErrorDocumentBehaviour {
        WRITE,
        ACCUMULATE,
        OMIT
    }

    private static final class ResumableBodyConsumerAsyncHandler extends ResumableAsyncHandler<Response> implements ProgressAsyncHandler<Response> {
        private final ProgressAsyncHandler<Response> delegate;

        public ResumableBodyConsumerAsyncHandler(long byteTransferred, ProgressAsyncHandler<Response> delegate2) {
            super(byteTransferred, (AsyncHandler<T>) delegate2);
            this.delegate = delegate2;
        }

        public STATE onHeaderWriteCompleted() {
            return this.delegate.onHeaderWriteCompleted();
        }

        public STATE onContentWriteCompleted() {
            return this.delegate.onContentWriteCompleted();
        }

        public STATE onContentWriteProgress(long amount, long current, long total) {
            return this.delegate.onContentWriteProgress(amount, current, total);
        }
    }

    private SimpleAsyncHttpClient(AsyncHttpClientConfig config2, RequestBuilder requestBuilder2, ThrowableHandler defaultThrowableHandler2, ErrorDocumentBehaviour errorDocumentBehaviour2, boolean resumeEnabled2, AsyncHttpClient ahc, SimpleAHCTransferListener listener2, String providerClass2) {
        this.config = config2;
        this.requestBuilder = requestBuilder2;
        this.defaultThrowableHandler = defaultThrowableHandler2;
        this.resumeEnabled = resumeEnabled2;
        this.errorDocumentBehaviour = errorDocumentBehaviour2;
        this.asyncHttpClient = ahc;
        this.listener = listener2;
        this.providerClass = providerClass2;
        this.derived = ahc != null;
    }

    public Future<Response> post(Part... parts) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_POST);
        for (Part part : parts) {
            r.addBodyPart(part);
        }
        return execute(r, null, null);
    }

    public Future<Response> post(BodyConsumer consumer, Part... parts) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_POST);
        for (Part part : parts) {
            r.addBodyPart(part);
        }
        return execute(r, consumer, null);
    }

    public Future<Response> post(BodyGenerator bodyGenerator) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_POST);
        r.setBody(bodyGenerator);
        return execute(r, null, null);
    }

    public Future<Response> post(BodyGenerator bodyGenerator, ThrowableHandler throwableHandler) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_POST);
        r.setBody(bodyGenerator);
        return execute(r, null, throwableHandler);
    }

    public Future<Response> post(BodyGenerator bodyGenerator, BodyConsumer bodyConsumer) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_POST);
        r.setBody(bodyGenerator);
        return execute(r, bodyConsumer, null);
    }

    public Future<Response> post(BodyGenerator bodyGenerator, BodyConsumer bodyConsumer, ThrowableHandler throwableHandler) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_POST);
        r.setBody(bodyGenerator);
        return execute(r, bodyConsumer, throwableHandler);
    }

    public Future<Response> put(Part... parts) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_POST);
        for (Part part : parts) {
            r.addBodyPart(part);
        }
        return execute(r, null, null);
    }

    public Future<Response> put(BodyConsumer consumer, Part... parts) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_POST);
        for (Part part : parts) {
            r.addBodyPart(part);
        }
        return execute(r, consumer, null);
    }

    public Future<Response> put(BodyGenerator bodyGenerator, BodyConsumer bodyConsumer) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_PUT);
        r.setBody(bodyGenerator);
        return execute(r, bodyConsumer, null);
    }

    public Future<Response> put(BodyGenerator bodyGenerator, BodyConsumer bodyConsumer, ThrowableHandler throwableHandler) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_PUT);
        r.setBody(bodyGenerator);
        return execute(r, bodyConsumer, throwableHandler);
    }

    public Future<Response> put(BodyGenerator bodyGenerator) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_PUT);
        r.setBody(bodyGenerator);
        return execute(r, null, null);
    }

    public Future<Response> put(BodyGenerator bodyGenerator, ThrowableHandler throwableHandler) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_PUT);
        r.setBody(bodyGenerator);
        return execute(r, null, throwableHandler);
    }

    public Future<Response> get() throws IOException {
        return execute(rebuildRequest(this.requestBuilder.build()), null, null);
    }

    public Future<Response> get(ThrowableHandler throwableHandler) throws IOException {
        return execute(rebuildRequest(this.requestBuilder.build()), null, throwableHandler);
    }

    public Future<Response> get(BodyConsumer bodyConsumer) throws IOException {
        return execute(rebuildRequest(this.requestBuilder.build()), bodyConsumer, null);
    }

    public Future<Response> get(BodyConsumer bodyConsumer, ThrowableHandler throwableHandler) throws IOException {
        return execute(rebuildRequest(this.requestBuilder.build()), bodyConsumer, throwableHandler);
    }

    public Future<Response> delete() throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_DELETE);
        return execute(r, null, null);
    }

    public Future<Response> delete(ThrowableHandler throwableHandler) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_DELETE);
        return execute(r, null, throwableHandler);
    }

    public Future<Response> delete(BodyConsumer bodyConsumer) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_DELETE);
        return execute(r, bodyConsumer, null);
    }

    public Future<Response> delete(BodyConsumer bodyConsumer, ThrowableHandler throwableHandler) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_DELETE);
        return execute(r, bodyConsumer, throwableHandler);
    }

    public Future<Response> head() throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_HEAD);
        return execute(r, null, null);
    }

    public Future<Response> head(ThrowableHandler throwableHandler) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_HEAD);
        return execute(r, null, throwableHandler);
    }

    public Future<Response> options() throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_OPTIONS);
        return execute(r, null, null);
    }

    public Future<Response> options(ThrowableHandler throwableHandler) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_OPTIONS);
        return execute(r, null, throwableHandler);
    }

    public Future<Response> options(BodyConsumer bodyConsumer) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_OPTIONS);
        return execute(r, bodyConsumer, null);
    }

    public Future<Response> options(BodyConsumer bodyConsumer, ThrowableHandler throwableHandler) throws IOException {
        RequestBuilder r = rebuildRequest(this.requestBuilder.build());
        r.setMethod((String) HttpRequest.METHOD_OPTIONS);
        return execute(r, bodyConsumer, throwableHandler);
    }

    private RequestBuilder rebuildRequest(Request rb) {
        return new RequestBuilder(rb);
    }

    private Future<Response> execute(RequestBuilder rb, BodyConsumer bodyConsumer, ThrowableHandler throwableHandler) throws IOException {
        if (throwableHandler == null) {
            throwableHandler = this.defaultThrowableHandler;
        }
        Request request = rb.build();
        ProgressAsyncHandler<Response> handler = new BodyConsumerAsyncHandler<>(bodyConsumer, throwableHandler, this.errorDocumentBehaviour, request.getUrl(), this.listener);
        if (this.resumeEnabled && request.getMethod().equals(HttpRequest.METHOD_GET) && bodyConsumer != null && (bodyConsumer instanceof ResumableBodyConsumer)) {
            ResumableBodyConsumer fileBodyConsumer = (ResumableBodyConsumer) bodyConsumer;
            long length = fileBodyConsumer.getTransferredBytes();
            fileBodyConsumer.resume();
            handler = new ResumableBodyConsumerAsyncHandler<>(length, handler);
        }
        return asyncHttpClient().executeRequest(request, handler);
    }

    /* access modifiers changed from: private */
    public AsyncHttpClient asyncHttpClient() {
        synchronized (this.config) {
            if (this.asyncHttpClient == null) {
                if (this.providerClass == null) {
                    this.asyncHttpClient = new AsyncHttpClient(this.config);
                } else {
                    this.asyncHttpClient = new AsyncHttpClient(this.providerClass, this.config);
                }
            }
        }
        return this.asyncHttpClient;
    }

    public void close() {
        if (!this.derived && this.asyncHttpClient != null) {
            this.asyncHttpClient.close();
        }
    }

    public DerivedBuilder derive() {
        return new Builder();
    }
}