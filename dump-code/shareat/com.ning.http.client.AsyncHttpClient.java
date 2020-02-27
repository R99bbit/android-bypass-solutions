package com.ning.http.client;

import com.ning.http.client.AsyncHttpClientConfig.Builder;
import com.ning.http.client.Request.EntityWriter;
import com.ning.http.client.cookie.Cookie;
import com.ning.http.client.filter.FilterContext;
import com.ning.http.client.filter.FilterContext.FilterContextBuilder;
import com.ning.http.client.filter.FilterException;
import com.ning.http.client.filter.RequestFilter;
import com.ning.http.client.providers.jdk.JDKAsyncHttpProvider;
import com.ning.http.client.resumable.ResumableAsyncHandler;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AsyncHttpClient implements Closeable {
    private static final String DEFAULT_PROVIDER = "com.ning.http.client.providers.netty.NettyAsyncHttpProvider";
    /* access modifiers changed from: private */
    public static final Logger logger = LoggerFactory.getLogger(AsyncHttpClient.class);
    private final AsyncHttpClientConfig config;
    private final AsyncHttpProvider httpProvider;
    private final AtomicBoolean isClosed;
    protected SignatureCalculator signatureCalculator;

    public class BoundRequestBuilder extends RequestBuilderBase<BoundRequestBuilder> {
        protected String baseURL;
        protected SignatureCalculator signatureCalculator;

        private BoundRequestBuilder(String reqType, boolean useRawUrl) {
            super(BoundRequestBuilder.class, reqType, useRawUrl);
        }

        private BoundRequestBuilder(Request prototype) {
            super(BoundRequestBuilder.class, prototype);
        }

        public <T> ListenableFuture<T> execute(AsyncHandler<T> handler) throws IOException {
            return AsyncHttpClient.this.executeRequest(build(), handler);
        }

        public ListenableFuture<Response> execute() throws IOException {
            return AsyncHttpClient.this.executeRequest(build(), new AsyncCompletionHandlerBase());
        }

        public BoundRequestBuilder addBodyPart(Part part) throws IllegalArgumentException {
            return (BoundRequestBuilder) super.addBodyPart(part);
        }

        public BoundRequestBuilder addCookie(Cookie cookie) {
            return (BoundRequestBuilder) super.addCookie(cookie);
        }

        public BoundRequestBuilder addHeader(String name, String value) {
            return (BoundRequestBuilder) super.addHeader(name, value);
        }

        public BoundRequestBuilder addParameter(String key, String value) throws IllegalArgumentException {
            return (BoundRequestBuilder) super.addParameter(key, value);
        }

        public BoundRequestBuilder addQueryParameter(String name, String value) {
            return (BoundRequestBuilder) super.addQueryParameter(name, value);
        }

        public Request build() {
            if (this.signatureCalculator != null) {
                String url = this.baseURL;
                int i = url.indexOf(63);
                if (i >= 0) {
                    url = url.substring(0, i);
                }
                this.signatureCalculator.calculateAndAddSignature(url, this.request, this);
            }
            return super.build();
        }

        public BoundRequestBuilder setBody(byte[] data) throws IllegalArgumentException {
            return (BoundRequestBuilder) super.setBody(data);
        }

        public BoundRequestBuilder setBody(EntityWriter dataWriter, long length) throws IllegalArgumentException {
            return (BoundRequestBuilder) super.setBody(dataWriter, length);
        }

        public BoundRequestBuilder setBody(EntityWriter dataWriter) {
            return (BoundRequestBuilder) super.setBody(dataWriter);
        }

        public BoundRequestBuilder setBody(InputStream stream) throws IllegalArgumentException {
            return (BoundRequestBuilder) super.setBody(stream);
        }

        public BoundRequestBuilder setBody(String data) throws IllegalArgumentException {
            return (BoundRequestBuilder) super.setBody(data);
        }

        public BoundRequestBuilder setHeader(String name, String value) {
            return (BoundRequestBuilder) super.setHeader(name, value);
        }

        public BoundRequestBuilder setHeaders(FluentCaseInsensitiveStringsMap headers) {
            return (BoundRequestBuilder) super.setHeaders(headers);
        }

        public BoundRequestBuilder setHeaders(Map<String, Collection<String>> headers) {
            return (BoundRequestBuilder) super.setHeaders(headers);
        }

        public BoundRequestBuilder setParameters(Map<String, Collection<String>> parameters) throws IllegalArgumentException {
            return (BoundRequestBuilder) super.setParameters(parameters);
        }

        public BoundRequestBuilder setParameters(FluentStringsMap parameters) throws IllegalArgumentException {
            return (BoundRequestBuilder) super.setParameters(parameters);
        }

        public BoundRequestBuilder setUrl(String url) {
            this.baseURL = url;
            return (BoundRequestBuilder) super.setUrl(url);
        }

        public BoundRequestBuilder setVirtualHost(String virtualHost) {
            return (BoundRequestBuilder) super.setVirtualHost(virtualHost);
        }

        public BoundRequestBuilder setSignatureCalculator(SignatureCalculator signatureCalculator2) {
            this.signatureCalculator = signatureCalculator2;
            return this;
        }
    }

    public AsyncHttpClient() {
        this(new Builder().build());
    }

    public AsyncHttpClient(AsyncHttpProvider provider) {
        this(provider, new Builder().build());
    }

    public AsyncHttpClient(AsyncHttpClientConfig config2) {
        this(loadDefaultProvider(DEFAULT_PROVIDER, config2), config2);
    }

    public AsyncHttpClient(AsyncHttpProvider httpProvider2, AsyncHttpClientConfig config2) {
        this.isClosed = new AtomicBoolean(false);
        this.config = config2;
        this.httpProvider = httpProvider2;
    }

    public AsyncHttpClient(String providerClass, AsyncHttpClientConfig config2) {
        this.isClosed = new AtomicBoolean(false);
        this.config = new Builder().build();
        this.httpProvider = loadDefaultProvider(providerClass, config2);
    }

    public AsyncHttpProvider getProvider() {
        return this.httpProvider;
    }

    public void close() {
        if (this.isClosed.compareAndSet(false, true)) {
            this.httpProvider.close();
        }
    }

    public void closeAsynchronously() {
        final ExecutorService e = Executors.newSingleThreadExecutor();
        e.submit(new Runnable() {
            public void run() {
                try {
                    AsyncHttpClient.this.close();
                } catch (Throwable t) {
                    AsyncHttpClient.logger.warn((String) "", t);
                } finally {
                    e.shutdown();
                }
            }
        });
    }

    /* access modifiers changed from: protected */
    public void finalize() throws Throwable {
        try {
            if (!this.isClosed.get()) {
                logger.debug("AsyncHttpClient.close() hasn't been invoked, which may produce file descriptor leaks");
            }
        } finally {
            super.finalize();
        }
    }

    public boolean isClosed() {
        return this.isClosed.get();
    }

    public AsyncHttpClientConfig getConfig() {
        return this.config;
    }

    public AsyncHttpClient setSignatureCalculator(SignatureCalculator signatureCalculator2) {
        this.signatureCalculator = signatureCalculator2;
        return this;
    }

    public BoundRequestBuilder prepareGet(String url) {
        return requestBuilder(HttpRequest.METHOD_GET, url);
    }

    public BoundRequestBuilder prepareConnect(String url) {
        return requestBuilder("CONNECT", url);
    }

    public BoundRequestBuilder prepareOptions(String url) {
        return requestBuilder(HttpRequest.METHOD_OPTIONS, url);
    }

    public BoundRequestBuilder prepareHead(String url) {
        return requestBuilder(HttpRequest.METHOD_HEAD, url);
    }

    public BoundRequestBuilder preparePost(String url) {
        return requestBuilder(HttpRequest.METHOD_POST, url);
    }

    public BoundRequestBuilder preparePut(String url) {
        return requestBuilder(HttpRequest.METHOD_PUT, url);
    }

    public BoundRequestBuilder prepareDelete(String url) {
        return requestBuilder(HttpRequest.METHOD_DELETE, url);
    }

    public BoundRequestBuilder prepareRequest(Request request) {
        return requestBuilder(request);
    }

    public <T> ListenableFuture<T> executeRequest(Request request, AsyncHandler<T> handler) throws IOException {
        FilterContext fc = preProcessRequest(new FilterContextBuilder().asyncHandler(handler).request(request).build());
        return this.httpProvider.execute(fc.getRequest(), fc.getAsyncHandler());
    }

    public ListenableFuture<Response> executeRequest(Request request) throws IOException {
        FilterContext fc = preProcessRequest(new FilterContextBuilder().asyncHandler(new AsyncCompletionHandlerBase()).request(request).build());
        return this.httpProvider.execute(fc.getRequest(), fc.getAsyncHandler());
    }

    private FilterContext preProcessRequest(FilterContext fc) throws IOException {
        for (RequestFilter asyncFilter : this.config.getRequestFilters()) {
            try {
                fc = asyncFilter.filter(fc);
                if (fc == null) {
                    throw new NullPointerException("FilterContext is null");
                }
            } catch (FilterException e) {
                IOException ex = new IOException();
                ex.initCause(e);
                throw ex;
            }
        }
        Request request = fc.getRequest();
        if (fc.getAsyncHandler() instanceof ResumableAsyncHandler) {
            request = ResumableAsyncHandler.class.cast(fc.getAsyncHandler()).adjustRequestRange(request);
        }
        if (request.getRangeOffset() != 0) {
            RequestBuilder builder = new RequestBuilder(request);
            builder.setHeader((String) "Range", "bytes=" + request.getRangeOffset() + "-");
            request = builder.build();
        }
        return new FilterContextBuilder(fc).request(request).build();
    }

    private static final AsyncHttpProvider loadDefaultProvider(String className, AsyncHttpClientConfig config2) {
        try {
            return (AsyncHttpProvider) Thread.currentThread().getContextClassLoader().loadClass(className).getDeclaredConstructor(new Class[]{AsyncHttpClientConfig.class}).newInstance(new Object[]{config2});
        } catch (Throwable th) {
            if (logger.isDebugEnabled()) {
                logger.debug((String) "Default provider not found {}. Using the {}", (Object) DEFAULT_PROVIDER, (Object) JDKAsyncHttpProvider.class.getName());
            }
            return new JDKAsyncHttpProvider(config2);
        }
    }

    /* access modifiers changed from: protected */
    public BoundRequestBuilder requestBuilder(String reqType, String url) {
        return new BoundRequestBuilder(reqType, this.config.isUseRawUrl()).setUrl(url).setSignatureCalculator(this.signatureCalculator);
    }

    /* access modifiers changed from: protected */
    public BoundRequestBuilder requestBuilder(Request prototype) {
        return new BoundRequestBuilder(prototype).setSignatureCalculator(this.signatureCalculator);
    }
}