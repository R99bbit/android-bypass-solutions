package com.ning.http.client.providers.jdk;

import com.facebook.appevents.AppEventsConstants;
import com.kakao.util.helper.CommonProtocol;
import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.AsyncHttpProviderConfig;
import com.ning.http.client.Body;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.MaxRedirectException;
import com.ning.http.client.PerRequestConfig;
import com.ning.http.client.ProgressAsyncHandler;
import com.ning.http.client.ProxyServer;
import com.ning.http.client.ProxyServer.Protocol;
import com.ning.http.client.Realm;
import com.ning.http.client.Realm.RealmBuilder;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilder;
import com.ning.http.client.Response;
import com.ning.http.client.cookie.CookieEncoder;
import com.ning.http.client.filter.FilterContext;
import com.ning.http.client.filter.FilterContext.FilterContextBuilder;
import com.ning.http.client.filter.FilterException;
import com.ning.http.client.filter.IOExceptionFilter;
import com.ning.http.client.filter.ResponseFilter;
import com.ning.http.client.listener.TransferCompletionHandler;
import com.ning.http.multipart.MultipartRequestEntity;
import com.ning.http.util.AsyncHttpProviderUtils;
import com.ning.http.util.AuthenticatorUtils;
import com.ning.http.util.MiscUtil;
import com.ning.http.util.ProxyUtils;
import com.ning.http.util.SslUtils;
import com.ning.http.util.UTF8UrlEncoder;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.Authenticator;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;
import javax.naming.AuthenticationException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JDKAsyncHttpProvider implements AsyncHttpProvider {
    private static final int MAX_BUFFERED_BYTES = 8192;
    private static final String NTLM_DOMAIN = "http.auth.ntlm.domain";
    /* access modifiers changed from: private */
    public static final Logger logger = LoggerFactory.getLogger(JDKAsyncHttpProvider.class);
    /* access modifiers changed from: private */
    public boolean bufferResponseInMemory = false;
    /* access modifiers changed from: private */
    public final AsyncHttpClientConfig config;
    private final AtomicBoolean isClose = new AtomicBoolean(false);
    /* access modifiers changed from: private */
    public Authenticator jdkAuthenticator;
    /* access modifiers changed from: private */
    public String jdkNtlmDomain;
    /* access modifiers changed from: private */
    public final AtomicInteger maxConnections = new AtomicInteger();

    private final class AsyncHttpUrlConnection<T> implements Callable<T> {
        private final AsyncHandler<T> asyncHandler;
        private byte[] cachedBytes;
        private int cachedBytesLenght;
        private int currentRedirectCount;
        private final ListenableFuture<T> future;
        private AtomicBoolean isAuth = new AtomicBoolean(false);
        private Request request;
        private boolean terminate = true;
        private HttpURLConnection urlConnection;

        public AsyncHttpUrlConnection(HttpURLConnection urlConnection2, Request request2, AsyncHandler<T> asyncHandler2, ListenableFuture<T> future2) {
            this.urlConnection = urlConnection2;
            this.request = request2;
            this.asyncHandler = asyncHandler2;
            this.future = future2;
            this.request = request2;
        }

        /* JADX WARNING: type inference failed for: r15v1, types: [java.io.InputStream] */
        /* JADX WARNING: type inference failed for: r32v1 */
        /* JADX WARNING: type inference failed for: r0v167, types: [java.io.InputStream] */
        /* JADX WARNING: Multi-variable type inference failed */
        /* JADX WARNING: Unknown variable types count: 1 */
        public T call() throws Exception {
            URI uri;
            FilterContext fc;
            Realm realm;
            int leftBytes;
            STATE state = STATE.ABORT;
            try {
                uri = AsyncHttpProviderUtils.createUri(this.request.getRawUrl());
            } catch (IllegalArgumentException e) {
                uri = AsyncHttpProviderUtils.createUri(this.request.getUrl());
            }
            try {
                configure(uri, this.urlConnection, this.request);
                this.urlConnection.connect();
                if (this.asyncHandler instanceof TransferCompletionHandler) {
                    throw new IllegalStateException(TransferCompletionHandler.class.getName() + "not supported by this provider");
                }
                int statusCode = this.urlConnection.getResponseCode();
                JDKAsyncHttpProvider.logger.debug((String) "\n\nRequest {}\n\nResponse {}\n", (Object) this.request, (Object) Integer.valueOf(statusCode));
                ResponseStatus responseStatus = new ResponseStatus(uri, this.urlConnection, JDKAsyncHttpProvider.this);
                FilterContext fc2 = new FilterContextBuilder().asyncHandler(this.asyncHandler).request(this.request).responseStatus(responseStatus).build();
                for (ResponseFilter asyncFilter : JDKAsyncHttpProvider.this.config.getResponseFilters()) {
                    fc2 = asyncFilter.filter(fc2);
                    if (fc2 == null) {
                        throw new NullPointerException("FilterContext is null");
                    }
                }
                if (fc2.replayRequest()) {
                    this.request = fc2.getRequest();
                    this.urlConnection = JDKAsyncHttpProvider.this.createUrlConnection(this.request);
                    this.terminate = false;
                    T call = call();
                    if (!this.terminate) {
                        return call;
                    }
                    if (JDKAsyncHttpProvider.this.config.getMaxTotalConnections() != -1) {
                        JDKAsyncHttpProvider.this.maxConnections.decrementAndGet();
                    }
                    this.urlConnection.disconnect();
                    if (JDKAsyncHttpProvider.this.jdkNtlmDomain != null) {
                        System.setProperty(JDKAsyncHttpProvider.NTLM_DOMAIN, JDKAsyncHttpProvider.this.jdkNtlmDomain);
                    }
                    Authenticator.setDefault(JDKAsyncHttpProvider.this.jdkAuthenticator);
                    return call;
                }
                if ((this.request.isRedirectEnabled() || JDKAsyncHttpProvider.this.config.isRedirectEnabled()) && (statusCode == 302 || statusCode == 301)) {
                    int i = this.currentRedirectCount;
                    this.currentRedirectCount = i + 1;
                    if (i < JDKAsyncHttpProvider.this.config.getMaxRedirects()) {
                        String newUrl = AsyncHttpProviderUtils.getRedirectUri(uri, this.urlConnection.getHeaderField("Location")).toString();
                        if (!newUrl.equals(uri.toString())) {
                            RequestBuilder builder = new RequestBuilder(this.request);
                            JDKAsyncHttpProvider.logger.debug((String) "Redirecting to {}", (Object) newUrl);
                            this.request = builder.setUrl(newUrl).build();
                            this.urlConnection = JDKAsyncHttpProvider.this.createUrlConnection(this.request);
                            this.terminate = false;
                            T call2 = call();
                            if (!this.terminate) {
                                return call2;
                            }
                            if (JDKAsyncHttpProvider.this.config.getMaxTotalConnections() != -1) {
                                JDKAsyncHttpProvider.this.maxConnections.decrementAndGet();
                            }
                            this.urlConnection.disconnect();
                            if (JDKAsyncHttpProvider.this.jdkNtlmDomain != null) {
                                System.setProperty(JDKAsyncHttpProvider.NTLM_DOMAIN, JDKAsyncHttpProvider.this.jdkNtlmDomain);
                            }
                            Authenticator.setDefault(JDKAsyncHttpProvider.this.jdkAuthenticator);
                            return call2;
                        }
                    } else {
                        throw new MaxRedirectException("Maximum redirect reached: " + JDKAsyncHttpProvider.this.config.getMaxRedirects());
                    }
                }
                if (this.request.getRealm() != null) {
                    realm = this.request.getRealm();
                } else {
                    realm = JDKAsyncHttpProvider.this.config.getRealm();
                }
                if (statusCode != 401 || this.isAuth.getAndSet(true) || realm == null) {
                    STATE state2 = this.asyncHandler.onStatusReceived(responseStatus);
                    if (state2 == STATE.CONTINUE) {
                        AsyncHandler<T> asyncHandler2 = this.asyncHandler;
                        ResponseHeaders responseHeaders = new ResponseHeaders(uri, this.urlConnection, JDKAsyncHttpProvider.this);
                        state2 = asyncHandler2.onHeadersReceived(responseHeaders);
                    }
                    if (state2 == STATE.CONTINUE) {
                        InputStream is = JDKAsyncHttpProvider.this.getInputStream(this.urlConnection);
                        String contentEncoding = this.urlConnection.getHeaderField("Content-Encoding");
                        if (contentEncoding == null ? false : "gzip".equalsIgnoreCase(contentEncoding)) {
                            GZIPInputStream gZIPInputStream = new GZIPInputStream(is);
                            is = gZIPInputStream;
                        }
                        int byteToRead = this.urlConnection.getContentLength();
                        ByteArrayInputStream byteArrayInputStream = is;
                        if (JDKAsyncHttpProvider.this.bufferResponseInMemory || byteToRead <= 0) {
                            int[] lengthWrapper = new int[1];
                            ByteArrayInputStream byteArrayInputStream2 = new ByteArrayInputStream(AsyncHttpProviderUtils.readFully(is, lengthWrapper), 0, lengthWrapper[0]);
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
                                int read = byteArrayInputStream.read(bytes);
                                if (read == -1) {
                                    break;
                                }
                                this.future.touch();
                                byte[] b = new byte[read];
                                System.arraycopy(bytes, 0, b, 0, read);
                                leftBytes -= read;
                                AsyncHandler<T> asyncHandler3 = this.asyncHandler;
                                ResponseBodyPart responseBodyPart = new ResponseBodyPart(uri, b, JDKAsyncHttpProvider.this, leftBytes > -1);
                                asyncHandler3.onBodyPartReceived(responseBodyPart);
                            }
                        }
                        if (this.request.getMethod().equalsIgnoreCase(HttpRequest.METHOD_HEAD)) {
                            AsyncHandler<T> asyncHandler4 = this.asyncHandler;
                            ResponseBodyPart responseBodyPart2 = new ResponseBodyPart(uri, "".getBytes(), JDKAsyncHttpProvider.this, true);
                            asyncHandler4.onBodyPartReceived(responseBodyPart2);
                        }
                    }
                    if (this.asyncHandler instanceof ProgressAsyncHandler) {
                        ProgressAsyncHandler progressAsyncHandler = (ProgressAsyncHandler) this.asyncHandler;
                        progressAsyncHandler.onHeaderWriteCompleted();
                        progressAsyncHandler.onContentWriteCompleted();
                    }
                    T t = this.asyncHandler.onCompleted();
                    this.future.content(t);
                    this.future.done();
                    if (!this.terminate) {
                        return t;
                    }
                    if (JDKAsyncHttpProvider.this.config.getMaxTotalConnections() != -1) {
                        JDKAsyncHttpProvider.this.maxConnections.decrementAndGet();
                    }
                    this.urlConnection.disconnect();
                    if (JDKAsyncHttpProvider.this.jdkNtlmDomain != null) {
                        System.setProperty(JDKAsyncHttpProvider.NTLM_DOMAIN, JDKAsyncHttpProvider.this.jdkNtlmDomain);
                    }
                    Authenticator.setDefault(JDKAsyncHttpProvider.this.jdkAuthenticator);
                    return t;
                }
                String wwwAuth = this.urlConnection.getHeaderField("WWW-Authenticate");
                JDKAsyncHttpProvider.logger.debug((String) "Sending authentication to {}", (Object) this.request.getUrl());
                this.request = ((RequestBuilder) new RequestBuilder(this.request).setRealm(new RealmBuilder().clone(realm).parseWWWAuthenticateHeader(wwwAuth).setUri(URI.create(this.request.getUrl()).getPath()).setMethodName(this.request.getMethod()).setUsePreemptiveAuth(true).build())).build();
                this.urlConnection = JDKAsyncHttpProvider.this.createUrlConnection(this.request);
                this.terminate = false;
                T call3 = call();
                if (!this.terminate) {
                    return call3;
                }
                if (JDKAsyncHttpProvider.this.config.getMaxTotalConnections() != -1) {
                    JDKAsyncHttpProvider.this.maxConnections.decrementAndGet();
                }
                this.urlConnection.disconnect();
                if (JDKAsyncHttpProvider.this.jdkNtlmDomain != null) {
                    System.setProperty(JDKAsyncHttpProvider.NTLM_DOMAIN, JDKAsyncHttpProvider.this.jdkNtlmDomain);
                }
                Authenticator.setDefault(JDKAsyncHttpProvider.this.jdkAuthenticator);
                return call3;
            } catch (Throwable t2) {
                JDKAsyncHttpProvider.logger.error(t2.getMessage(), t2);
            }
            if (this.terminate) {
                if (JDKAsyncHttpProvider.this.config.getMaxTotalConnections() != -1) {
                    JDKAsyncHttpProvider.this.maxConnections.decrementAndGet();
                }
                this.urlConnection.disconnect();
                if (JDKAsyncHttpProvider.this.jdkNtlmDomain != null) {
                    System.setProperty(JDKAsyncHttpProvider.NTLM_DOMAIN, JDKAsyncHttpProvider.this.jdkNtlmDomain);
                }
                Authenticator.setDefault(JDKAsyncHttpProvider.this.jdkAuthenticator);
            }
            return null;
        }

        private FilterContext handleIoException(FilterContext fc) throws FilterException {
            for (IOExceptionFilter asyncFilter : JDKAsyncHttpProvider.this.config.getIOExceptionFilters()) {
                fc = asyncFilter.filter(fc);
                if (fc == null) {
                    throw new NullPointerException("FilterContext is null");
                }
            }
            return fc;
        }

        private Throwable filterException(Throwable t) {
            if (t instanceof UnknownHostException) {
                return new ConnectException(t.getMessage());
            }
            if (t instanceof SocketTimeoutException) {
                int responseTimeoutInMs = JDKAsyncHttpProvider.this.config.getRequestTimeoutInMs();
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

        private void configure(URI uri, HttpURLConnection urlConnection2, Request request2) throws IOException, AuthenticationException {
            int requestTimeout;
            PerRequestConfig conf = request2.getPerRequestConfig();
            if (conf == null || conf.getRequestTimeoutInMs() == 0) {
                requestTimeout = JDKAsyncHttpProvider.this.config.getRequestTimeoutInMs();
            } else {
                requestTimeout = conf.getRequestTimeoutInMs();
            }
            urlConnection2.setConnectTimeout(JDKAsyncHttpProvider.this.config.getConnectionTimeoutInMs());
            if (requestTimeout != -1) {
                urlConnection2.setReadTimeout(requestTimeout);
            }
            urlConnection2.setInstanceFollowRedirects(false);
            String host = uri.getHost();
            String method = request2.getMethod();
            if (request2.getVirtualHost() != null) {
                host = request2.getVirtualHost();
            }
            if (uri.getPort() == -1 || request2.getVirtualHost() != null) {
                urlConnection2.setRequestProperty("Host", host);
            } else {
                urlConnection2.setRequestProperty("Host", host + ":" + uri.getPort());
            }
            if (JDKAsyncHttpProvider.this.config.isCompressionEnabled()) {
                urlConnection2.setRequestProperty("Accept-Encoding", "gzip");
            }
            if (!method.equalsIgnoreCase("CONNECT")) {
                FluentCaseInsensitiveStringsMap h = request2.getHeaders();
                if (h != null) {
                    for (String name : h.keySet()) {
                        if (!"host".equalsIgnoreCase(name)) {
                            for (String value : h.get((Object) name)) {
                                urlConnection2.setRequestProperty(name, value);
                                if (name.equalsIgnoreCase(Names.EXPECT)) {
                                    throw new IllegalStateException("Expect: 100-Continue not supported");
                                }
                            }
                            continue;
                        }
                    }
                }
            }
            String ka = AsyncHttpProviderUtils.keepAliveHeaderValue(JDKAsyncHttpProvider.this.config);
            urlConnection2.setRequestProperty("Connection", ka);
            ProxyServer proxyServer = ProxyUtils.getProxyServer(JDKAsyncHttpProvider.this.config, request2);
            if (!ProxyUtils.avoidProxy(proxyServer, uri.getHost())) {
                urlConnection2.setRequestProperty("Proxy-Connection", ka);
                if (proxyServer.getPrincipal() != null) {
                    urlConnection2.setRequestProperty("Proxy-Authorization", AuthenticatorUtils.computeBasicAuthentication(proxyServer));
                }
                if (proxyServer.getProtocol().equals(Protocol.NTLM)) {
                    JDKAsyncHttpProvider.this.jdkNtlmDomain = System.getProperty(JDKAsyncHttpProvider.NTLM_DOMAIN);
                    System.setProperty(JDKAsyncHttpProvider.NTLM_DOMAIN, proxyServer.getNtlmDomain());
                }
            }
            Realm realm = request2.getRealm() != null ? request2.getRealm() : JDKAsyncHttpProvider.this.config.getRealm();
            if (realm != null && realm.getUsePreemptiveAuth()) {
                switch (realm.getAuthScheme()) {
                    case BASIC:
                        urlConnection2.setRequestProperty("Authorization", AuthenticatorUtils.computeBasicAuthentication(realm));
                        break;
                    case DIGEST:
                        if (MiscUtil.isNonEmpty(realm.getNonce())) {
                            try {
                                r1 = "Authorization";
                                urlConnection2.setRequestProperty("Authorization", AuthenticatorUtils.computeDigestAuthentication(realm));
                                break;
                            } catch (NoSuchAlgorithmException e) {
                                SecurityException securityException = new SecurityException(e);
                                throw securityException;
                            }
                        }
                        break;
                    case NTLM:
                        JDKAsyncHttpProvider.this.jdkNtlmDomain = System.getProperty(JDKAsyncHttpProvider.NTLM_DOMAIN);
                        System.setProperty(JDKAsyncHttpProvider.NTLM_DOMAIN, realm.getDomain());
                        break;
                    case NONE:
                        break;
                    default:
                        throw new IllegalStateException(String.format("Invalid Authentication %s", new Object[]{realm.toString()}));
                }
            }
            if (request2.getHeaders().getFirstValue("Accept") == null) {
                urlConnection2.setRequestProperty("Accept", "*/*");
            }
            if (request2.getHeaders().getFirstValue("User-Agent") != null) {
                urlConnection2.setRequestProperty("User-Agent", request2.getHeaders().getFirstValue("User-Agent"));
            } else if (JDKAsyncHttpProvider.this.config.getUserAgent() != null) {
                urlConnection2.setRequestProperty("User-Agent", JDKAsyncHttpProvider.this.config.getUserAgent());
            } else {
                urlConnection2.setRequestProperty("User-Agent", AsyncHttpProviderUtils.constructUserAgent(JDKAsyncHttpProvider.class));
            }
            if (MiscUtil.isNonEmpty(request2.getCookies())) {
                urlConnection2.setRequestProperty(Names.COOKIE, CookieEncoder.encode(request2.getCookies()));
            }
            String reqType = request2.getMethod();
            urlConnection2.setRequestMethod(reqType);
            if (HttpRequest.METHOD_POST.equals(reqType) || HttpRequest.METHOD_PUT.equals(reqType)) {
                urlConnection2.setRequestProperty("Content-Length", AppEventsConstants.EVENT_PARAM_VALUE_NO);
                urlConnection2.setDoOutput(true);
                String bodyCharset = request2.getBodyEncoding() == null ? "ISO-8859-1" : request2.getBodyEncoding();
                if (this.cachedBytes != null) {
                    urlConnection2.setRequestProperty("Content-Length", String.valueOf(this.cachedBytesLenght));
                    urlConnection2.setFixedLengthStreamingMode(this.cachedBytesLenght);
                    urlConnection2.getOutputStream().write(this.cachedBytes, 0, this.cachedBytesLenght);
                } else if (request2.getByteData() != null) {
                    urlConnection2.setRequestProperty("Content-Length", String.valueOf(request2.getByteData().length));
                    urlConnection2.setFixedLengthStreamingMode(request2.getByteData().length);
                    urlConnection2.getOutputStream().write(request2.getByteData());
                } else if (request2.getStringData() != null) {
                    if (!request2.getHeaders().containsKey("Content-Type")) {
                        urlConnection2.setRequestProperty("Content-Type", "text/html;" + bodyCharset);
                    }
                    byte[] b = request2.getStringData().getBytes(bodyCharset);
                    urlConnection2.setRequestProperty("Content-Length", String.valueOf(b.length));
                    urlConnection2.getOutputStream().write(b);
                } else if (request2.getStreamData() != null) {
                    int[] lengthWrapper = new int[1];
                    this.cachedBytes = AsyncHttpProviderUtils.readFully(request2.getStreamData(), lengthWrapper);
                    this.cachedBytesLenght = lengthWrapper[0];
                    urlConnection2.setRequestProperty("Content-Length", String.valueOf(this.cachedBytesLenght));
                    urlConnection2.setFixedLengthStreamingMode(this.cachedBytesLenght);
                    urlConnection2.getOutputStream().write(this.cachedBytes, 0, this.cachedBytesLenght);
                } else if (request2.getParams() != null) {
                    StringBuilder sb = new StringBuilder();
                    Iterator<Entry<String, List<String>>> it = request2.getParams().iterator();
                    while (it.hasNext()) {
                        Entry<String, List<String>> paramEntry = it.next();
                        String key = paramEntry.getKey();
                        for (String value2 : paramEntry.getValue()) {
                            if (sb.length() > 0) {
                                sb.append("&");
                            }
                            UTF8UrlEncoder.appendEncoded(sb, key);
                            sb.append("=");
                            UTF8UrlEncoder.appendEncoded(sb, value2);
                        }
                    }
                    urlConnection2.setRequestProperty("Content-Length", String.valueOf(sb.length()));
                    urlConnection2.setFixedLengthStreamingMode(sb.length());
                    if (!request2.getHeaders().containsKey("Content-Type")) {
                        urlConnection2.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                    }
                    urlConnection2.getOutputStream().write(sb.toString().getBytes(bodyCharset));
                } else if (request2.getParts() != null) {
                    int lenght = (int) request2.getContentLength();
                    if (lenght != -1) {
                        urlConnection2.setRequestProperty("Content-Length", String.valueOf(lenght));
                        urlConnection2.setFixedLengthStreamingMode(lenght);
                    }
                    if (lenght == -1) {
                    }
                    MultipartRequestEntity mre = AsyncHttpProviderUtils.createMultipartRequestEntity(request2.getParts(), request2.getHeaders());
                    urlConnection2.setRequestProperty("Content-Type", mre.getContentType());
                    urlConnection2.setRequestProperty("Content-Length", String.valueOf(mre.getContentLength()));
                    mre.writeRequest(urlConnection2.getOutputStream());
                } else if (request2.getEntityWriter() != null) {
                    int lenght2 = (int) request2.getContentLength();
                    if (lenght2 != -1) {
                        urlConnection2.setRequestProperty("Content-Length", String.valueOf(lenght2));
                        urlConnection2.setFixedLengthStreamingMode(lenght2);
                    }
                    request2.getEntityWriter().writeEntity(urlConnection2.getOutputStream());
                } else if (request2.getFile() != null) {
                    File file = request2.getFile();
                    if (!file.isFile()) {
                        throw new IOException(String.format(Thread.currentThread() + "File %s is not a file or doesn't exist", new Object[]{file.getAbsolutePath()}));
                    }
                    urlConnection2.setRequestProperty("Content-Length", String.valueOf(file.length()));
                    urlConnection2.setFixedLengthStreamingMode((int) file.length());
                    FileInputStream fis = new FileInputStream(file);
                    try {
                        OutputStream os = urlConnection2.getOutputStream();
                        byte[] buffer = new byte[16384];
                        while (true) {
                            int read = fis.read(buffer);
                            if (read >= 0) {
                                os.write(buffer, 0, read);
                            } else {
                                return;
                            }
                        }
                    } finally {
                        fis.close();
                    }
                } else if (request2.getBodyGenerator() != null) {
                    Body body = request2.getBodyGenerator().createBody();
                    try {
                        int length = (int) body.getContentLength();
                        if (length < 0) {
                            length = (int) request2.getContentLength();
                        }
                        if (length >= 0) {
                            urlConnection2.setRequestProperty("Content-Length", String.valueOf(length));
                            urlConnection2.setFixedLengthStreamingMode(length);
                        }
                        OutputStream os2 = urlConnection2.getOutputStream();
                        ByteBuffer buffer2 = ByteBuffer.allocate(8192);
                        while (true) {
                            buffer2.clear();
                            if (body.read(buffer2) < 0) {
                                try {
                                    return;
                                } catch (IOException e2) {
                                    JDKAsyncHttpProvider.logger.warn((String) "Failed to close request body: {}", (Object) e2.getMessage(), (Object) e2);
                                    return;
                                }
                            } else {
                                os2.write(buffer2.array(), buffer2.arrayOffset(), buffer2.position());
                            }
                        }
                    } finally {
                        try {
                            body.close();
                        } catch (IOException e3) {
                            JDKAsyncHttpProvider.logger.warn((String) "Failed to close request body: {}", (Object) e3.getMessage(), (Object) e3);
                        }
                    }
                }
            }
        }
    }

    public JDKAsyncHttpProvider(AsyncHttpClientConfig config2) {
        this.config = config2;
        AsyncHttpProviderConfig<?, ?> providerConfig = config2.getAsyncHttpProviderConfig();
        if (providerConfig instanceof JDKAsyncHttpProviderConfig) {
            configure(JDKAsyncHttpProviderConfig.class.cast(providerConfig));
        }
    }

    private void configure(JDKAsyncHttpProviderConfig config2) {
        for (Entry<String, String> e : config2.propertiesSet()) {
            System.setProperty(e.getKey(), e.getValue());
        }
        if (config2.getProperty((String) JDKAsyncHttpProviderConfig.FORCE_RESPONSE_BUFFERING) != null) {
            this.bufferResponseInMemory = true;
        }
    }

    public <T> ListenableFuture<T> execute(Request request, AsyncHandler<T> handler) throws IOException {
        return execute(request, handler, null);
    }

    public <T> ListenableFuture<T> execute(Request request, AsyncHandler<T> handler, ListenableFuture<?> future) throws IOException {
        JDKFuture f;
        if (this.isClose.get()) {
            throw new IOException("Closed");
        } else if (this.config.getMaxTotalConnections() <= -1 || this.maxConnections.get() + 1 <= this.config.getMaxTotalConnections()) {
            ProxyServer proxyServer = ProxyUtils.getProxyServer(this.config, request);
            Realm realm = request.getRealm() != null ? request.getRealm() : this.config.getRealm();
            if (!(proxyServer == null && realm == null)) {
                try {
                    Proxy proxy = configureProxyAndAuth(proxyServer, realm);
                } catch (AuthenticationException e) {
                    throw new IOException(e.getMessage());
                }
            }
            HttpURLConnection urlConnection = createUrlConnection(request);
            PerRequestConfig conf = request.getPerRequestConfig();
            int requestTimeout = (conf == null || conf.getRequestTimeoutInMs() == 0) ? this.config.getRequestTimeoutInMs() : conf.getRequestTimeoutInMs();
            JDKFuture jDKFuture = null;
            if (future != null) {
                jDKFuture = new JDKDelegateFuture(handler, requestTimeout, future, urlConnection);
            }
            if (jDKFuture == null) {
                f = new JDKFuture(handler, requestTimeout, urlConnection);
            } else {
                f = jDKFuture;
            }
            f.touch();
            f.setInnerFuture(this.config.executorService().submit(new AsyncHttpUrlConnection(urlConnection, request, handler, f)));
            this.maxConnections.incrementAndGet();
            return f;
        } else {
            throw new IOException(String.format("Too many connections %s", new Object[]{Integer.valueOf(this.config.getMaxTotalConnections())}));
        }
    }

    /* access modifiers changed from: private */
    public HttpURLConnection createUrlConnection(Request request) throws IOException {
        ProxyServer proxyServer = ProxyUtils.getProxyServer(this.config, request);
        Realm realm = request.getRealm() != null ? request.getRealm() : this.config.getRealm();
        Proxy proxy = null;
        if (!(proxyServer == null && realm == null)) {
            try {
                proxy = configureProxyAndAuth(proxyServer, realm);
            } catch (AuthenticationException e) {
                throw new IOException(e.getMessage());
            }
        }
        URL url = request.getURI().toURL();
        if (proxy == null) {
            proxy = Proxy.NO_PROXY;
        }
        HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection(proxy);
        if (request.getUrl().startsWith(CommonProtocol.URL_SCHEME)) {
            HttpsURLConnection secure = (HttpsURLConnection) urlConnection;
            SSLContext sslContext = this.config.getSSLContext();
            if (sslContext == null) {
                try {
                    sslContext = SslUtils.getSSLContext();
                } catch (NoSuchAlgorithmException e2) {
                    throw new IOException(e2.getMessage());
                } catch (GeneralSecurityException e3) {
                    throw new IOException(e3.getMessage());
                }
            }
            secure.setSSLSocketFactory(sslContext.getSocketFactory());
            secure.setHostnameVerifier(this.config.getHostnameVerifier());
        }
        return urlConnection;
    }

    public void close() {
        this.isClose.set(true);
    }

    public Response prepareResponse(HttpResponseStatus status, HttpResponseHeaders headers, List<HttpResponseBodyPart> bodyParts) {
        return new JDKResponse(status, headers, bodyParts);
    }

    private Proxy configureProxyAndAuth(ProxyServer proxyServer, Realm realm) throws AuthenticationException {
        final boolean hasProxy;
        final boolean hasAuthentication = true;
        Proxy proxy = null;
        if (proxyServer != null) {
            proxy = new Proxy(Type.HTTP, new InetSocketAddress(proxyServer.getHost().startsWith("http://") ? proxyServer.getHost().substring("http://".length()) : proxyServer.getHost(), proxyServer.getPort()));
        }
        if (proxyServer == null || proxyServer.getPrincipal() == null) {
            hasProxy = false;
        } else {
            hasProxy = true;
        }
        if (realm == null || realm.getPrincipal() == null) {
            hasAuthentication = false;
        }
        if (hasProxy || hasAuthentication) {
            try {
                Field f = Authenticator.class.getDeclaredField("theAuthenticator");
                f.setAccessible(true);
                this.jdkAuthenticator = (Authenticator) f.get(Authenticator.class);
            } catch (IllegalAccessException | NoSuchFieldException e) {
            }
            final ProxyServer proxyServer2 = proxyServer;
            final Realm realm2 = realm;
            Authenticator.setDefault(new Authenticator() {
                /* access modifiers changed from: protected */
                public PasswordAuthentication getPasswordAuthentication() {
                    if (hasProxy && getRequestingHost().equals(proxyServer2.getHost()) && getRequestingPort() == proxyServer2.getPort()) {
                        String password = "";
                        if (proxyServer2.getPassword() != null) {
                            password = proxyServer2.getPassword();
                        }
                        return new PasswordAuthentication(proxyServer2.getPrincipal(), password.toCharArray());
                    } else if (hasAuthentication) {
                        return new PasswordAuthentication(realm2.getPrincipal(), realm2.getPassword().toCharArray());
                    } else {
                        return super.getPasswordAuthentication();
                    }
                }
            });
        } else {
            Authenticator.setDefault(null);
        }
        return proxy;
    }

    /* access modifiers changed from: private */
    public InputStream getInputStream(HttpURLConnection urlConnection) throws IOException {
        if (urlConnection.getResponseCode() < 400) {
            return urlConnection.getInputStream();
        }
        InputStream ein = urlConnection.getErrorStream();
        return ein == null ? new ByteArrayInputStream(new byte[0]) : ein;
    }
}