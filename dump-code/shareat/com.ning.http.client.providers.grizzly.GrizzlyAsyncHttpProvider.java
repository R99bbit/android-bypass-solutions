package com.ning.http.client.providers.grizzly;

import com.kakao.util.helper.CommonProtocol;
import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.AsyncHandlerExtensions;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.AsyncHttpProviderConfig;
import com.ning.http.client.Body;
import com.ning.http.client.BodyGenerator;
import com.ning.http.client.ConnectionsPool;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.FluentStringsMap;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.MaxRedirectException;
import com.ning.http.client.Part;
import com.ning.http.client.PerRequestConfig;
import com.ning.http.client.ProxyServer;
import com.ning.http.client.Realm;
import com.ning.http.client.Realm.RealmBuilder;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilder;
import com.ning.http.client.Response;
import com.ning.http.client.UpgradeHandler;
import com.ning.http.client.cookie.Cookie;
import com.ning.http.client.cookie.CookieDecoder;
import com.ning.http.client.filter.FilterContext;
import com.ning.http.client.filter.FilterContext.FilterContextBuilder;
import com.ning.http.client.filter.ResponseFilter;
import com.ning.http.client.listener.TransferCompletionHandler;
import com.ning.http.client.listener.TransferCompletionHandler.TransferAdapter;
import com.ning.http.client.providers.grizzly.FeedableBodyGenerator.BaseFeeder;
import com.ning.http.client.providers.grizzly.GrizzlyAsyncHttpProviderConfig.Property;
import com.ning.http.client.websocket.WebSocketByteListener;
import com.ning.http.client.websocket.WebSocketCloseCodeReasonListener;
import com.ning.http.client.websocket.WebSocketPingListener;
import com.ning.http.client.websocket.WebSocketPongListener;
import com.ning.http.client.websocket.WebSocketTextListener;
import com.ning.http.client.websocket.WebSocketUpgradeHandler;
import com.ning.http.multipart.MultipartBody;
import com.ning.http.multipart.MultipartRequestEntity;
import com.ning.http.util.AsyncHttpProviderUtils;
import com.ning.http.util.AuthenticatorUtils;
import com.ning.http.util.MiscUtil;
import com.ning.http.util.ProxyUtils;
import com.ning.http.util.SslUtils;
import com.nostra13.universalimageloader.core.download.BaseImageDownloader;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.CompletionHandler;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.Connection.CloseListener;
import org.glassfish.grizzly.Connection.CloseType;
import org.glassfish.grizzly.EmptyCompletionHandler;
import org.glassfish.grizzly.FileTransfer;
import org.glassfish.grizzly.Grizzly;
import org.glassfish.grizzly.WriteResult;
import org.glassfish.grizzly.attributes.Attribute;
import org.glassfish.grizzly.attributes.AttributeStorage;
import org.glassfish.grizzly.filterchain.BaseFilter;
import org.glassfish.grizzly.filterchain.FilterChain;
import org.glassfish.grizzly.filterchain.FilterChainBuilder;
import org.glassfish.grizzly.filterchain.FilterChainContext;
import org.glassfish.grizzly.filterchain.FilterChainEvent;
import org.glassfish.grizzly.filterchain.NextAction;
import org.glassfish.grizzly.filterchain.TransportFilter;
import org.glassfish.grizzly.http.ContentEncoding;
import org.glassfish.grizzly.http.EncodingFilter;
import org.glassfish.grizzly.http.GZipContentEncoding;
import org.glassfish.grizzly.http.HttpClientFilter;
import org.glassfish.grizzly.http.HttpContent;
import org.glassfish.grizzly.http.HttpHeader;
import org.glassfish.grizzly.http.HttpRequestPacket;
import org.glassfish.grizzly.http.HttpRequestPacket.Builder;
import org.glassfish.grizzly.http.HttpResponsePacket;
import org.glassfish.grizzly.http.Method;
import org.glassfish.grizzly.http.Protocol;
import org.glassfish.grizzly.http.util.CookieSerializerUtils;
import org.glassfish.grizzly.http.util.DataChunk;
import org.glassfish.grizzly.http.util.Header;
import org.glassfish.grizzly.http.util.HttpStatus;
import org.glassfish.grizzly.http.util.MimeHeaders;
import org.glassfish.grizzly.impl.FutureImpl;
import org.glassfish.grizzly.impl.SafeFutureImpl;
import org.glassfish.grizzly.memory.Buffers;
import org.glassfish.grizzly.memory.MemoryManager;
import org.glassfish.grizzly.nio.transport.TCPNIOConnectorHandler;
import org.glassfish.grizzly.nio.transport.TCPNIOTransport;
import org.glassfish.grizzly.nio.transport.TCPNIOTransportBuilder;
import org.glassfish.grizzly.ssl.SSLEngineConfigurator;
import org.glassfish.grizzly.ssl.SSLFilter;
import org.glassfish.grizzly.strategies.SameThreadIOStrategy;
import org.glassfish.grizzly.strategies.WorkerThreadIOStrategy;
import org.glassfish.grizzly.utils.BufferOutputStream;
import org.glassfish.grizzly.utils.Charsets;
import org.glassfish.grizzly.utils.DelayedExecutor;
import org.glassfish.grizzly.utils.DelayedExecutor.Resolver;
import org.glassfish.grizzly.utils.Futures;
import org.glassfish.grizzly.utils.IdleTimeoutFilter;
import org.glassfish.grizzly.utils.IdleTimeoutFilter.TimeoutHandler;
import org.glassfish.grizzly.utils.IdleTimeoutFilter.TimeoutResolver;
import org.glassfish.grizzly.websockets.ClosingFrame;
import org.glassfish.grizzly.websockets.DataFrame;
import org.glassfish.grizzly.websockets.HandShake;
import org.glassfish.grizzly.websockets.ProtocolHandler;
import org.glassfish.grizzly.websockets.SimpleWebSocket;
import org.glassfish.grizzly.websockets.Version;
import org.glassfish.grizzly.websockets.WebSocket;
import org.glassfish.grizzly.websockets.WebSocketFilter;
import org.glassfish.grizzly.websockets.WebSocketHolder;
import org.glassfish.grizzly.websockets.WebSocketListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GrizzlyAsyncHttpProvider implements AsyncHttpProvider {
    /* access modifiers changed from: private */
    public static final Logger LOGGER = LoggerFactory.getLogger(GrizzlyAsyncHttpProvider.class);
    private static final Attribute<HttpTransactionContext> REQUEST_STATE_ATTR = Grizzly.DEFAULT_ATTRIBUTE_BUILDER.createAttribute(HttpTransactionContext.class.getName());
    /* access modifiers changed from: private */
    public static final boolean SEND_FILE_SUPPORT = false;
    private final BodyHandlerFactory bodyHandlerFactory = new BodyHandlerFactory();
    /* access modifiers changed from: private */
    public final AsyncHttpClientConfig clientConfig;
    private final TCPNIOTransport clientTransport;
    /* access modifiers changed from: private */
    public final ConnectionManager connectionManager;
    Resolver<Connection> resolver;
    private DelayedExecutor timeoutExecutor;

    private static final class AHCWebSocketListenerAdapter implements WebSocketListener {
        private final com.ning.http.client.websocket.WebSocketListener ahcListener;
        private final ByteArrayOutputStream byteArrayOutputStream;
        private final StringBuilder stringBuffer;
        private final GrizzlyWebSocketAdapter webSocket;

        AHCWebSocketListenerAdapter(com.ning.http.client.websocket.WebSocketListener ahcListener2, GrizzlyWebSocketAdapter webSocket2) {
            this.ahcListener = ahcListener2;
            this.webSocket = webSocket2;
            if (webSocket2.bufferFragments) {
                this.stringBuffer = new StringBuilder();
                this.byteArrayOutputStream = new ByteArrayOutputStream();
                return;
            }
            this.stringBuffer = null;
            this.byteArrayOutputStream = null;
        }

        public void onClose(WebSocket gWebSocket, DataFrame dataFrame) {
            try {
                if (this.ahcListener instanceof WebSocketCloseCodeReasonListener) {
                    ClosingFrame cf = ClosingFrame.class.cast(dataFrame);
                    WebSocketCloseCodeReasonListener.class.cast(this.ahcListener).onClose(this.webSocket, cf.getCode(), cf.getReason());
                    return;
                }
                this.ahcListener.onClose(this.webSocket);
            } catch (Throwable e) {
                this.ahcListener.onError(e);
            }
        }

        public void onConnect(WebSocket gWebSocket) {
            try {
                this.ahcListener.onOpen(this.webSocket);
            } catch (Throwable e) {
                this.ahcListener.onError(e);
            }
        }

        public void onMessage(WebSocket webSocket2, String s) {
            try {
                if (this.ahcListener instanceof WebSocketTextListener) {
                    WebSocketTextListener.class.cast(this.ahcListener).onMessage(s);
                }
            } catch (Throwable e) {
                this.ahcListener.onError(e);
            }
        }

        public void onMessage(WebSocket webSocket2, byte[] bytes) {
            try {
                if (this.ahcListener instanceof WebSocketByteListener) {
                    WebSocketByteListener.class.cast(this.ahcListener).onMessage(bytes);
                }
            } catch (Throwable e) {
                this.ahcListener.onError(e);
            }
        }

        public void onPing(WebSocket webSocket2, byte[] bytes) {
            try {
                if (this.ahcListener instanceof WebSocketPingListener) {
                    WebSocketPingListener.class.cast(this.ahcListener).onPing(bytes);
                }
            } catch (Throwable e) {
                this.ahcListener.onError(e);
            }
        }

        public void onPong(WebSocket webSocket2, byte[] bytes) {
            try {
                if (this.ahcListener instanceof WebSocketPongListener) {
                    WebSocketPongListener.class.cast(this.ahcListener).onPong(bytes);
                }
            } catch (Throwable e) {
                this.ahcListener.onError(e);
            }
        }

        public void onFragment(WebSocket webSocket2, String s, boolean last) {
            try {
                if (this.webSocket.bufferFragments) {
                    synchronized (this.webSocket) {
                        this.stringBuffer.append(s);
                        if (last && (this.ahcListener instanceof WebSocketTextListener)) {
                            String message = this.stringBuffer.toString();
                            this.stringBuffer.setLength(0);
                            WebSocketTextListener.class.cast(this.ahcListener).onMessage(message);
                        }
                    }
                } else if (this.ahcListener instanceof WebSocketTextListener) {
                    WebSocketTextListener.class.cast(this.ahcListener).onFragment(s, last);
                }
            } catch (Throwable e) {
                this.ahcListener.onError(e);
            }
        }

        public void onFragment(WebSocket webSocket2, byte[] bytes, boolean last) {
            try {
                if (this.webSocket.bufferFragments) {
                    synchronized (this.webSocket) {
                        this.byteArrayOutputStream.write(bytes);
                        if (last && (this.ahcListener instanceof WebSocketByteListener)) {
                            byte[] bytesLocal = this.byteArrayOutputStream.toByteArray();
                            this.byteArrayOutputStream.reset();
                            WebSocketByteListener.class.cast(this.ahcListener).onMessage(bytesLocal);
                        }
                    }
                } else if (this.ahcListener instanceof WebSocketByteListener) {
                    WebSocketByteListener.class.cast(this.ahcListener).onFragment(bytes, last);
                }
            } catch (Throwable e) {
                this.ahcListener.onError(e);
            }
        }

        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            AHCWebSocketListenerAdapter that = (AHCWebSocketListenerAdapter) o;
            if (this.ahcListener == null ? that.ahcListener != null : !this.ahcListener.equals(that.ahcListener)) {
                return false;
            }
            if (this.webSocket != null) {
                if (this.webSocket.equals(that.webSocket)) {
                    return true;
                }
            } else if (that.webSocket == null) {
                return true;
            }
            return false;
        }

        public int hashCode() {
            int result;
            int i = 0;
            if (this.ahcListener != null) {
                result = this.ahcListener.hashCode();
            } else {
                result = 0;
            }
            int i2 = result * 31;
            if (this.webSocket != null) {
                i = this.webSocket.hashCode();
            }
            return i2 + i;
        }
    }

    private static final class AsyncHttpClientEventFilter extends HttpClientFilter {
        private final Map<Integer, StatusHandler> HANDLER_MAP = new HashMap();
        private final GrizzlyAsyncHttpProvider provider;

        private static final class AuthorizationHandler implements StatusHandler {
            /* access modifiers changed from: private */
            public static final AuthorizationHandler INSTANCE = new AuthorizationHandler();

            private AuthorizationHandler() {
            }

            public boolean handlesStatus(int statusCode) {
                return HttpStatus.UNAUTHORIZED_401.statusMatches(statusCode);
            }

            public boolean handleStatus(HttpResponsePacket responsePacket, HttpTransactionContext httpTransactionContext, FilterChainContext ctx) {
                String auth = responsePacket.getHeader(Header.WWWAuthenticate);
                if (auth == null) {
                    throw new IllegalStateException("401 response received, but no WWW-Authenticate header was present");
                }
                Realm realm = httpTransactionContext.request.getRealm();
                if (realm == null) {
                    realm = httpTransactionContext.provider.clientConfig.getRealm();
                }
                if (realm == null) {
                    httpTransactionContext.invocationStatus = InvocationStatus.STOP;
                    if (httpTransactionContext.handler != null) {
                        try {
                            httpTransactionContext.handler.onStatusReceived(httpTransactionContext.responseStatus);
                        } catch (Exception e) {
                            httpTransactionContext.abort(e);
                        }
                    }
                    return true;
                }
                responsePacket.setSkipRemainder(true);
                Request req = httpTransactionContext.request;
                Realm realm2 = new RealmBuilder().clone(realm).setScheme(realm.getAuthScheme()).setUri(httpTransactionContext.request.getURI().getPath()).setMethodName(req.getMethod()).setUsePreemptiveAuth(true).parseWWWAuthenticateHeader(auth).build();
                String lowerCaseAuth = auth.toLowerCase(Locale.ENGLISH);
                if (lowerCaseAuth.startsWith("basic")) {
                    req.getHeaders().remove((Object) Header.Authorization.toString());
                    try {
                        req.getHeaders().add(Header.Authorization.toString(), AuthenticatorUtils.computeBasicAuthentication(realm2));
                    } catch (UnsupportedEncodingException e2) {
                    }
                } else if (lowerCaseAuth.startsWith("digest")) {
                    req.getHeaders().remove((Object) Header.Authorization.toString());
                    try {
                        req.getHeaders().add(Header.Authorization.toString(), AuthenticatorUtils.computeDigestAuthentication(realm2));
                    } catch (NoSuchAlgorithmException e3) {
                        throw new IllegalStateException("Digest authentication not supported", e3);
                    } catch (UnsupportedEncodingException e4) {
                        throw new IllegalStateException("Unsupported encoding.", e4);
                    }
                } else {
                    throw new IllegalStateException("Unsupported authorization method: " + auth);
                }
                try {
                    Connection c = httpTransactionContext.provider.connectionManager.obtainConnection(req, httpTransactionContext.future);
                    HttpTransactionContext newContext = httpTransactionContext.copy();
                    httpTransactionContext.future = null;
                    GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = httpTransactionContext.provider;
                    GrizzlyAsyncHttpProvider.setHttpTransactionContext(c, newContext);
                    newContext.invocationStatus = InvocationStatus.STOP;
                    try {
                        httpTransactionContext.provider.execute(c, req, httpTransactionContext.handler, httpTransactionContext.future);
                        return false;
                    } catch (IOException ioe) {
                        newContext.abort(ioe);
                        return false;
                    }
                } catch (Exception e5) {
                    httpTransactionContext.abort(e5);
                    httpTransactionContext.invocationStatus = InvocationStatus.STOP;
                    return false;
                }
            }
        }

        private static final class RedirectHandler implements StatusHandler {
            /* access modifiers changed from: private */
            public static final RedirectHandler INSTANCE = new RedirectHandler();

            private RedirectHandler() {
            }

            public boolean handlesStatus(int statusCode) {
                return AsyncHttpClientEventFilter.isRedirect(statusCode);
            }

            public boolean handleStatus(HttpResponsePacket responsePacket, HttpTransactionContext httpTransactionContext, FilterChainContext ctx) {
                URI orig;
                String redirectURL = responsePacket.getHeader(Header.Location);
                if (redirectURL == null) {
                    throw new IllegalStateException("redirect received, but no location header was present");
                }
                if (httpTransactionContext.lastRedirectURI == null) {
                    orig = httpTransactionContext.request.getURI();
                } else {
                    orig = AsyncHttpProviderUtils.getRedirectUri(httpTransactionContext.request.getURI(), httpTransactionContext.lastRedirectURI);
                }
                httpTransactionContext.lastRedirectURI = redirectURL;
                URI uri = AsyncHttpProviderUtils.getRedirectUri(orig, redirectURL);
                if (!uri.toString().equalsIgnoreCase(orig.toString())) {
                    Request requestToSend = AsyncHttpClientEventFilter.newRequest(uri, responsePacket, httpTransactionContext, sendAsGet(responsePacket, httpTransactionContext));
                    try {
                        Connection c = httpTransactionContext.provider.connectionManager.obtainConnection(requestToSend, httpTransactionContext.future);
                        if (switchingSchemes(orig, uri)) {
                            try {
                                notifySchemeSwitch(ctx, c, uri);
                            } catch (IOException ioe) {
                                httpTransactionContext.abort(ioe);
                            }
                        }
                        HttpTransactionContext newContext = httpTransactionContext.copy();
                        httpTransactionContext.future = null;
                        newContext.invocationStatus = InvocationStatus.CONTINUE;
                        newContext.request = requestToSend;
                        newContext.requestUrl = requestToSend.getUrl();
                        GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = httpTransactionContext.provider;
                        GrizzlyAsyncHttpProvider.setHttpTransactionContext(c, newContext);
                        httpTransactionContext.provider.execute(c, requestToSend, newContext.handler, newContext.future);
                        return false;
                    } catch (Exception e) {
                        httpTransactionContext.abort(e);
                        httpTransactionContext.invocationStatus = InvocationStatus.CONTINUE;
                        return true;
                    }
                } else {
                    httpTransactionContext.statusHandler = null;
                    httpTransactionContext.invocationStatus = InvocationStatus.CONTINUE;
                    try {
                        httpTransactionContext.handler.onStatusReceived(httpTransactionContext.responseStatus);
                    } catch (Exception e2) {
                        httpTransactionContext.abort(e2);
                    }
                    return true;
                }
            }

            private boolean sendAsGet(HttpResponsePacket response, HttpTransactionContext ctx) {
                int statusCode = response.getStatus();
                return statusCode >= 302 && statusCode <= 303 && (statusCode != 302 || !ctx.provider.clientConfig.isStrict302Handling());
            }

            private boolean switchingSchemes(URI oldUri, URI newUri) {
                return !oldUri.getScheme().equals(newUri.getScheme());
            }

            private void notifySchemeSwitch(FilterChainContext ctx, Connection c, URI uri) throws IOException {
                ctx.notifyDownstream(new SSLSwitchingEvent(CommonProtocol.URL_SCHEME.equals(uri.getScheme()), c));
            }
        }

        AsyncHttpClientEventFilter(GrizzlyAsyncHttpProvider provider2, int maxHerdersSizeProperty) {
            super(maxHerdersSizeProperty);
            this.provider = provider2;
            this.HANDLER_MAP.put(Integer.valueOf(HttpStatus.UNAUTHORIZED_401.getStatusCode()), AuthorizationHandler.INSTANCE);
            this.HANDLER_MAP.put(Integer.valueOf(HttpStatus.MOVED_PERMANENTLY_301.getStatusCode()), RedirectHandler.INSTANCE);
            this.HANDLER_MAP.put(Integer.valueOf(HttpStatus.FOUND_302.getStatusCode()), RedirectHandler.INSTANCE);
            this.HANDLER_MAP.put(Integer.valueOf(HttpStatus.TEMPORARY_REDIRECT_307.getStatusCode()), RedirectHandler.INSTANCE);
        }

        public void exceptionOccurred(FilterChainContext ctx, Throwable error) {
            GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = this.provider;
            GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection()).abort(error);
        }

        /* access modifiers changed from: protected */
        public void onHttpContentParsed(HttpContent content, FilterChainContext ctx) {
            GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = this.provider;
            HttpTransactionContext context = GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection());
            AsyncHandler handler = context.handler;
            if (handler != null && context.currentState != STATE.ABORT) {
                try {
                    context.currentState = handler.onBodyPartReceived(new GrizzlyResponseBodyPart(content, null, ctx.getConnection(), this.provider));
                } catch (Exception e) {
                    handler.onThrowable(e);
                }
            }
        }

        /* access modifiers changed from: protected */
        public void onHttpHeadersEncoded(HttpHeader httpHeader, FilterChainContext ctx) {
            GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = this.provider;
            AsyncHandler handler = GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection()).handler;
            if (handler instanceof TransferCompletionHandler) {
                ((TransferCompletionHandler) handler).onHeaderWriteCompleted();
            }
            if (handler instanceof AsyncHandlerExtensions) {
                ((AsyncHandlerExtensions) handler).onRequestSent();
            }
        }

        /* access modifiers changed from: protected */
        public void onHttpContentEncoded(HttpContent content, FilterChainContext ctx) {
            GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = this.provider;
            HttpTransactionContext context = GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection());
            AsyncHandler handler = context.handler;
            if (handler instanceof TransferCompletionHandler) {
                int written = content.getContent().remaining();
                ((TransferCompletionHandler) handler).onContentWriteProgress((long) written, context.totalBodyWritten.addAndGet((long) written), content.getHttpHeader().getContentLength());
            }
        }

        /* access modifiers changed from: protected */
        public void onInitialLineParsed(HttpHeader httpHeader, FilterChainContext ctx) {
            GrizzlyAsyncHttpProvider.super.onInitialLineParsed(httpHeader, ctx);
            if (!httpHeader.isSkipRemainder()) {
                Connection connection = ctx.getConnection();
                GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = this.provider;
                HttpTransactionContext context = GrizzlyAsyncHttpProvider.getHttpTransactionContext(connection);
                int status = ((HttpResponsePacket) httpHeader).getStatus();
                if (context.establishingTunnel && HttpStatus.OK_200.statusMatches(status)) {
                    return;
                }
                if (HttpStatus.CONINTUE_100.statusMatches(status)) {
                    ctx.notifyUpstream(new ContinueEvent(context));
                    return;
                }
                if (context.statusHandler == null || context.statusHandler.handlesStatus(status)) {
                    context.statusHandler = null;
                } else {
                    context.statusHandler = null;
                    context.invocationStatus = InvocationStatus.CONTINUE;
                }
                if (context.invocationStatus == InvocationStatus.CONTINUE) {
                    if (this.HANDLER_MAP.containsKey(Integer.valueOf(status))) {
                        context.statusHandler = this.HANDLER_MAP.get(Integer.valueOf(status));
                    }
                    if ((context.statusHandler instanceof RedirectHandler) && !isRedirectAllowed(context)) {
                        context.statusHandler = null;
                    }
                }
                if (isRedirectAllowed(context)) {
                    if (isRedirect(status)) {
                        if (context.statusHandler == null) {
                            context.statusHandler = RedirectHandler.INSTANCE;
                        }
                        context.redirectCount.incrementAndGet();
                        if (redirectCountExceeded(context)) {
                            httpHeader.setSkipRemainder(true);
                            context.abort(new MaxRedirectException());
                        }
                    } else if (context.redirectCount.get() > 0) {
                        context.redirectCount.set(0);
                    }
                }
                GrizzlyResponseStatus responseStatus = new GrizzlyResponseStatus((HttpResponsePacket) httpHeader, context.request.getURI(), this.provider);
                context.responseStatus = responseStatus;
                if (context.statusHandler == null && context.currentState != STATE.ABORT) {
                    try {
                        AsyncHandler handler = context.handler;
                        if (handler != null) {
                            context.currentState = handler.onStatusReceived(responseStatus);
                            if (context.isWSRequest && context.currentState == STATE.ABORT) {
                                httpHeader.setSkipRemainder(true);
                                try {
                                    context.result(handler.onCompleted());
                                    context.done();
                                } catch (Exception e) {
                                    context.abort(e);
                                }
                            }
                        }
                    } catch (Exception e2) {
                        httpHeader.setSkipRemainder(true);
                        context.abort(e2);
                    }
                }
            }
        }

        /* access modifiers changed from: protected */
        public void onHttpHeaderError(HttpHeader httpHeader, FilterChainContext ctx, Throwable t) throws IOException {
            t.printStackTrace();
            httpHeader.setSkipRemainder(true);
            GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = this.provider;
            GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection()).abort(t);
        }

        /* access modifiers changed from: protected */
        public void onHttpHeadersParsed(HttpHeader httpHeader, FilterChainContext ctx) {
            GrizzlyAsyncHttpProvider.super.onHttpHeadersParsed(httpHeader, ctx);
            GrizzlyAsyncHttpProvider.LOGGER.debug((String) "RESPONSE: {}", (Object) httpHeader);
            if (httpHeader.containsHeader(Header.Connection) && "close".equals(httpHeader.getHeader(Header.Connection))) {
                ConnectionManager.markConnectionAsDoNotCache(ctx.getConnection());
            }
            GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = this.provider;
            HttpTransactionContext context = GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection());
            if (!httpHeader.isSkipRemainder() && !context.establishingTunnel) {
                AsyncHandler handler = context.handler;
                List<ResponseFilter> filters = context.provider.clientConfig.getResponseFilters();
                GrizzlyResponseHeaders grizzlyResponseHeaders = new GrizzlyResponseHeaders((HttpResponsePacket) httpHeader, context.request.getURI(), this.provider);
                if (!filters.isEmpty()) {
                    FilterContext fc = new FilterContextBuilder().asyncHandler(handler).request(context.request).responseHeaders(grizzlyResponseHeaders).responseStatus(context.responseStatus).build();
                    try {
                        for (ResponseFilter f : filters) {
                            fc = f.filter(fc);
                        }
                    } catch (Exception e) {
                        context.abort(e);
                    }
                    if (fc.replayRequest()) {
                        httpHeader.setSkipRemainder(true);
                        Request newRequest = fc.getRequest();
                        AsyncHandler newHandler = fc.getAsyncHandler();
                        try {
                            Connection c = context.provider.connectionManager.obtainConnection(newRequest, context.future);
                            HttpTransactionContext newContext = context.copy();
                            context.future = null;
                            GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider2 = this.provider;
                            GrizzlyAsyncHttpProvider.setHttpTransactionContext(c, newContext);
                            try {
                                context.provider.execute(c, newRequest, newHandler, context.future);
                                return;
                            } catch (IOException ioe) {
                                newContext.abort(ioe);
                                return;
                            }
                        } catch (Exception e2) {
                            context.abort(e2);
                            return;
                        }
                    }
                }
                if (context.statusHandler != null && context.invocationStatus == InvocationStatus.CONTINUE && !context.statusHandler.handleStatus((HttpResponsePacket) httpHeader, context, ctx)) {
                    httpHeader.setSkipRemainder(true);
                } else if (context.isWSRequest) {
                    try {
                        context.protocolHandler.setConnection(ctx.getConnection());
                        GrizzlyWebSocketAdapter webSocketAdapter = createWebSocketAdapter(context);
                        context.webSocket = webSocketAdapter;
                        SimpleWebSocket ws = webSocketAdapter.gWebSocket;
                        if (context.currentState == STATE.UPGRADE) {
                            httpHeader.setChunked(false);
                            ws.onConnect();
                            WebSocketHolder.set(ctx.getConnection(), context.protocolHandler, ws);
                            ((WebSocketUpgradeHandler) context.handler).onSuccess(context.webSocket);
                            int wsTimeout = context.provider.clientConfig.getWebSocketIdleTimeoutInMs();
                            IdleTimeoutFilter.setCustomTimeout(ctx.getConnection(), wsTimeout <= 0 ? IdleTimeoutFilter.FOREVER.longValue() : (long) wsTimeout, TimeUnit.MILLISECONDS);
                            context.result(handler.onCompleted());
                            return;
                        }
                        httpHeader.setSkipRemainder(true);
                        ((WebSocketUpgradeHandler) context.handler).onClose(context.webSocket, 1002, "WebSocket protocol error: unexpected HTTP response status during handshake.");
                        context.result(null);
                    } catch (Exception e3) {
                        httpHeader.setSkipRemainder(true);
                        context.abort(e3);
                    }
                } else if (context.currentState != STATE.ABORT) {
                    try {
                        context.currentState = handler.onHeadersReceived(grizzlyResponseHeaders);
                    } catch (Exception e4) {
                        httpHeader.setSkipRemainder(true);
                        context.abort(e4);
                    }
                }
            }
        }

        /* access modifiers changed from: protected */
        public boolean onHttpPacketParsed(HttpHeader httpHeader, FilterChainContext ctx) {
            if (httpHeader.isSkipRemainder()) {
                clearResponse(ctx.getConnection());
                cleanup(ctx, this.provider);
                return false;
            }
            boolean onHttpPacketParsed = GrizzlyAsyncHttpProvider.super.onHttpPacketParsed(httpHeader, ctx);
            GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = this.provider;
            HttpTransactionContext context = GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection());
            if (!context.establishingTunnel || !HttpStatus.OK_200.statusMatches(((HttpResponsePacket) httpHeader).getStatus())) {
                cleanup(ctx, this.provider);
                AsyncHandler handler = context.handler;
                if (handler != null) {
                    try {
                        context.result(handler.onCompleted());
                        return onHttpPacketParsed;
                    } catch (Exception e) {
                        context.abort(e);
                        return onHttpPacketParsed;
                    }
                } else {
                    context.done();
                    return onHttpPacketParsed;
                }
            } else {
                context.establishingTunnel = false;
                Connection c = ctx.getConnection();
                context.tunnelEstablished(c);
                try {
                    context.provider.execute(c, context.request, context.handler, context.future);
                    return onHttpPacketParsed;
                } catch (IOException e2) {
                    context.abort(e2);
                    return onHttpPacketParsed;
                }
            }
        }

        private static GrizzlyWebSocketAdapter createWebSocketAdapter(HttpTransactionContext context) {
            SimpleWebSocket ws = new SimpleWebSocket(context.protocolHandler, new WebSocketListener[0]);
            AsyncHttpProviderConfig config = context.provider.clientConfig.getAsyncHttpProviderConfig();
            boolean bufferFragments = true;
            if (config instanceof GrizzlyAsyncHttpProviderConfig) {
                bufferFragments = ((Boolean) ((GrizzlyAsyncHttpProviderConfig) config).getProperty(Property.BUFFER_WEBSOCKET_FRAGMENTS)).booleanValue();
            }
            return new GrizzlyWebSocketAdapter(ws, bufferFragments);
        }

        private static boolean isRedirectAllowed(HttpTransactionContext ctx) {
            boolean allowed = ctx.request.isRedirectEnabled();
            if (ctx.request.isRedirectOverrideSet()) {
                return allowed;
            }
            if (!allowed) {
                allowed = ctx.redirectsAllowed;
            }
            return allowed;
        }

        private static HttpTransactionContext cleanup(FilterChainContext ctx, GrizzlyAsyncHttpProvider provider2) {
            Connection c = ctx.getConnection();
            HttpTransactionContext context = GrizzlyAsyncHttpProvider.getHttpTransactionContext(c);
            GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = context.provider;
            GrizzlyAsyncHttpProvider.setHttpTransactionContext(c, null);
            if (!context.provider.connectionManager.canReturnConnection(c)) {
                context.abort(new IOException("Maximum pooled connections exceeded"));
            } else if (!context.provider.connectionManager.returnConnection(context.request, c)) {
                ctx.getConnection().close();
            }
            return context;
        }

        private static boolean redirectCountExceeded(HttpTransactionContext context) {
            return context.redirectCount.get() > context.maxRedirectCount;
        }

        /* access modifiers changed from: private */
        public static boolean isRedirect(int status) {
            return HttpStatus.MOVED_PERMANENTLY_301.statusMatches(status) || HttpStatus.FOUND_302.statusMatches(status) || HttpStatus.SEE_OTHER_303.statusMatches(status) || HttpStatus.TEMPORARY_REDIRECT_307.statusMatches(status);
        }

        /* access modifiers changed from: private */
        public static Request newRequest(URI uri, HttpResponsePacket response, HttpTransactionContext ctx, boolean asGet) {
            RequestBuilder builder = new RequestBuilder(ctx.request);
            if (asGet) {
                builder.setMethod((String) HttpRequest.METHOD_GET);
            }
            builder.setUrl(uri.toString());
            if (ctx.provider.clientConfig.isRemoveQueryParamOnRedirect()) {
                builder.setQueryParameters((FluentStringsMap) null);
            }
            for (String cookieStr : response.getHeaders().values(Header.Cookie)) {
                builder.addOrReplaceCookie(CookieDecoder.decode(cookieStr));
            }
            return builder.build();
        }
    }

    private final class AsyncHttpClientFilter extends BaseFilter {
        private final AsyncHttpClientConfig config;

        AsyncHttpClientFilter(AsyncHttpClientConfig config2) {
            this.config = config2;
        }

        public NextAction handleWrite(FilterChainContext ctx) throws IOException {
            Object message = ctx.getMessage();
            if (message instanceof Request) {
                ctx.setMessage(null);
                if (!sendAsGrizzlyRequest((Request) message, ctx)) {
                    return ctx.getSuspendAction();
                }
            } else if (message instanceof Buffer) {
                return ctx.getInvokeAction();
            }
            return ctx.getStopAction();
        }

        public NextAction handleEvent(FilterChainContext ctx, FilterChainEvent event) throws IOException {
            if (event.type() == ContinueEvent.class) {
                ((ExpectHandler) ((ContinueEvent) event).context.bodyHandler).finish(ctx);
            }
            return ctx.getStopAction();
        }

        private boolean sendAsGrizzlyRequest(Request request, FilterChainContext ctx) throws IOException {
            HttpRequestPacket requestPacket;
            HttpTransactionContext httpCtx = GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection());
            if (isUpgradeRequest(httpCtx.handler)) {
                if (isWSRequest(httpCtx.requestUrl)) {
                    httpCtx.isWSRequest = true;
                    convertToUpgradeRequest(httpCtx);
                }
            }
            Request req = httpCtx.request;
            URI uri = req.isUseRawUrl() ? req.getRawURI() : req.getURI();
            Builder builder = HttpRequestPacket.builder();
            boolean secure = CommonProtocol.URL_SCHEME.equals(uri.getScheme());
            builder.method(request.getMethod());
            builder.protocol(Protocol.HTTP_1_1);
            String host = request.getVirtualHost();
            if (host != null) {
                builder.header(Header.Host, host);
            } else if (uri.getPort() == -1) {
                builder.header(Header.Host, uri.getHost());
            } else {
                builder.header(Header.Host, uri.getHost() + ':' + uri.getPort());
            }
            ProxyServer proxy = ProxyUtils.getProxyServer(this.config, request);
            boolean useProxy = proxy != null;
            if (!useProxy) {
                builder.uri(uri.getPath());
            } else if ((secure || httpCtx.isWSRequest) && !httpCtx.isTunnelEstablished(ctx.getConnection())) {
                secure = false;
                httpCtx.establishingTunnel = true;
                builder.method(Method.CONNECT);
                builder.uri(AsyncHttpProviderUtils.getAuthority(uri));
            } else if (!secure || !this.config.isUseRelativeURIsWithSSLProxies()) {
                builder.uri(uri.toString());
            } else {
                builder.uri(uri.getPath());
            }
            if (GrizzlyAsyncHttpProvider.requestHasEntityBody(request)) {
                long contentLength = request.getContentLength();
                if (contentLength >= 0) {
                    builder.contentLength(contentLength);
                    builder.chunked(false);
                } else {
                    builder.chunked(true);
                }
            }
            if (!httpCtx.isWSRequest || httpCtx.establishingTunnel) {
                requestPacket = builder.build();
            } else {
                try {
                    URI wsURI = new URI(httpCtx.wsRequestURI);
                    secure = "wss".equalsIgnoreCase(wsURI.getScheme());
                    httpCtx.protocolHandler = Version.RFC6455.createHandler(true);
                    httpCtx.handshake = httpCtx.protocolHandler.createHandShake(wsURI);
                    requestPacket = (HttpRequestPacket) httpCtx.handshake.composeHeaders().getHttpHeader();
                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException("Invalid WS URI: " + httpCtx.wsRequestURI);
                }
            }
            requestPacket.setSecure(secure);
            SSLSwitchingEvent sSLSwitchingEvent = new SSLSwitchingEvent(secure, ctx.getConnection());
            ctx.notifyDownstream(sSLSwitchingEvent);
            if (!useProxy && !httpCtx.isWSRequest) {
                requestPacket.setQueryString(uri.getRawQuery());
            }
            addHeaders(request, requestPacket);
            addCookies(request, requestPacket);
            if (useProxy) {
                if (!requestPacket.getHeaders().contains(Header.ProxyConnection)) {
                    requestPacket.setHeader(Header.ProxyConnection, "keep-alive");
                }
                if (proxy.getPrincipal() != null) {
                    requestPacket.setHeader(Header.ProxyAuthorization, AuthenticatorUtils.computeBasicAuthentication(proxy));
                }
            }
            AsyncHandler h = httpCtx.handler;
            if (h instanceof TransferCompletionHandler) {
                GrizzlyTransferAdapter grizzlyTransferAdapter = new GrizzlyTransferAdapter(new FluentCaseInsensitiveStringsMap(request.getHeaders()));
                TransferCompletionHandler.class.cast(h).transferAdapter(grizzlyTransferAdapter);
            }
            return GrizzlyAsyncHttpProvider.this.sendRequest(ctx, request, requestPacket);
        }

        private boolean isUpgradeRequest(AsyncHandler handler) {
            return handler instanceof UpgradeHandler;
        }

        private boolean isWSRequest(String requestUri) {
            return requestUri.charAt(0) == 'w' && requestUri.charAt(1) == 's';
        }

        private void convertToUpgradeRequest(HttpTransactionContext ctx) {
            int colonIdx = ctx.requestUrl.indexOf(58);
            if (colonIdx < 2 || colonIdx > 3) {
                throw new IllegalArgumentException("Invalid websocket URL: " + ctx.requestUrl);
            }
            StringBuilder sb = new StringBuilder(ctx.requestUrl);
            sb.replace(0, colonIdx, colonIdx == 2 ? "http" : CommonProtocol.URL_SCHEME);
            ctx.wsRequestURI = ctx.requestUrl;
            ctx.requestUrl = sb.toString();
        }

        private void addHeaders(Request request, HttpRequestPacket requestPacket) {
            FluentCaseInsensitiveStringsMap map = request.getHeaders();
            if (MiscUtil.isNonEmpty((Map<?, ?>) map)) {
                for (Entry<String, List<String>> entry : map.entrySet()) {
                    String headerName = entry.getKey();
                    List<String> headerValues = entry.getValue();
                    if (MiscUtil.isNonEmpty((Collection<?>) headerValues)) {
                        for (String headerValue : headerValues) {
                            requestPacket.addHeader(headerName, headerValue);
                        }
                    }
                }
            }
            MimeHeaders headers = requestPacket.getHeaders();
            if (!headers.contains(Header.Connection)) {
                requestPacket.addHeader(Header.Connection, "keep-alive");
            }
            if (!headers.contains(Header.Accept)) {
                requestPacket.addHeader(Header.Accept, "*/*");
            }
            if (!headers.contains(Header.UserAgent)) {
                requestPacket.addHeader(Header.UserAgent, this.config.getUserAgent());
            }
        }

        private void addCookies(Request request, HttpRequestPacket requestPacket) {
            Collection<Cookie> cookies = request.getCookies();
            if (MiscUtil.isNonEmpty(cookies)) {
                StringBuilder sb = new StringBuilder(128);
                org.glassfish.grizzly.http.Cookie[] gCookies = new org.glassfish.grizzly.http.Cookie[cookies.size()];
                convertCookies(cookies, gCookies);
                CookieSerializerUtils.serializeClientCookies(sb, gCookies);
                requestPacket.addHeader(Header.Cookie, sb.toString());
            }
        }

        private void convertCookies(Collection<Cookie> cookies, org.glassfish.grizzly.http.Cookie[] gCookies) {
            int idx = 0;
            for (Cookie cookie : cookies) {
                org.glassfish.grizzly.http.Cookie gCookie = new org.glassfish.grizzly.http.Cookie(cookie.getName(), cookie.getValue());
                gCookie.setDomain(cookie.getDomain());
                gCookie.setPath(cookie.getPath());
                gCookie.setVersion(1);
                gCookie.setMaxAge(cookie.getMaxAge());
                gCookie.setSecure(cookie.isSecure());
                gCookies[idx] = gCookie;
                idx++;
            }
        }

        private void addQueryString(Request request, HttpRequestPacket requestPacket) {
            FluentStringsMap map = request.getQueryParams();
            if (MiscUtil.isNonEmpty((Map<?, ?>) map)) {
                StringBuilder sb = new StringBuilder(128);
                for (Entry<String, List<String>> entry : map.entrySet()) {
                    String name = entry.getKey();
                    List<String> values = entry.getValue();
                    if (MiscUtil.isNonEmpty((Collection<?>) values)) {
                        try {
                            int len = values.size();
                            for (int i = 0; i < len; i++) {
                                if (MiscUtil.isNonEmpty(values.get(i))) {
                                    sb.append(URLEncoder.encode(name, "UTF-8")).append('=').append(URLEncoder.encode(values.get(i), "UTF-8")).append('&');
                                } else {
                                    sb.append(URLEncoder.encode(name, "UTF-8")).append('&');
                                }
                            }
                        } catch (UnsupportedEncodingException e) {
                        }
                    }
                }
                sb.setLength(sb.length() - 1);
                requestPacket.setQueryString(sb.toString());
            }
        }
    }

    private final class AsyncHttpClientTransportFilter extends TransportFilter {
        private AsyncHttpClientTransportFilter() {
        }

        public NextAction handleRead(FilterChainContext ctx) throws IOException {
            final HttpTransactionContext context = GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection());
            if (context == null) {
                return GrizzlyAsyncHttpProvider.super.handleRead(ctx);
            }
            ctx.getTransportContext().setCompletionHandler(new CompletionHandler() {
                public void cancelled() {
                }

                public void failed(Throwable throwable) {
                    if (throwable instanceof EOFException) {
                        context.abort(new IOException("Remotely Closed"));
                    }
                    context.abort(throwable);
                }

                public void completed(Object result) {
                }

                public void updated(Object result) {
                }
            });
            return GrizzlyAsyncHttpProvider.super.handleRead(ctx);
        }
    }

    private static final class BodyGeneratorBodyHandler implements BodyHandler {
        private BodyGeneratorBodyHandler() {
        }

        public boolean handlesBodyType(Request request) {
            return request.getBodyGenerator() != null;
        }

        public boolean doHandle(FilterChainContext ctx, Request request, HttpRequestPacket requestPacket) throws IOException {
            CompletionHandler completionHandler;
            BodyGenerator generator = request.getBodyGenerator();
            Body bodyLocal = generator.createBody();
            long len = bodyLocal.getContentLength();
            if (len >= 0) {
                requestPacket.setContentLengthLong(len);
            } else {
                requestPacket.setChunked(true);
            }
            MemoryManager mm = ctx.getMemoryManager();
            boolean last = false;
            while (!last) {
                Buffer buffer = mm.allocate(8192);
                buffer.allowBufferDispose(true);
                long readBytes = bodyLocal.read(buffer.toByteBuffer());
                if (readBytes > 0) {
                    buffer.position((int) readBytes);
                    buffer.trim();
                } else {
                    buffer.dispose();
                    if (readBytes < 0) {
                        last = true;
                        buffer = Buffers.EMPTY_BUFFER;
                    } else if (generator instanceof FeedableBodyGenerator) {
                        ((FeedableBodyGenerator) generator).initializeAsynchronousTransfer(ctx, requestPacket);
                        return false;
                    } else {
                        throw new IllegalStateException("BodyGenerator unexpectedly returned 0 bytes available");
                    }
                }
                HttpContent content = requestPacket.httpContentBuilder().content(buffer).last(last).build();
                if (!requestPacket.isCommitted()) {
                    completionHandler = ctx.getTransportContext().getCompletionHandler();
                } else {
                    completionHandler = null;
                }
                ctx.write(content, completionHandler);
            }
            return true;
        }
    }

    private interface BodyHandler {
        public static final int MAX_CHUNK_SIZE = 8192;

        boolean doHandle(FilterChainContext filterChainContext, Request request, HttpRequestPacket httpRequestPacket) throws IOException;

        boolean handlesBodyType(Request request);
    }

    private final class BodyHandlerFactory {
        private final BodyHandler[] HANDLERS;

        private BodyHandlerFactory() {
            this.HANDLERS = new BodyHandler[]{new StringBodyHandler(), new ByteArrayBodyHandler(), new ParamsBodyHandler(), new EntityWriterBodyHandler(), new StreamDataBodyHandler(), new PartsBodyHandler(), new FileBodyHandler(), new BodyGeneratorBodyHandler()};
        }

        public BodyHandler getBodyHandler(Request request) {
            BodyHandler[] arr$;
            for (BodyHandler h : this.HANDLERS) {
                if (h.handlesBodyType(request)) {
                    return h;
                }
            }
            return new NoBodyHandler();
        }
    }

    private final class ByteArrayBodyHandler implements BodyHandler {
        private ByteArrayBodyHandler() {
        }

        public boolean handlesBodyType(Request request) {
            return request.getByteData() != null;
        }

        public boolean doHandle(FilterChainContext ctx, Request request, HttpRequestPacket requestPacket) throws IOException {
            MemoryManager mm = ctx.getMemoryManager();
            byte[] data = request.getByteData();
            Buffer gBuffer = Buffers.wrap(mm, data);
            if (requestPacket.getContentLength() == -1 && !GrizzlyAsyncHttpProvider.this.clientConfig.isCompressionEnabled()) {
                requestPacket.setContentLengthLong((long) data.length);
            }
            HttpContent content = requestPacket.httpContentBuilder().content(gBuffer).build();
            content.setLast(true);
            ctx.write(content, !requestPacket.isCommitted() ? ctx.getTransportContext().getCompletionHandler() : null);
            return true;
        }
    }

    private static final class ClientEncodingFilter implements EncodingFilter {
        private ClientEncodingFilter() {
        }

        public boolean applyEncoding(HttpHeader httpPacket) {
            httpPacket.addHeader(Header.AcceptEncoding, "gzip");
            return false;
        }

        public boolean applyDecoding(HttpHeader httpPacket) {
            DataChunk bc = ((HttpResponsePacket) httpPacket).getHeaders().getValue(Header.ContentEncoding);
            if (bc == null || bc.indexOf("gzip", 0) == -1) {
                return false;
            }
            return true;
        }
    }

    static class ConnectionManager {
        private static final Attribute<Boolean> DO_NOT_CACHE = Grizzly.DEFAULT_ATTRIBUTE_BUILDER.createAttribute(ConnectionManager.class.getName());
        private final TCPNIOConnectorHandler connectionHandler;
        /* access modifiers changed from: private */
        public final ConnectionMonitor connectionMonitor;
        private final ConnectionsPool<String, Connection> pool;
        /* access modifiers changed from: private */
        public final GrizzlyAsyncHttpProvider provider;

        private static class ConnectionMonitor implements CloseListener {
            private final Semaphore connections;

            ConnectionMonitor(int maxConnections) {
                if (maxConnections != -1) {
                    this.connections = new Semaphore(maxConnections);
                } else {
                    this.connections = null;
                }
            }

            public boolean acquire() {
                return this.connections == null || this.connections.tryAcquire();
            }

            public void onClosed(Connection connection, CloseType closeType) throws IOException {
                if (this.connections != null) {
                    this.connections.release();
                }
            }
        }

        ConnectionManager(GrizzlyAsyncHttpProvider provider2, TCPNIOTransport transport) {
            ConnectionsPool<?, ?> nonCachingPool;
            this.provider = provider2;
            AsyncHttpClientConfig config = provider2.clientConfig;
            if (config.getAllowPoolingConnection()) {
                ConnectionsPool<?, ?> connectionsPool = config.getConnectionsPool();
                if (connectionsPool != null) {
                    nonCachingPool = connectionsPool;
                } else {
                    nonCachingPool = new GrizzlyConnectionsPool<>(config);
                }
            } else {
                nonCachingPool = new NonCachingPool<>();
            }
            this.pool = nonCachingPool;
            this.connectionHandler = TCPNIOConnectorHandler.builder(transport).build();
            this.connectionMonitor = new ConnectionMonitor(provider2.clientConfig.getMaxTotalConnections());
        }

        static void markConnectionAsDoNotCache(Connection c) {
            DO_NOT_CACHE.set(c, Boolean.TRUE);
        }

        static boolean isConnectionCacheable(Connection c) {
            Boolean canCache = (Boolean) DO_NOT_CACHE.get(c);
            if (canCache != null) {
                return canCache.booleanValue();
            }
            return false;
        }

        /* access modifiers changed from: 0000 */
        public void doAsyncTrackedConnection(Request request, GrizzlyResponseFuture requestFuture, CompletionHandler<Connection> connectHandler) throws IOException, ExecutionException, InterruptedException {
            Connection c = (Connection) this.pool.poll(getPoolKey(request, requestFuture.getProxy()));
            if (c != null) {
                this.provider.touchConnection(c, request);
                connectHandler.completed(c);
            } else if (!this.connectionMonitor.acquire()) {
                throw new IOException("Max connections exceeded");
            } else {
                doAsyncConnect(request, requestFuture, connectHandler);
            }
        }

        /* access modifiers changed from: 0000 */
        public Connection obtainConnection(Request request, GrizzlyResponseFuture requestFuture) throws IOException, ExecutionException, InterruptedException, TimeoutException {
            Connection c = obtainConnection0(request, requestFuture);
            DO_NOT_CACHE.set(c, Boolean.TRUE);
            return c;
        }

        /* access modifiers changed from: 0000 */
        public void doAsyncConnect(Request request, GrizzlyResponseFuture requestFuture, CompletionHandler<Connection> connectHandler) throws IOException, ExecutionException, InterruptedException {
            ProxyServer proxy = requestFuture.getProxy();
            URI uri = request.getURI();
            String host = proxy != null ? proxy.getHost() : uri.getHost();
            int port = proxy != null ? proxy.getPort() : uri.getPort();
            if (request.getLocalAddress() != null) {
                this.connectionHandler.connect(new InetSocketAddress(host, GrizzlyAsyncHttpProvider.getPort(uri, port)), new InetSocketAddress(request.getLocalAddress(), 0), createConnectionCompletionHandler(request, requestFuture, connectHandler));
            } else {
                this.connectionHandler.connect(new InetSocketAddress(host, GrizzlyAsyncHttpProvider.getPort(uri, port)), createConnectionCompletionHandler(request, requestFuture, connectHandler));
            }
        }

        private Connection obtainConnection0(Request request, GrizzlyResponseFuture requestFuture) throws IOException, ExecutionException, InterruptedException, TimeoutException {
            URI uri = request.getURI();
            ProxyServer proxy = requestFuture.getProxy();
            String host = proxy != null ? proxy.getHost() : uri.getHost();
            int port = proxy != null ? proxy.getPort() : uri.getPort();
            int cTimeout = this.provider.clientConfig.getConnectionTimeoutInMs();
            FutureImpl<Connection> future = Futures.createSafeFuture();
            CompletionHandler<Connection> ch = Futures.toCompletionHandler(future, createConnectionCompletionHandler(request, requestFuture, null));
            if (cTimeout > 0) {
                this.connectionHandler.connect(new InetSocketAddress(host, GrizzlyAsyncHttpProvider.getPort(uri, port)), ch);
                return (Connection) future.get((long) cTimeout, TimeUnit.MILLISECONDS);
            }
            this.connectionHandler.connect(new InetSocketAddress(host, GrizzlyAsyncHttpProvider.getPort(uri, port)), ch);
            return (Connection) future.get();
        }

        /* access modifiers changed from: 0000 */
        public boolean returnConnection(Request request, Connection c) {
            boolean result = DO_NOT_CACHE.get(c) == null && this.pool.offer(getPoolKey(request, ProxyUtils.getProxyServer(this.provider.clientConfig, request)), c);
            if (result && this.provider.resolver != null) {
                this.provider.resolver.setTimeoutMillis(c, IdleTimeoutFilter.FOREVER.longValue());
            }
            return result;
        }

        /* access modifiers changed from: 0000 */
        public boolean canReturnConnection(Connection c) {
            return DO_NOT_CACHE.get(c) != null || this.pool.canCacheConnection();
        }

        /* access modifiers changed from: 0000 */
        public void destroy() {
            this.pool.destroy();
        }

        /* access modifiers changed from: 0000 */
        public CompletionHandler<Connection> createConnectionCompletionHandler(final Request request, final GrizzlyResponseFuture future, final CompletionHandler<Connection> wrappedHandler) {
            return new CompletionHandler<Connection>() {
                public void cancelled() {
                    if (wrappedHandler != null) {
                        wrappedHandler.cancelled();
                    } else {
                        future.cancel(true);
                    }
                }

                public void failed(Throwable throwable) {
                    if (wrappedHandler != null) {
                        wrappedHandler.failed(throwable);
                    } else {
                        future.abort(throwable);
                    }
                }

                public void completed(Connection connection) {
                    future.setConnection(connection);
                    ConnectionManager.this.provider.touchConnection(connection, request);
                    if (wrappedHandler != null) {
                        connection.addCloseListener(ConnectionManager.this.connectionMonitor);
                        wrappedHandler.completed(connection);
                    }
                }

                public void updated(Connection result) {
                    if (wrappedHandler != null) {
                        wrappedHandler.updated(result);
                    }
                }
            };
        }

        private static String getPoolKey(Request request, ProxyServer proxyServer) {
            String serverPart = request.getConnectionPoolKeyStrategy().getKey(request.getURI());
            return proxyServer != null ? AsyncHttpProviderUtils.getBaseUrl(proxyServer.getURI()) + serverPart : serverPart;
        }
    }

    private static final class ContinueEvent implements FilterChainEvent {
        /* access modifiers changed from: private */
        public final HttpTransactionContext context;

        ContinueEvent(HttpTransactionContext context2) {
            this.context = context2;
        }

        public Object type() {
            return ContinueEvent.class;
        }
    }

    private static final class EntityWriterBodyHandler implements BodyHandler {
        private EntityWriterBodyHandler() {
        }

        public boolean handlesBodyType(Request request) {
            return request.getEntityWriter() != null;
        }

        public boolean doHandle(FilterChainContext ctx, Request request, HttpRequestPacket requestPacket) throws IOException {
            MemoryManager mm = ctx.getMemoryManager();
            BufferOutputStream o = new BufferOutputStream(mm, mm.allocate(512), true);
            request.getEntityWriter().writeEntity(o);
            Buffer b = o.getBuffer();
            b.trim();
            if (b.hasRemaining()) {
                HttpContent content = requestPacket.httpContentBuilder().content(b).build();
                content.setLast(true);
                ctx.write(content, !requestPacket.isCommitted() ? ctx.getTransportContext().getCompletionHandler() : null);
            }
            return true;
        }
    }

    private static final class ExpectHandler implements BodyHandler {
        private final BodyHandler delegate;
        private Request request;
        private HttpRequestPacket requestPacket;

        private ExpectHandler(BodyHandler delegate2) {
            this.delegate = delegate2;
        }

        public boolean handlesBodyType(Request request2) {
            return this.delegate.handlesBodyType(request2);
        }

        public boolean doHandle(FilterChainContext ctx, Request request2, HttpRequestPacket requestPacket2) throws IOException {
            this.request = request2;
            this.requestPacket = requestPacket2;
            ctx.write(requestPacket2, !requestPacket2.isCommitted() ? ctx.getTransportContext().getCompletionHandler() : null);
            return true;
        }

        public void finish(FilterChainContext ctx) throws IOException {
            this.delegate.doHandle(ctx, this.request, this.requestPacket);
        }
    }

    private final class FileBodyHandler implements BodyHandler {
        private FileBodyHandler() {
        }

        public boolean handlesBodyType(Request request) {
            return request.getFile() != null;
        }

        public boolean doHandle(FilterChainContext ctx, Request request, final HttpRequestPacket requestPacket) throws IOException {
            File f = request.getFile();
            requestPacket.setContentLengthLong(f.length());
            final HttpTransactionContext context = GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection());
            if (!GrizzlyAsyncHttpProvider.SEND_FILE_SUPPORT || requestPacket.isSecure()) {
                FileInputStream fis = new FileInputStream(request.getFile());
                MemoryManager mm = ctx.getMemoryManager();
                AtomicInteger written = new AtomicInteger();
                boolean last = false;
                try {
                    byte[] buf = new byte[8192];
                    while (!last) {
                        Buffer b = null;
                        int read = fis.read(buf);
                        if (read < 0) {
                            last = true;
                            b = Buffers.EMPTY_BUFFER;
                        }
                        if (b != Buffers.EMPTY_BUFFER) {
                            written.addAndGet(read);
                            b = Buffers.wrap(mm, buf, 0, read);
                        }
                        ctx.write(requestPacket.httpContentBuilder().content(b).last(last).build(), !requestPacket.isCommitted() ? ctx.getTransportContext().getCompletionHandler() : null);
                    }
                } finally {
                    try {
                        fis.close();
                    } catch (IOException e) {
                    }
                }
            } else {
                ctx.write(requestPacket, !requestPacket.isCommitted() ? ctx.getTransportContext().getCompletionHandler() : null);
                ctx.write(new FileTransfer(f), new EmptyCompletionHandler<WriteResult>() {
                    public void updated(WriteResult result) {
                        AsyncHandler handler = context.handler;
                        if (handler instanceof TransferCompletionHandler) {
                            long written = result.getWrittenSize();
                            ((TransferCompletionHandler) handler).onContentWriteProgress(written, context.totalBodyWritten.addAndGet(written), requestPacket.getContentLength());
                        }
                    }
                });
            }
            return true;
        }
    }

    private static final class GrizzlyTransferAdapter extends TransferAdapter {
        public GrizzlyTransferAdapter(FluentCaseInsensitiveStringsMap headers) throws IOException {
            super(headers);
        }

        public void getBytes(byte[] bytes) {
        }
    }

    private static final class GrizzlyWebSocketAdapter implements com.ning.http.client.websocket.WebSocket {
        final boolean bufferFragments;
        final SimpleWebSocket gWebSocket;

        GrizzlyWebSocketAdapter(SimpleWebSocket gWebSocket2, boolean bufferFragments2) {
            this.gWebSocket = gWebSocket2;
            this.bufferFragments = bufferFragments2;
        }

        public com.ning.http.client.websocket.WebSocket sendMessage(byte[] message) {
            this.gWebSocket.send(message);
            return this;
        }

        public com.ning.http.client.websocket.WebSocket stream(byte[] fragment, boolean last) {
            if (MiscUtil.isNonEmpty(fragment)) {
                this.gWebSocket.stream(last, fragment, 0, fragment.length);
            }
            return this;
        }

        public com.ning.http.client.websocket.WebSocket stream(byte[] fragment, int offset, int len, boolean last) {
            if (MiscUtil.isNonEmpty(fragment)) {
                this.gWebSocket.stream(last, fragment, offset, len);
            }
            return this;
        }

        public com.ning.http.client.websocket.WebSocket sendTextMessage(String message) {
            this.gWebSocket.send(message);
            return this;
        }

        public com.ning.http.client.websocket.WebSocket streamText(String fragment, boolean last) {
            this.gWebSocket.stream(last, fragment);
            return this;
        }

        public com.ning.http.client.websocket.WebSocket sendPing(byte[] payload) {
            this.gWebSocket.sendPing(payload);
            return this;
        }

        public com.ning.http.client.websocket.WebSocket sendPong(byte[] payload) {
            this.gWebSocket.sendPong(payload);
            return this;
        }

        public com.ning.http.client.websocket.WebSocket addWebSocketListener(com.ning.http.client.websocket.WebSocketListener l) {
            this.gWebSocket.add(new AHCWebSocketListenerAdapter(l, this));
            return this;
        }

        public com.ning.http.client.websocket.WebSocket removeWebSocketListener(com.ning.http.client.websocket.WebSocketListener l) {
            this.gWebSocket.remove(new AHCWebSocketListenerAdapter(l, this));
            return this;
        }

        public boolean isOpen() {
            return this.gWebSocket.isConnected();
        }

        public void close() {
            this.gWebSocket.close();
        }
    }

    final class HttpTransactionContext {
        BodyHandler bodyHandler;
        STATE currentState;
        boolean establishingTunnel;
        GrizzlyResponseFuture future;
        AsyncHandler handler;
        HandShake handshake;
        InvocationStatus invocationStatus = InvocationStatus.CONTINUE;
        boolean isWSRequest;
        String lastRedirectURI;
        final int maxRedirectCount;
        ProtocolHandler protocolHandler;
        final GrizzlyAsyncHttpProvider provider = GrizzlyAsyncHttpProvider.this;
        final AtomicInteger redirectCount = new AtomicInteger(0);
        final boolean redirectsAllowed;
        Request request;
        String requestUrl;
        GrizzlyResponseStatus responseStatus;
        StatusHandler statusHandler;
        AtomicLong totalBodyWritten = new AtomicLong();
        com.ning.http.client.websocket.WebSocket webSocket;
        String wsRequestURI;

        HttpTransactionContext(GrizzlyResponseFuture future2, Request request2, AsyncHandler handler2) {
            this.future = future2;
            this.request = request2;
            this.handler = handler2;
            this.redirectsAllowed = this.provider.clientConfig.isRedirectEnabled();
            this.maxRedirectCount = this.provider.clientConfig.getMaxRedirects();
            this.requestUrl = request2.getUrl();
        }

        /* access modifiers changed from: 0000 */
        public HttpTransactionContext copy() {
            HttpTransactionContext newContext = new HttpTransactionContext(this.future, this.request, this.handler);
            newContext.invocationStatus = this.invocationStatus;
            newContext.bodyHandler = this.bodyHandler;
            newContext.currentState = this.currentState;
            newContext.statusHandler = this.statusHandler;
            newContext.lastRedirectURI = this.lastRedirectURI;
            newContext.redirectCount.set(this.redirectCount.get());
            return newContext;
        }

        /* access modifiers changed from: 0000 */
        public void abort(Throwable t) {
            if (this.future != null) {
                this.future.abort(t);
            }
        }

        /* access modifiers changed from: 0000 */
        public void done() {
            if (this.future != null) {
                this.future.done();
            }
        }

        /* access modifiers changed from: 0000 */
        public void result(Object result) {
            if (this.future != null) {
                this.future.delegate.result(result);
                this.future.done();
            }
        }

        /* access modifiers changed from: 0000 */
        public boolean isTunnelEstablished(Connection c) {
            return c.getAttributes().getAttribute("tunnel-established") != null;
        }

        /* access modifiers changed from: 0000 */
        public void tunnelEstablished(Connection c) {
            c.getAttributes().setAttribute("tunnel-established", Boolean.TRUE);
        }
    }

    private static final class NoBodyHandler implements BodyHandler {
        private NoBodyHandler() {
        }

        public boolean handlesBodyType(Request request) {
            return false;
        }

        public boolean doHandle(FilterChainContext ctx, Request request, HttpRequestPacket requestPacket) throws IOException {
            HttpContent content = requestPacket.httpContentBuilder().content(Buffers.EMPTY_BUFFER).build();
            content.setLast(true);
            ctx.write(content, !requestPacket.isCommitted() ? ctx.getTransportContext().getCompletionHandler() : null);
            return true;
        }
    }

    private static final class NonCachingPool implements ConnectionsPool<String, Connection> {
        private NonCachingPool() {
        }

        public boolean offer(String uri, Connection connection) {
            return false;
        }

        public Connection poll(String uri) {
            return null;
        }

        public boolean removeAll(Connection connection) {
            return false;
        }

        public boolean canCacheConnection() {
            return true;
        }

        public void destroy() {
        }
    }

    private final class ParamsBodyHandler implements BodyHandler {
        private ParamsBodyHandler() {
        }

        public boolean handlesBodyType(Request request) {
            return MiscUtil.isNonEmpty((Map<?, ?>) request.getParams());
        }

        public boolean doHandle(FilterChainContext ctx, Request request, HttpRequestPacket requestPacket) throws IOException {
            if (requestPacket.getContentType() == null) {
                requestPacket.setContentType("application/x-www-form-urlencoded");
            }
            StringBuilder sb = null;
            String charset = request.getBodyEncoding();
            if (charset == null) {
                charset = Charsets.ASCII_CHARSET.name();
            }
            FluentStringsMap params = request.getParams();
            if (!params.isEmpty()) {
                for (Entry<String, List<String>> entry : params.entrySet()) {
                    String name = entry.getKey();
                    List<String> values = entry.getValue();
                    if (MiscUtil.isNonEmpty((Collection<?>) values)) {
                        if (sb == null) {
                            sb = new StringBuilder(128);
                        }
                        for (String value : values) {
                            if (sb.length() > 0) {
                                sb.append('&');
                            }
                            sb.append(URLEncoder.encode(name, charset)).append('=').append(URLEncoder.encode(value, charset));
                        }
                    }
                }
            }
            if (sb != null) {
                byte[] data = sb.toString().getBytes(charset);
                HttpContent content = requestPacket.httpContentBuilder().content(Buffers.wrap(ctx.getMemoryManager(), data)).build();
                if (requestPacket.getContentLength() == -1 && !GrizzlyAsyncHttpProvider.this.clientConfig.isCompressionEnabled()) {
                    requestPacket.setContentLengthLong((long) data.length);
                }
                content.setLast(true);
                ctx.write(content, !requestPacket.isCommitted() ? ctx.getTransportContext().getCompletionHandler() : null);
            }
            return true;
        }
    }

    private static final class PartsBodyHandler implements BodyHandler {
        private PartsBodyHandler() {
        }

        public boolean handlesBodyType(Request request) {
            return MiscUtil.isNonEmpty((Collection<?>) request.getParts());
        }

        public boolean doHandle(final FilterChainContext ctx, Request request, HttpRequestPacket requestPacket) throws IOException {
            final List<Part> parts = request.getParts();
            MultipartRequestEntity mre = AsyncHttpProviderUtils.createMultipartRequestEntity(parts, request.getHeaders());
            final long contentLength = mre.getContentLength();
            final String contentType = mre.getContentType();
            requestPacket.setContentLengthLong(contentLength);
            requestPacket.setContentType(contentType);
            if (GrizzlyAsyncHttpProvider.LOGGER.isDebugEnabled()) {
                GrizzlyAsyncHttpProvider.LOGGER.debug((String) "REQUEST(modified): contentLength={}, contentType={}", Long.valueOf(requestPacket.getContentLength()), requestPacket.getContentType());
            }
            FeedableBodyGenerator generator = new FeedableBodyGenerator() {
                public Body createBody() throws IOException {
                    return new MultipartBody(parts, contentType, contentLength);
                }
            };
            generator.setFeeder(new BaseFeeder(generator) {
                public void flush() throws IOException {
                    Body bodyLocal = this.feedableBodyGenerator.createBody();
                    try {
                        MemoryManager mm = ctx.getMemoryManager();
                        boolean last = false;
                        while (!last) {
                            Buffer buffer = mm.allocate(8192);
                            buffer.allowBufferDispose(true);
                            long readBytes = bodyLocal.read(buffer.toByteBuffer());
                            if (readBytes > 0) {
                                buffer.position((int) readBytes);
                                buffer.trim();
                            } else {
                                buffer.dispose();
                                if (readBytes < 0) {
                                    last = true;
                                    buffer = Buffers.EMPTY_BUFFER;
                                } else {
                                    throw new IllegalStateException("MultipartBody unexpectedly returned 0 bytes available");
                                }
                            }
                            feed(buffer, last);
                        }
                        if (bodyLocal != null) {
                            try {
                                bodyLocal.close();
                            } catch (IOException e) {
                            }
                        }
                    } finally {
                        if (bodyLocal != null) {
                            try {
                                bodyLocal.close();
                            } catch (IOException e2) {
                            }
                        }
                    }
                }
            });
            generator.initializeAsynchronousTransfer(ctx, requestPacket);
            return false;
        }
    }

    private interface StatusHandler {

        public enum InvocationStatus {
            CONTINUE,
            STOP
        }

        boolean handleStatus(HttpResponsePacket httpResponsePacket, HttpTransactionContext httpTransactionContext, FilterChainContext filterChainContext);

        boolean handlesStatus(int i);
    }

    private static final class StreamDataBodyHandler implements BodyHandler {
        private StreamDataBodyHandler() {
        }

        public boolean handlesBodyType(Request request) {
            return request.getStreamData() != null;
        }

        public boolean doHandle(FilterChainContext ctx, Request request, HttpRequestPacket requestPacket) throws IOException {
            MemoryManager mm = ctx.getMemoryManager();
            Buffer buffer = mm.allocate(512);
            byte[] b = new byte[512];
            InputStream in = request.getStreamData();
            try {
                in.reset();
            } catch (IOException ioe) {
                if (GrizzlyAsyncHttpProvider.LOGGER.isDebugEnabled()) {
                    GrizzlyAsyncHttpProvider.LOGGER.debug(ioe.toString(), (Throwable) ioe);
                }
            }
            if (in.markSupported()) {
                in.mark(0);
            }
            while (true) {
                int read = in.read(b);
                if (read == -1) {
                    break;
                }
                if (read > buffer.remaining()) {
                    buffer = mm.reallocate(buffer, buffer.capacity() + 512);
                }
                buffer.put(b, 0, read);
            }
            buffer.trim();
            if (buffer.hasRemaining()) {
                HttpContent content = requestPacket.httpContentBuilder().content(buffer).build();
                buffer.allowBufferDispose(false);
                content.setLast(true);
                ctx.write(content, !requestPacket.isCommitted() ? ctx.getTransportContext().getCompletionHandler() : null);
            }
            return true;
        }
    }

    private final class StringBodyHandler implements BodyHandler {
        private StringBodyHandler() {
        }

        public boolean handlesBodyType(Request request) {
            return request.getStringData() != null;
        }

        public boolean doHandle(FilterChainContext ctx, Request request, HttpRequestPacket requestPacket) throws IOException {
            String charset = request.getBodyEncoding();
            if (charset == null) {
                charset = Charsets.ASCII_CHARSET.name();
            }
            byte[] data = request.getStringData().getBytes(charset);
            Buffer gBuffer = Buffers.wrap(ctx.getMemoryManager(), data);
            if (requestPacket.getContentLength() == -1 && !GrizzlyAsyncHttpProvider.this.clientConfig.isCompressionEnabled()) {
                requestPacket.setContentLengthLong((long) data.length);
            }
            HttpContent content = requestPacket.httpContentBuilder().content(gBuffer).build();
            content.setLast(true);
            ctx.write(content, !requestPacket.isCommitted() ? ctx.getTransportContext().getCompletionHandler() : null);
            return true;
        }
    }

    static final class SwitchingSSLFilter extends SSLFilter {
        final Attribute<Boolean> CONNECTION_IS_SECURE = Grizzly.DEFAULT_ATTRIBUTE_BUILDER.createAttribute(SwitchingSSLFilter.class.getName());
        private final boolean secureByDefault;

        static final class SSLSwitchingEvent implements FilterChainEvent {
            final Connection connection;
            final boolean secure;

            SSLSwitchingEvent(boolean secure2, Connection c) {
                this.secure = secure2;
                this.connection = c;
            }

            public Object type() {
                return SSLSwitchingEvent.class;
            }
        }

        SwitchingSSLFilter(SSLEngineConfigurator clientConfig, boolean secureByDefault2) {
            super(null, clientConfig);
            this.secureByDefault = secureByDefault2;
        }

        public NextAction handleEvent(FilterChainContext ctx, FilterChainEvent event) throws IOException {
            if (event.type() != SSLSwitchingEvent.class) {
                return ctx.getInvokeAction();
            }
            SSLSwitchingEvent se = (SSLSwitchingEvent) event;
            this.CONNECTION_IS_SECURE.set(se.connection, Boolean.valueOf(se.secure));
            return ctx.getStopAction();
        }

        public NextAction handleRead(FilterChainContext ctx) throws IOException {
            if (isSecure(ctx.getConnection())) {
                return GrizzlyAsyncHttpProvider.super.handleRead(ctx);
            }
            return ctx.getInvokeAction();
        }

        public NextAction handleWrite(FilterChainContext ctx) throws IOException {
            if (isSecure(ctx.getConnection())) {
                return GrizzlyAsyncHttpProvider.super.handleWrite(ctx);
            }
            return ctx.getInvokeAction();
        }

        public void onFilterChainChanged(FilterChain filterChain) {
        }

        private boolean isSecure(Connection c) {
            Boolean secStatus = (Boolean) this.CONNECTION_IS_SECURE.get(c);
            if (secStatus == null) {
                secStatus = Boolean.valueOf(this.secureByDefault);
            }
            return secStatus.booleanValue();
        }
    }

    public GrizzlyAsyncHttpProvider(AsyncHttpClientConfig clientConfig2) {
        this.clientConfig = clientConfig2;
        this.clientTransport = TCPNIOTransportBuilder.newInstance().build();
        initializeTransport(clientConfig2);
        this.connectionManager = new ConnectionManager(this, this.clientTransport);
        try {
            this.clientTransport.start();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    public <T> ListenableFuture<T> execute(final Request request, final AsyncHandler<T> handler) throws IOException {
        if (this.clientTransport.isStopped()) {
            throw new IOException("AsyncHttpClient has been closed.");
        }
        final GrizzlyResponseFuture<T> future = new GrizzlyResponseFuture<>(this, request, handler, ProxyUtils.getProxyServer(this.clientConfig, request));
        future.setDelegate(SafeFutureImpl.create());
        try {
            this.connectionManager.doAsyncTrackedConnection(request, future, new CompletionHandler<Connection>() {
                public void cancelled() {
                    future.cancel(true);
                }

                public void failed(Throwable throwable) {
                    future.abort(throwable);
                }

                public void completed(Connection c) {
                    try {
                        GrizzlyAsyncHttpProvider.this.execute(c, request, handler, future);
                    } catch (Exception e) {
                        if (e instanceof RuntimeException) {
                            failed(e);
                        } else if (e instanceof IOException) {
                            failed(e);
                        }
                        if (GrizzlyAsyncHttpProvider.LOGGER.isWarnEnabled()) {
                            GrizzlyAsyncHttpProvider.LOGGER.warn(e.toString(), (Throwable) e);
                        }
                    }
                }

                public void updated(Connection c) {
                }
            });
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw ((RuntimeException) e);
            } else if (e instanceof IOException) {
                throw ((IOException) e);
            } else if (LOGGER.isWarnEnabled()) {
                LOGGER.warn(e.toString(), (Throwable) e);
            }
        }
        return future;
    }

    public void close() {
        try {
            this.connectionManager.destroy();
            this.clientTransport.shutdownNow();
            ExecutorService service = this.clientConfig.executorService();
            if (service != null) {
                service.shutdown();
            }
            if (this.timeoutExecutor != null) {
                this.timeoutExecutor.stop();
                this.timeoutExecutor.getThreadPool().shutdownNow();
            }
        } catch (IOException e) {
        }
    }

    public Response prepareResponse(HttpResponseStatus status, HttpResponseHeaders headers, List<HttpResponseBodyPart> bodyParts) {
        return new GrizzlyResponse(status, headers, bodyParts);
    }

    /* access modifiers changed from: protected */
    public <T> ListenableFuture<T> execute(Connection c, Request request, AsyncHandler<T> handler, GrizzlyResponseFuture<T> future) throws IOException {
        try {
            if (getHttpTransactionContext(c) == null) {
                setHttpTransactionContext(c, new HttpTransactionContext(future, request, handler));
            }
            c.write(request, createWriteCompletionHandler(future));
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw ((RuntimeException) e);
            } else if (e instanceof IOException) {
                throw ((IOException) e);
            } else if (LOGGER.isWarnEnabled()) {
                LOGGER.warn(e.toString(), (Throwable) e);
            }
        }
        return future;
    }

    /* access modifiers changed from: protected */
    public void initializeTransport(AsyncHttpClientConfig clientConfig2) {
        GrizzlyAsyncHttpProviderConfig providerConfig;
        FilterChainBuilder fcb = FilterChainBuilder.stateless();
        AsyncHttpClientTransportFilter asyncHttpClientTransportFilter = new AsyncHttpClientTransportFilter();
        fcb.add(asyncHttpClientTransportFilter);
        int timeout = clientConfig2.getRequestTimeoutInMs();
        if (timeout > 0) {
            int delay = 500;
            if (timeout < 500) {
                delay = timeout - 10;
            }
            this.timeoutExecutor = IdleTimeoutFilter.createDefaultIdleDelayedExecutor((long) delay, TimeUnit.MILLISECONDS);
            this.timeoutExecutor.start();
            final AsyncHttpClientConfig asyncHttpClientConfig = clientConfig2;
            final int i = timeout;
            AnonymousClass2 r0 = new TimeoutResolver() {
                public long getTimeout(FilterChainContext ctx) {
                    GrizzlyAsyncHttpProvider grizzlyAsyncHttpProvider = GrizzlyAsyncHttpProvider.this;
                    HttpTransactionContext context = GrizzlyAsyncHttpProvider.getHttpTransactionContext(ctx.getConnection());
                    if (context != null) {
                        if (context.isWSRequest) {
                            return (long) asyncHttpClientConfig.getWebSocketIdleTimeoutInMs();
                        }
                        PerRequestConfig config = context.request.getPerRequestConfig();
                        if (config != null) {
                            long timeout = (long) config.getRequestTimeoutInMs();
                            if (timeout > 0) {
                                return timeout;
                            }
                        }
                    }
                    return (long) i;
                }
            };
            DelayedExecutor delayedExecutor = this.timeoutExecutor;
            AnonymousClass3 r02 = new TimeoutHandler() {
                public void onTimeout(Connection connection) {
                    GrizzlyAsyncHttpProvider.this.timeout(connection);
                }
            };
            IdleTimeoutFilter idleTimeoutFilter = new IdleTimeoutFilter(delayedExecutor, r0, r02);
            fcb.add(idleTimeoutFilter);
            this.resolver = idleTimeoutFilter.getResolver();
        }
        SSLContext context = clientConfig2.getSSLContext();
        boolean defaultSecState = context != null;
        if (context == null) {
            try {
                context = SslUtils.getSSLContext();
            } catch (Exception e) {
                IllegalStateException illegalStateException = new IllegalStateException(e);
                throw illegalStateException;
            }
        }
        SwitchingSSLFilter switchingSSLFilter = new SwitchingSSLFilter(new SSLEngineConfigurator(context, true, false, false), defaultSecState);
        fcb.add(switchingSSLFilter);
        if (clientConfig2.getAsyncHttpProviderConfig() instanceof GrizzlyAsyncHttpProviderConfig) {
            providerConfig = (GrizzlyAsyncHttpProviderConfig) clientConfig2.getAsyncHttpProviderConfig();
        } else {
            providerConfig = new GrizzlyAsyncHttpProviderConfig();
        }
        AsyncHttpClientEventFilter eventFilter = new AsyncHttpClientEventFilter(this, ((Integer) providerConfig.getProperty(Property.MAX_HTTP_PACKET_HEADER_SIZE)).intValue());
        AsyncHttpClientFilter clientFilter = new AsyncHttpClientFilter(clientConfig2);
        ContentEncoding[] encodings = eventFilter.getContentEncodings();
        if (encodings.length > 0) {
            ContentEncoding[] arr$ = encodings;
            int len$ = arr$.length;
            for (int i$ = 0; i$ < len$; i$++) {
                eventFilter.removeContentEncoding(arr$[i$]);
            }
        }
        if (clientConfig2.isCompressionEnabled()) {
            eventFilter.addContentEncoding(new GZipContentEncoding(512, 512, new ClientEncodingFilter()));
        }
        fcb.add(eventFilter);
        fcb.add(clientFilter);
        this.clientTransport.getAsyncQueueIO().getWriter().setMaxPendingBytesPerConnection(-2);
        TransportCustomizer customizer = (TransportCustomizer) providerConfig.getProperty(Property.TRANSPORT_CUSTOMIZER);
        if (customizer != null) {
            customizer.customize(this.clientTransport, fcb);
        } else {
            doDefaultTransportConfig();
        }
        fcb.add(new WebSocketFilter());
        this.clientTransport.setProcessor(fcb.build());
    }

    /* access modifiers changed from: 0000 */
    public void touchConnection(Connection c, Request request) {
        PerRequestConfig config = request.getPerRequestConfig();
        if (config != null) {
            long timeout = (long) config.getRequestTimeoutInMs();
            if (timeout > 0) {
                long newTimeout = System.currentTimeMillis() + timeout;
                if (this.resolver != null) {
                    this.resolver.setTimeoutMillis(c, newTimeout);
                    return;
                }
                return;
            }
            return;
        }
        long timeout2 = (long) this.clientConfig.getRequestTimeoutInMs();
        if (timeout2 > 0 && this.resolver != null) {
            this.resolver.setTimeoutMillis(c, System.currentTimeMillis() + timeout2);
        }
    }

    private static boolean configSendFileSupport() {
        return (!System.getProperty("os.name").equalsIgnoreCase("linux") || linuxSendFileSupported()) && !System.getProperty("os.name").equalsIgnoreCase("HP-UX");
    }

    private static boolean linuxSendFileSupported() {
        boolean z = true;
        String version = System.getProperty("java.version");
        if (version.startsWith("1.6")) {
            int idx = version.indexOf(95);
            if (idx == -1) {
                return false;
            }
            if (Integer.parseInt(version.substring(idx + 1)) < 18) {
                z = false;
            }
            return z;
        } else if (version.startsWith("1.7") || version.startsWith("1.8")) {
            return true;
        } else {
            return false;
        }
    }

    private void doDefaultTransportConfig() {
        ExecutorService service = this.clientConfig.executorService();
        if (service != null) {
            this.clientTransport.setIOStrategy(WorkerThreadIOStrategy.getInstance());
            this.clientTransport.setWorkerThreadPool(service);
            return;
        }
        this.clientTransport.setIOStrategy(SameThreadIOStrategy.getInstance());
    }

    private <T> CompletionHandler<WriteResult> createWriteCompletionHandler(final GrizzlyResponseFuture<T> future) {
        return new CompletionHandler<WriteResult>() {
            public void cancelled() {
                future.cancel(true);
            }

            public void failed(Throwable throwable) {
                future.abort(throwable);
            }

            public void completed(WriteResult result) {
            }

            public void updated(WriteResult result) {
            }
        };
    }

    static void setHttpTransactionContext(AttributeStorage storage, HttpTransactionContext httpTransactionState) {
        if (httpTransactionState == null) {
            REQUEST_STATE_ATTR.remove(storage);
        } else {
            REQUEST_STATE_ATTR.set(storage, httpTransactionState);
        }
    }

    static HttpTransactionContext getHttpTransactionContext(AttributeStorage storage) {
        return (HttpTransactionContext) REQUEST_STATE_ATTR.get(storage);
    }

    /* access modifiers changed from: 0000 */
    public void timeout(Connection c) {
        HttpTransactionContext context = getHttpTransactionContext(c);
        setHttpTransactionContext(c, null);
        context.abort(new TimeoutException("Timeout exceeded"));
    }

    static int getPort(URI uri, int p) {
        int port = p;
        if (port != -1) {
            return port;
        }
        String protocol = uri.getScheme().toLowerCase(Locale.ENGLISH);
        if ("http".equals(protocol) || "ws".equals(protocol)) {
            return 80;
        }
        if (CommonProtocol.URL_SCHEME.equals(protocol) || "wss".equals(protocol)) {
            return 443;
        }
        throw new IllegalArgumentException("Unknown protocol: " + protocol);
    }

    /* access modifiers changed from: 0000 */
    public boolean sendRequest(FilterChainContext ctx, Request request, HttpRequestPacket requestPacket) throws IOException {
        if (requestHasEntityBody(request)) {
            HttpTransactionContext context = getHttpTransactionContext(ctx.getConnection());
            BodyHandler handler = this.bodyHandlerFactory.getBodyHandler(request);
            if (requestPacket.getHeaders().contains(Header.Expect) && requestPacket.getHeaders().getValue(1).equalsIgnoreCase("100-Continue")) {
                handler = new ExpectHandler(handler);
            }
            context.bodyHandler = handler;
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("REQUEST: " + requestPacket.toString());
            }
            return handler.doHandle(ctx, request, requestPacket);
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("REQUEST: " + requestPacket.toString());
        }
        ctx.write(requestPacket, ctx.getTransportContext().getCompletionHandler());
        return true;
    }

    /* access modifiers changed from: private */
    public static boolean requestHasEntityBody(Request request) {
        String method = request.getMethod();
        return Method.POST.matchesMethod(method) || Method.PUT.matchesMethod(method) || Method.PATCH.matchesMethod(method) || Method.DELETE.matchesMethod(method);
    }

    public static void main(String[] args) {
        SecureRandom secureRandom = new SecureRandom();
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, secureRandom);
        } catch (Exception e) {
            e.printStackTrace();
        }
        AsyncHttpClientConfig config = new AsyncHttpClientConfig.Builder().setConnectionTimeoutInMs(BaseImageDownloader.DEFAULT_HTTP_CONNECT_TIMEOUT).setSSLContext(sslContext).build();
        AsyncHttpClient client = new AsyncHttpClient((AsyncHttpProvider) new GrizzlyAsyncHttpProvider(config), config);
        try {
            long start = System.currentTimeMillis();
            try {
                client.executeRequest(client.prepareGet("http://www.google.com").build()).get();
            } catch (InterruptedException e2) {
                e2.printStackTrace();
            } catch (ExecutionException e3) {
                e3.printStackTrace();
            }
            System.out.println("COMPLETE: " + (System.currentTimeMillis() - start) + "ms");
        } catch (IOException e4) {
            e4.printStackTrace();
        }
    }
}