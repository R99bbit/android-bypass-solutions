package com.ning.http.client.providers.netty;

import android.support.v4.view.PointerIconCompat;
import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.AsyncHandlerExtensions;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.Body;
import com.ning.http.client.BodyGenerator;
import com.ning.http.client.ConnectionPoolKeyStrategy;
import com.ning.http.client.ConnectionsPool;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.FluentStringsMap;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.MaxRedirectException;
import com.ning.http.client.PerRequestConfig;
import com.ning.http.client.ProgressAsyncHandler;
import com.ning.http.client.ProxyServer;
import com.ning.http.client.RandomAccessBody;
import com.ning.http.client.Realm;
import com.ning.http.client.Realm.AuthScheme;
import com.ning.http.client.Realm.RealmBuilder;
import com.ning.http.client.Request;
import com.ning.http.client.Request.EntityWriter;
import com.ning.http.client.RequestBuilder;
import com.ning.http.client.Response;
import com.ning.http.client.cookie.CookieDecoder;
import com.ning.http.client.cookie.CookieEncoder;
import com.ning.http.client.filter.FilterContext;
import com.ning.http.client.filter.FilterContext.FilterContextBuilder;
import com.ning.http.client.filter.FilterException;
import com.ning.http.client.filter.IOExceptionFilter;
import com.ning.http.client.filter.ResponseFilter;
import com.ning.http.client.generators.InputStreamBodyGenerator;
import com.ning.http.client.listener.TransferCompletionHandler;
import com.ning.http.client.listener.TransferCompletionHandler.TransferAdapter;
import com.ning.http.client.ntlm.NTLMEngine;
import com.ning.http.client.ntlm.NTLMEngineException;
import com.ning.http.client.providers.netty.NettyConnectListener.Builder;
import com.ning.http.client.providers.netty.spnego.SpnegoEngine;
import com.ning.http.client.providers.netty.timeout.IdleConnectionTimeoutTimerTask;
import com.ning.http.client.providers.netty.timeout.RequestTimeoutTimerTask;
import com.ning.http.client.providers.netty.timeout.TimeoutsHolder;
import com.ning.http.client.websocket.WebSocket;
import com.ning.http.client.websocket.WebSocketUpgradeHandler;
import com.ning.http.multipart.MultipartBody;
import com.ning.http.multipart.MultipartRequestEntity;
import com.ning.http.util.AsyncHttpProviderUtils;
import com.ning.http.util.AuthenticatorUtils;
import com.ning.http.util.CleanupChannelGroup;
import com.ning.http.util.MiscUtil;
import com.ning.http.util.ProxyUtils;
import com.ning.http.util.SslUtils;
import com.ning.http.util.UTF8UrlEncoder;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLEngine;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferOutputStream;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureProgressListener;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.DefaultChannelFuture;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.FileRegion;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.channel.socket.ClientSocketChannelFactory;
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory;
import org.jboss.netty.channel.socket.oio.OioClientSocketChannelFactory;
import org.jboss.netty.handler.codec.PrematureChannelClosureException;
import org.jboss.netty.handler.codec.http.DefaultHttpChunkTrailer;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpChunkTrailer;
import org.jboss.netty.handler.codec.http.HttpClientCodec;
import org.jboss.netty.handler.codec.http.HttpContentDecompressor;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import org.jboss.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import org.jboss.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import org.jboss.netty.handler.codec.http.websocketx.WebSocket08FrameDecoder;
import org.jboss.netty.handler.codec.http.websocketx.WebSocket08FrameEncoder;
import org.jboss.netty.handler.codec.http.websocketx.WebSocketFrame;
import org.jboss.netty.handler.ssl.SslHandler;
import org.jboss.netty.handler.stream.ChunkedFile;
import org.jboss.netty.handler.stream.ChunkedWriteHandler;
import org.jboss.netty.util.HashedWheelTimer;
import org.jboss.netty.util.Timeout;
import org.jboss.netty.util.TimerTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NettyAsyncHttpProvider extends SimpleChannelUpstreamHandler implements AsyncHttpProvider {
    public static final String GZIP_DEFLATE = "gzip,deflate";
    private static final String HTTP = "http";
    private static final String HTTPS = "https";
    public static final String HTTP_HANDLER = "httpHandler";
    public static final String HTTP_PROCESSOR = "httpProcessor";
    public static final ThreadLocal<Boolean> IN_IO_THREAD = new ThreadLocalBoolean();
    private static final Logger LOGGER = LoggerFactory.getLogger(NettyAsyncHttpProvider.class);
    private static final int MAX_BUFFERED_BYTES = 8192;
    public static final IOException REMOTELY_CLOSED_EXCEPTION = new IOException("Remotely Closed");
    public static final String SSL_HANDLER = "sslHandler";
    /* access modifiers changed from: private */
    public static final Charset UTF8 = Charset.forName("UTF-8");
    private static final String WEBSOCKET = "ws";
    private static final String WEBSOCKET_SSL = "wss";
    public static final String WS_PROCESSOR = "wsProcessor";
    /* access modifiers changed from: private */
    public static final Logger log = LoggerFactory.getLogger(NettyAsyncHttpProvider.class);
    private static final NTLMEngine ntlmEngine = new NTLMEngine();
    private static SpnegoEngine spnegoEngine = null;
    private final boolean allowReleaseSocketChannelFactory;
    private final boolean allowStopHashedWheelTimer;
    /* access modifiers changed from: private */
    public final AsyncHttpClientConfig config;
    /* access modifiers changed from: private */
    public final ConnectionsPool<String, Channel> connectionsPool;
    private final boolean disableZeroCopy;
    private boolean executeConnectAsync = true;
    /* access modifiers changed from: private */
    public Semaphore freeConnections = null;
    private final HashedWheelTimer hashedWheelTimer;
    private int httpClientCodecMaxChunkSize = 8192;
    private int httpClientCodecMaxHeaderSize = 8192;
    private int httpClientCodecMaxInitialLineLength = 4096;
    private final Protocol httpProtocol = new HttpProtocol();
    private int httpsClientCodecMaxChunkSize = 8192;
    private int httpsClientCodecMaxHeaderSize = 8192;
    private int httpsClientCodecMaxInitialLineLength = 4096;
    private final AtomicBoolean isClose = new AtomicBoolean(false);
    private final ChannelGroup openChannels = new CleanupChannelGroup("asyncHttpClient") {
        public boolean remove(Object o) {
            boolean removed = super.remove(o);
            if (removed && NettyAsyncHttpProvider.this.trackConnections) {
                NettyAsyncHttpProvider.this.freeConnections.release();
            }
            return removed;
        }
    };
    private final ClientBootstrap plainBootstrap;
    private final NettyAsyncHttpProviderConfig providerConfig;
    private final ClientBootstrap secureBootstrap;
    private final ClientBootstrap secureWebSocketBootstrap;
    private final ClientSocketChannelFactory socketChannelFactory;
    /* access modifiers changed from: private */
    public final boolean trackConnections;
    private final boolean useRawUrl;
    private final ClientBootstrap webSocketBootstrap;
    private final Protocol webSocketProtocol = new WebSocketProtocol();

    private abstract class AsyncCallable implements Callable<Object> {
        private final NettyResponseFuture<?> future;

        public abstract Object call() throws Exception;

        public AsyncCallable(NettyResponseFuture<?> future2) {
            this.future = future2;
        }

        public NettyResponseFuture<?> future() {
            return this.future;
        }
    }

    static final class DiscardEvent {
        DiscardEvent() {
        }
    }

    private final class HttpProtocol implements Protocol {
        private HttpProtocol() {
        }

        /* JADX WARNING: Code restructure failed: missing block: B:110:0x03d5, code lost:
            r28 = move-exception;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:111:0x03d6, code lost:
            r43.this$0.abort(r9, r28);
         */
        /* JADX WARNING: Failed to process nested try/catch */
        public void handle(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
            Realm realm;
            Realm newRealm;
            RealmBuilder realmBuilder;
            Realm newRealm2;
            NettyResponseFuture<?> future = (NettyResponseFuture) ctx.getAttachment();
            future.touch();
            if (future.isCancelled() || future.isDone()) {
                NettyAsyncHttpProvider.this.finishChannel(ctx);
                return;
            }
            HttpRequest nettyRequest = future.getNettyRequest();
            AsyncHandler handler = future.getAsyncHandler();
            Request request = future.getRequest();
            ProxyServer proxyServer = future.getProxyServer();
            HttpResponse response = null;
            if (e.getMessage() instanceof HttpResponse) {
                response = (HttpResponse) e.getMessage();
                NettyAsyncHttpProvider.log.debug((String) "\n\nRequest {}\n\nResponse {}\n", (Object) nettyRequest, (Object) response);
                future.setHttpResponse(response);
                int statusCode = response.getStatus().getCode();
                String ka = response.getHeader("Connection");
                future.setKeepAlive(ka == null || ka.equalsIgnoreCase("keep-alive"));
                List<String> wwwAuth = NettyAsyncHttpProvider.this.getAuthorizationToken(response.getHeaders(), "WWW-Authenticate");
                if (request.getRealm() != null) {
                    realm = request.getRealm();
                } else {
                    realm = NettyAsyncHttpProvider.this.config.getRealm();
                }
                ResponseStatus responseStatus = new ResponseStatus(future.getURI(), response, NettyAsyncHttpProvider.this);
                ResponseHeaders responseHeaders = new ResponseHeaders(future.getURI(), response, NettyAsyncHttpProvider.this);
                FilterContext fc = new FilterContextBuilder().asyncHandler(handler).request(request).responseStatus(responseStatus).responseHeaders(responseHeaders).build();
                for (ResponseFilter filter : NettyAsyncHttpProvider.this.config.getResponseFilters()) {
                    try {
                        fc = filter.filter(fc);
                        if (fc == null) {
                            throw new NullPointerException("FilterContext is null");
                        }
                    } catch (FilterException efe) {
                        NettyAsyncHttpProvider.this.abort(future, efe);
                    }
                }
                AsyncHandler handler2 = fc.getAsyncHandler();
                future.setAsyncHandler(handler2);
                if (fc.replayRequest()) {
                    NettyAsyncHttpProvider.this.replayRequest(future, fc, response, ctx);
                    return;
                }
                FluentCaseInsensitiveStringsMap headers = request.getHeaders();
                final RequestBuilder builder = new RequestBuilder(future.getRequest());
                if (statusCode == 401 && realm != null && !wwwAuth.isEmpty() && !future.getAndSetAuth(true)) {
                    future.setState(STATE.NEW);
                    if (!wwwAuth.contains("Kerberos") && (NettyAsyncHttpProvider.isNTLM(wwwAuth) || wwwAuth.contains("Negotiate"))) {
                        newRealm2 = NettyAsyncHttpProvider.this.ntlmChallenge(wwwAuth, request, proxyServer, headers, realm, future);
                    } else if (wwwAuth.contains("Negotiate")) {
                        newRealm2 = NettyAsyncHttpProvider.this.kerberosChallenge(wwwAuth, request, proxyServer, headers, realm, future);
                        if (newRealm2 == null) {
                            return;
                        }
                    } else {
                        if (realm != null) {
                            realmBuilder = new RealmBuilder().clone(realm).setScheme(realm.getAuthScheme());
                        } else {
                            realmBuilder = new RealmBuilder();
                        }
                        newRealm2 = realmBuilder.setUri(request.getURI().getPath()).setMethodName(request.getMethod()).setUsePreemptiveAuth(true).parseWWWAuthenticateHeader(wwwAuth.get(0)).build();
                    }
                    final Realm nr = new RealmBuilder().clone(newRealm2).setUri(request.getUrl()).build();
                    NettyAsyncHttpProvider.log.debug((String) "Sending authentication to {}", (Object) request.getUrl());
                    final ChannelHandlerContext channelHandlerContext = ctx;
                    final NettyResponseFuture nettyResponseFuture = future;
                    final FluentCaseInsensitiveStringsMap fluentCaseInsensitiveStringsMap = headers;
                    AsyncCallable ac = new AsyncCallable(future) {
                        public Object call() throws Exception {
                            NettyAsyncHttpProvider.this.drainChannel(channelHandlerContext, nettyResponseFuture);
                            NettyAsyncHttpProvider.this.nextRequest(((RequestBuilder) builder.setHeaders(fluentCaseInsensitiveStringsMap).setRealm(nr)).build(), nettyResponseFuture);
                            return null;
                        }
                    };
                    if (!future.getKeepAlive() || !response.isChunked()) {
                        ac.call();
                    } else {
                        ctx.setAttachment(ac);
                    }
                } else if (statusCode == 100) {
                    future.getAndSetWriteHeaders(false);
                    future.getAndSetWriteBody(true);
                    NettyAsyncHttpProvider.this.writeRequest(ctx.getChannel(), NettyAsyncHttpProvider.this.config, future);
                } else {
                    List<String> proxyAuth = NettyAsyncHttpProvider.this.getAuthorizationToken(response.getHeaders(), "Proxy-Authenticate");
                    if (statusCode == 407 && realm != null && !proxyAuth.isEmpty() && !future.getAndSetAuth(true)) {
                        NettyAsyncHttpProvider.log.debug((String) "Sending proxy authentication to {}", (Object) request.getUrl());
                        future.setState(STATE.NEW);
                        if (!proxyAuth.contains("Kerberos") && (NettyAsyncHttpProvider.isNTLM(proxyAuth) || proxyAuth.contains("Negotiate"))) {
                            newRealm = NettyAsyncHttpProvider.this.ntlmProxyChallenge(proxyAuth, request, proxyServer, headers, realm, future);
                        } else if (proxyAuth.contains("Negotiate")) {
                            newRealm = NettyAsyncHttpProvider.this.kerberosChallenge(proxyAuth, request, proxyServer, headers, realm, future);
                            if (newRealm == null) {
                                return;
                            }
                        } else {
                            newRealm = future.getRequest().getRealm();
                        }
                        Request req = ((RequestBuilder) builder.setHeaders(headers).setRealm(newRealm)).build();
                        future.setReuseChannel(true);
                        future.setConnectAllowed(true);
                        NettyAsyncHttpProvider.this.nextRequest(req, future);
                    } else if (future.getNettyRequest().getMethod().equals(HttpMethod.CONNECT) && statusCode == 200) {
                        NettyAsyncHttpProvider.log.debug((String) "Connected to {}:{}", (Object) proxyServer.getHost(), (Object) Integer.valueOf(proxyServer.getPort()));
                        if (future.getKeepAlive()) {
                            future.attachChannel(ctx.getChannel(), true);
                        }
                        try {
                            NettyAsyncHttpProvider.log.debug((String) "Connecting to proxy {} for scheme {}", (Object) proxyServer, (Object) request.getUrl());
                            NettyAsyncHttpProvider.this.upgradeProtocol(ctx.getChannel().getPipeline(), request.getURI().getScheme());
                            Request req2 = builder.build();
                            future.setReuseChannel(true);
                            future.setConnectAllowed(false);
                            NettyAsyncHttpProvider.this.nextRequest(req2, future);
                        } catch (Exception t) {
                            if ((t instanceof IOException) && !NettyAsyncHttpProvider.this.config.getIOExceptionFilters().isEmpty()) {
                                FilterContext<?> fc2 = NettyAsyncHttpProvider.this.handleIoException(new FilterContextBuilder().asyncHandler(future.getAsyncHandler()).request(future.getRequest()).ioException(IOException.class.cast(t)).build(), future);
                                if (fc2.replayRequest()) {
                                    NettyAsyncHttpProvider.this.replayRequest(future, fc2, response, ctx);
                                    return;
                                }
                            }
                            NettyAsyncHttpProvider.this.abort(future, t);
                            NettyAsyncHttpProvider.this.finishUpdate(future, ctx, false);
                            throw t;
                        } catch (Throwable th) {
                            NettyAsyncHttpProvider.this.finishUpdate(future, ctx, false);
                            throw t;
                        }
                    } else if (NettyAsyncHttpProvider.this.redirect(request, future, response, ctx)) {
                    } else {
                        if (!future.getAndSetStatusReceived(true) && NettyAsyncHttpProvider.this.updateStatusAndInterrupt(handler2, responseStatus)) {
                            NettyAsyncHttpProvider.this.finishUpdate(future, ctx, response.isChunked());
                        } else if (!response.getHeaders().isEmpty() && NettyAsyncHttpProvider.this.updateHeadersAndInterrupt(handler2, responseHeaders)) {
                            NettyAsyncHttpProvider.this.finishUpdate(future, ctx, response.isChunked());
                        } else if (!response.isChunked()) {
                            NettyAsyncHttpProvider.this.updateBodyAndInterrupt(future, handler2, new ResponseBodyPart(future.getURI(), response, NettyAsyncHttpProvider.this, true));
                            NettyAsyncHttpProvider.this.finishUpdate(future, ctx, false);
                        } else if (nettyRequest.getMethod().equals(HttpMethod.HEAD)) {
                            NettyAsyncHttpProvider.this.updateBodyAndInterrupt(future, handler2, new ResponseBodyPart(future.getURI(), response, NettyAsyncHttpProvider.this, true));
                            NettyAsyncHttpProvider.this.markAsDone(future, ctx);
                            NettyAsyncHttpProvider.this.drainChannel(ctx, future);
                        }
                    }
                }
            } else if (e.getMessage() instanceof HttpChunk) {
                HttpChunk chunk = (HttpChunk) e.getMessage();
                if (handler == null) {
                    return;
                }
                if (chunk.isLast() || NettyAsyncHttpProvider.this.updateBodyAndInterrupt(future, handler, new ResponseBodyPart(future.getURI(), null, NettyAsyncHttpProvider.this, chunk, chunk.isLast()))) {
                    if (chunk instanceof DefaultHttpChunkTrailer) {
                        NettyAsyncHttpProvider.this.updateHeadersAndInterrupt(handler, new ResponseHeaders(future.getURI(), future.getHttpResponse(), NettyAsyncHttpProvider.this, (HttpChunkTrailer) chunk));
                    }
                    NettyAsyncHttpProvider.this.finishUpdate(future, ctx, !chunk.isLast());
                }
            }
        }

        public void onError(ChannelHandlerContext ctx, ExceptionEvent e) {
        }

        public void onClose(ChannelHandlerContext ctx, ChannelStateEvent e) {
        }
    }

    private static class NettyTransferAdapter extends TransferAdapter {
        private int byteRead = 0;
        private final ChannelBuffer content;
        private final FileInputStream file;

        public NettyTransferAdapter(FluentCaseInsensitiveStringsMap headers, ChannelBuffer content2, File file2) throws IOException {
            super(headers);
            this.content = content2;
            if (file2 != null) {
                this.file = new FileInputStream(file2);
            } else {
                this.file = null;
            }
        }

        public void getBytes(byte[] bytes) {
            if (this.content.writableBytes() != 0) {
                this.content.getBytes(this.byteRead, bytes);
                this.byteRead += bytes.length;
            } else if (this.file != null) {
                try {
                    this.byteRead += this.file.read(bytes);
                } catch (IOException e) {
                    NettyAsyncHttpProvider.log.error(e.getMessage(), (Throwable) e);
                }
            }
        }
    }

    private static class NonConnectionsPool implements ConnectionsPool<String, Channel> {
        private NonConnectionsPool() {
        }

        public boolean offer(String uri, Channel connection) {
            return false;
        }

        public Channel poll(String uri) {
            return null;
        }

        public boolean removeAll(Channel connection) {
            return false;
        }

        public boolean canCacheConnection() {
            return true;
        }

        public void destroy() {
        }
    }

    public static class OptimizedFileRegion implements FileRegion {
        private long byteWritten;
        private final long count;
        private final FileChannel file;
        private final long position;
        private final RandomAccessFile raf;

        public OptimizedFileRegion(RandomAccessFile raf2, long position2, long count2) {
            this.raf = raf2;
            this.file = raf2.getChannel();
            this.position = position2;
            this.count = count2;
        }

        public long getPosition() {
            return this.position;
        }

        public long getCount() {
            return this.count;
        }

        public long transferTo(WritableByteChannel target, long position2) throws IOException {
            long bw = 0;
            long count2 = this.count - position2;
            if (count2 < 0 || position2 < 0) {
                throw new IllegalArgumentException("position out of range: " + position2 + " (expected: 0 - " + (this.count - 1) + ")");
            }
            if (count2 != 0) {
                bw = this.file.transferTo(this.position + position2, count2, target);
                this.byteWritten += bw;
                if (this.byteWritten == this.raf.length()) {
                    releaseExternalResources();
                }
            }
            return bw;
        }

        public void releaseExternalResources() {
            try {
                this.file.close();
            } catch (IOException e) {
                NettyAsyncHttpProvider.log.warn((String) "Failed to close a file.", (Throwable) e);
            }
            try {
                this.raf.close();
            } catch (IOException e2) {
                NettyAsyncHttpProvider.log.warn((String) "Failed to close a file.", (Throwable) e2);
            }
        }
    }

    private class ProgressListener implements ChannelFutureProgressListener {
        private final AsyncHandler asyncHandler;
        private final NettyResponseFuture<?> future;
        private final boolean notifyHeaders;

        public ProgressListener(boolean notifyHeaders2, AsyncHandler asyncHandler2, NettyResponseFuture<?> future2) {
            this.notifyHeaders = notifyHeaders2;
            this.asyncHandler = asyncHandler2;
            this.future = future2;
        }

        public void operationComplete(ChannelFuture cf) {
            Throwable cause = cf.getCause();
            if (cause == null || this.future.getState() == STATE.NEW) {
                this.future.touch();
                Realm realm = this.future.getRequest().getRealm() != null ? this.future.getRequest().getRealm() : NettyAsyncHttpProvider.this.getConfig().getRealm();
                if ((this.future.isInAuth() || realm == null || realm.getUsePreemptiveAuth()) && (this.asyncHandler instanceof ProgressAsyncHandler)) {
                    if (this.notifyHeaders) {
                        ProgressAsyncHandler.class.cast(this.asyncHandler).onHeaderWriteCompleted();
                    } else {
                        ProgressAsyncHandler.class.cast(this.asyncHandler).onContentWriteCompleted();
                    }
                }
            } else if (cause instanceof IllegalStateException) {
                NettyAsyncHttpProvider.log.debug(cause.getMessage(), cause);
                try {
                    cf.getChannel().close();
                } catch (RuntimeException ex) {
                    NettyAsyncHttpProvider.log.debug(ex.getMessage(), (Throwable) ex);
                }
            } else if ((cause instanceof ClosedChannelException) || NettyAsyncHttpProvider.abortOnReadCloseException(cause) || NettyAsyncHttpProvider.abortOnWriteCloseException(cause)) {
                if (NettyAsyncHttpProvider.log.isDebugEnabled()) {
                    NettyAsyncHttpProvider.log.debug(cf.getCause() == null ? "" : cf.getCause().getMessage(), cf.getCause());
                }
                try {
                    cf.getChannel().close();
                } catch (RuntimeException ex2) {
                    NettyAsyncHttpProvider.log.debug(ex2.getMessage(), (Throwable) ex2);
                }
            } else {
                this.future.abort(cause);
            }
        }

        public void operationProgressed(ChannelFuture cf, long amount, long current, long total) {
            this.future.touch();
            if (this.asyncHandler instanceof ProgressAsyncHandler) {
                ProgressAsyncHandler.class.cast(this.asyncHandler).onContentWriteProgress(amount, current, total);
            }
        }
    }

    public static class ThreadLocalBoolean extends ThreadLocal<Boolean> {
        private final boolean defaultValue;

        public ThreadLocalBoolean() {
            this(false);
        }

        public ThreadLocalBoolean(boolean defaultValue2) {
            this.defaultValue = defaultValue2;
        }

        /* access modifiers changed from: protected */
        public Boolean initialValue() {
            return this.defaultValue ? Boolean.TRUE : Boolean.FALSE;
        }
    }

    private final class WebSocketProtocol implements Protocol {
        private static final byte OPCODE_BINARY = 2;
        private static final byte OPCODE_CONT = 0;
        private static final byte OPCODE_TEXT = 1;
        private static final byte OPCODE_UNKNOWN = -1;

        private WebSocketProtocol() {
        }

        private void invokeOnSucces(ChannelHandlerContext ctx, WebSocketUpgradeHandler h) {
            if (!h.touchSuccess()) {
                try {
                    h.onSuccess((WebSocket) new NettyWebSocket(ctx.getChannel()));
                } catch (Exception ex) {
                    NettyAsyncHttpProvider nettyAsyncHttpProvider = NettyAsyncHttpProvider.this;
                    NettyAsyncHttpProvider.log.warn((String) "onSuccess unexexpected exception", (Throwable) ex);
                }
            }
        }

        public void handle(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
            NettyResponseFuture future = NettyResponseFuture.class.cast(ctx.getAttachment());
            WebSocketUpgradeHandler h = WebSocketUpgradeHandler.class.cast(future.getAsyncHandler());
            Request request = future.getRequest();
            if (e.getMessage() instanceof HttpResponse) {
                HttpResponse response = (HttpResponse) e.getMessage();
                ResponseStatus responseStatus = new ResponseStatus(future.getURI(), response, NettyAsyncHttpProvider.this);
                ResponseHeaders responseHeaders = new ResponseHeaders(future.getURI(), response, NettyAsyncHttpProvider.this);
                FilterContext<?> fc = new FilterContextBuilder().asyncHandler(h).request(request).responseStatus(responseStatus).responseHeaders(responseHeaders).build();
                for (ResponseFilter asyncFilter : NettyAsyncHttpProvider.this.config.getResponseFilters()) {
                    try {
                        fc = asyncFilter.filter(fc);
                        if (fc == null) {
                            throw new NullPointerException("FilterContext is null");
                        }
                    } catch (FilterException efe) {
                        NettyAsyncHttpProvider.this.abort(future, efe);
                    }
                }
                future.setAsyncHandler(fc.getAsyncHandler());
                if (fc.replayRequest()) {
                    NettyAsyncHttpProvider.this.replayRequest(future, fc, response, ctx);
                    return;
                }
                future.setHttpResponse(response);
                if (!NettyAsyncHttpProvider.this.redirect(request, future, response, ctx)) {
                    HttpResponseStatus httpResponseStatus = new HttpResponseStatus(101, "Web Socket Protocol Handshake");
                    boolean validStatus = response.getStatus().equals(httpResponseStatus);
                    boolean validUpgrade = response.getHeader("Upgrade") != null;
                    String c = response.getHeader("Connection");
                    if (c == null) {
                        c = response.getHeader("connection");
                    }
                    boolean validConnection = c == null ? false : c.equalsIgnoreCase("Upgrade");
                    ResponseStatus responseStatus2 = new ResponseStatus(future.getURI(), response, NettyAsyncHttpProvider.this);
                    if (!(h.onStatusReceived(responseStatus2) == STATE.UPGRADE)) {
                        try {
                            h.onCompleted();
                        } finally {
                            future.done();
                        }
                    } else {
                        if (!(h.onHeadersReceived(responseHeaders) == STATE.CONTINUE) || !validStatus || !validUpgrade || !validConnection) {
                            NettyAsyncHttpProvider.this.abort(future, new IOException("Invalid handshake response"));
                            return;
                        }
                        String accept = response.getHeader(Names.SEC_WEBSOCKET_ACCEPT);
                        String key = WebSocketUtil.getAcceptKey(future.getNettyRequest().getHeader(Names.SEC_WEBSOCKET_KEY));
                        if (accept == null || !accept.equals(key)) {
                            NettyAsyncHttpProvider.this.abort(future, new IOException(String.format("Invalid challenge. Actual: %s. Expected: %s", new Object[]{accept, key})));
                            return;
                        }
                        ctx.getPipeline().replace((String) NettyAsyncHttpProvider.HTTP_HANDLER, (String) "ws-encoder", (ChannelHandler) new WebSocket08FrameEncoder(true));
                        ctx.getPipeline().addBefore(NettyAsyncHttpProvider.WS_PROCESSOR, "ws-decoder", new WebSocket08FrameDecoder(false, false));
                        invokeOnSucces(ctx, h);
                        future.done();
                    }
                }
            } else if (e.getMessage() instanceof WebSocketFrame) {
                invokeOnSucces(ctx, h);
                WebSocketFrame frame = (WebSocketFrame) e.getMessage();
                char c2 = 65535;
                if (frame instanceof TextWebSocketFrame) {
                    c2 = 1;
                } else if (frame instanceof BinaryWebSocketFrame) {
                    c2 = 2;
                }
                HttpChunk webSocketChunk = new HttpChunk() {
                    private ChannelBuffer content;

                    public boolean isLast() {
                        return false;
                    }

                    public ChannelBuffer getContent() {
                        return this.content;
                    }

                    public void setContent(ChannelBuffer content2) {
                        this.content = content2;
                    }
                };
                if (frame.getBinaryData() != null) {
                    webSocketChunk.setContent(ChannelBuffers.wrappedBuffer(frame.getBinaryData()));
                    ResponseBodyPart rp = new ResponseBodyPart(future.getURI(), null, NettyAsyncHttpProvider.this, webSocketChunk, true);
                    h.onBodyPartReceived(rp);
                    NettyWebSocket webSocket = NettyWebSocket.class.cast(h.onCompleted());
                    if (webSocket != null) {
                        if (c2 == 2) {
                            webSocket.onBinaryFragment(rp.getBodyPartBytes(), frame.isFinalFragment());
                        } else if (c2 == 1) {
                            webSocket.onTextFragment(frame.getBinaryData().toString(NettyAsyncHttpProvider.UTF8), frame.isFinalFragment());
                        }
                        if (frame instanceof CloseWebSocketFrame) {
                            try {
                                ctx.setAttachment(DiscardEvent.class);
                                webSocket.onClose(CloseWebSocketFrame.class.cast(frame).getStatusCode(), CloseWebSocketFrame.class.cast(frame).getReasonText());
                            } catch (Throwable t) {
                                NettyAsyncHttpProvider.log.trace((String) "", t);
                            } finally {
                                h.resetSuccess();
                            }
                        }
                    } else {
                        NettyAsyncHttpProvider.log.debug("UpgradeHandler returned a null NettyWebSocket ");
                    }
                }
            } else {
                NettyAsyncHttpProvider.log.error((String) "Invalid attachment {}", ctx.getAttachment());
            }
        }

        public void onError(ChannelHandlerContext ctx, ExceptionEvent e) {
            try {
                NettyAsyncHttpProvider.log.warn((String) "onError {}", (Object) e);
                if (ctx.getAttachment() instanceof NettyResponseFuture) {
                    NettyWebSocket webSocket = NettyWebSocket.class.cast(WebSocketUpgradeHandler.class.cast(NettyResponseFuture.class.cast(ctx.getAttachment()).getAsyncHandler()).onCompleted());
                    if (webSocket != null) {
                        webSocket.onError(e.getCause());
                        webSocket.close();
                    }
                }
            } catch (Throwable t) {
                NettyAsyncHttpProvider.log.error((String) "onError", t);
            }
        }

        public void onClose(ChannelHandlerContext ctx, ChannelStateEvent e) {
            NettyAsyncHttpProvider.log.trace((String) "onClose {}", (Object) e);
            if (ctx.getAttachment() instanceof NettyResponseFuture) {
                try {
                    WebSocketUpgradeHandler h = WebSocketUpgradeHandler.class.cast(NettyResponseFuture.class.cast(ctx.getAttachment()).getAsyncHandler());
                    NettyWebSocket webSocket = NettyWebSocket.class.cast(h.onCompleted());
                    h.resetSuccess();
                    NettyAsyncHttpProvider.log.trace("Connection was closed abnormally (that is, with no close frame being sent).");
                    if (!(ctx.getAttachment() instanceof DiscardEvent) && webSocket != null) {
                        webSocket.close(PointerIconCompat.TYPE_CELL, "Connection was closed abnormally (that is, with no close frame being sent).");
                    }
                } catch (Throwable t) {
                    NettyAsyncHttpProvider.log.error((String) "onError", t);
                }
            }
        }
    }

    static {
        REMOTELY_CLOSED_EXCEPTION.setStackTrace(new StackTraceElement[0]);
    }

    /* access modifiers changed from: private */
    public static boolean isNTLM(List<String> auth) {
        return MiscUtil.isNonEmpty((Collection<?>) auth) && auth.get(0).startsWith("NTLM");
    }

    /*  JADX ERROR: IF instruction can be used only in fallback mode
        jadx.core.utils.exceptions.CodegenException: IF instruction can be used only in fallback mode
        	at jadx.core.codegen.InsnGen.fallbackOnlyInsn(InsnGen.java:571)
        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:477)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:242)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:213)
        	at jadx.core.codegen.RegionGen.makeSimpleBlock(RegionGen.java:109)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:55)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:92)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:58)
        	at jadx.core.codegen.RegionGen.makeRegionIndent(RegionGen.java:98)
        	at jadx.core.codegen.RegionGen.makeIf(RegionGen.java:142)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:62)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:92)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:58)
        	at jadx.core.codegen.MethodGen.addRegionInsns(MethodGen.java:210)
        	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:203)
        	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:315)
        	at jadx.core.codegen.ClassGen.addMethods(ClassGen.java:261)
        	at jadx.core.codegen.ClassGen.addClassBody(ClassGen.java:224)
        	at jadx.core.codegen.ClassGen.addClassCode(ClassGen.java:109)
        	at jadx.core.codegen.ClassGen.makeClass(ClassGen.java:75)
        	at jadx.core.codegen.CodeGen.wrapCodeGen(CodeGen.java:44)
        	at jadx.core.codegen.CodeGen.generateJavaCode(CodeGen.java:32)
        	at jadx.core.codegen.CodeGen.generate(CodeGen.java:20)
        	at jadx.core.ProcessClass.process(ProcessClass.java:36)
        	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
        	at jadx.api.JavaClass.decompile(JavaClass.java:62)
        */
    /* JADX WARNING: Code restructure failed: missing block: B:37:0x0165, code lost:
        r0 = new com.ning.http.client.providers.netty.NettyAsyncHttpProvider.NonConnectionsPool(null);
     */
    public NettyAsyncHttpProvider(com.ning.http.client.AsyncHttpClientConfig r12) {
        /*
            r11 = this;
            r9 = 4096(0x1000, float:5.74E-42)
            r10 = 0
            r8 = 8192(0x2000, float:1.14794E-41)
            r7 = 0
            r6 = 1
            r11.<init>()
            java.util.concurrent.atomic.AtomicBoolean r5 = new java.util.concurrent.atomic.AtomicBoolean
            r5.<init>(r7)
            r11.isClose = r5
            r11.httpClientCodecMaxInitialLineLength = r9
            r11.httpClientCodecMaxHeaderSize = r8
            r11.httpClientCodecMaxChunkSize = r8
            r11.httpsClientCodecMaxInitialLineLength = r9
            r11.httpsClientCodecMaxHeaderSize = r8
            r11.httpsClientCodecMaxChunkSize = r8
            com.ning.http.client.providers.netty.NettyAsyncHttpProvider$1 r5 = new com.ning.http.client.providers.netty.NettyAsyncHttpProvider$1
            java.lang.String r8 = "asyncHttpClient"
            r5.<init>(r8)
            r11.openChannels = r5
            r11.freeConnections = r10
            r11.executeConnectAsync = r6
            com.ning.http.client.providers.netty.NettyAsyncHttpProvider$HttpProtocol r5 = new com.ning.http.client.providers.netty.NettyAsyncHttpProvider$HttpProtocol
            r5.<init>()
            r11.httpProtocol = r5
            com.ning.http.client.providers.netty.NettyAsyncHttpProvider$WebSocketProtocol r5 = new com.ning.http.client.providers.netty.NettyAsyncHttpProvider$WebSocketProtocol
            r5.<init>()
            r11.webSocketProtocol = r5
            com.ning.http.client.AsyncHttpProviderConfig r5 = r12.getAsyncHttpProviderConfig()
            boolean r5 = r5 instanceof com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig
            if (r5 == 0) goto L_0x00f1
            java.lang.Class<com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig> r5 = com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig.class
            com.ning.http.client.AsyncHttpProviderConfig r8 = r12.getAsyncHttpProviderConfig()
            java.lang.Object r5 = r5.cast(r8)
            com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig r5 = (com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig) r5
            r11.providerConfig = r5
        L_0x004f:
            int r5 = r12.getRequestCompressionLevel()
            if (r5 <= 0) goto L_0x005d
            org.slf4j.Logger r5 = LOGGER
            java.lang.String r8 = "Request was enabled but Netty actually doesn't support this feature"
            r5.warn(r8)
        L_0x005d:
            com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig r5 = r11.providerConfig
            java.lang.String r8 = "useBlockingIO"
            java.lang.Object r5 = r5.getProperty(r8)
            if (r5 == 0) goto L_0x00fa
            org.jboss.netty.channel.socket.oio.OioClientSocketChannelFactory r5 = new org.jboss.netty.channel.socket.oio.OioClientSocketChannelFactory
            java.util.concurrent.ExecutorService r8 = r12.executorService()
            r5.<init>(r8)
            r11.socketChannelFactory = r5
            r11.allowReleaseSocketChannelFactory = r6
        L_0x0075:
            com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig r5 = r11.providerConfig
            org.jboss.netty.util.HashedWheelTimer r5 = r5.getHashedWheelTimer()
            if (r5 != 0) goto L_0x0158
            r5 = r6
        L_0x007e:
            r11.allowStopHashedWheelTimer = r5
            boolean r5 = r11.allowStopHashedWheelTimer
            if (r5 == 0) goto L_0x015b
            org.jboss.netty.util.HashedWheelTimer r5 = new org.jboss.netty.util.HashedWheelTimer
            r5.<init>()
        L_0x0089:
            r11.hashedWheelTimer = r5
            org.jboss.netty.util.HashedWheelTimer r5 = r11.hashedWheelTimer
            r5.start()
            org.jboss.netty.bootstrap.ClientBootstrap r5 = new org.jboss.netty.bootstrap.ClientBootstrap
            org.jboss.netty.channel.socket.ClientSocketChannelFactory r8 = r11.socketChannelFactory
            r5.<init>(r8)
            r11.plainBootstrap = r5
            org.jboss.netty.bootstrap.ClientBootstrap r5 = new org.jboss.netty.bootstrap.ClientBootstrap
            org.jboss.netty.channel.socket.ClientSocketChannelFactory r8 = r11.socketChannelFactory
            r5.<init>(r8)
            r11.secureBootstrap = r5
            org.jboss.netty.bootstrap.ClientBootstrap r5 = new org.jboss.netty.bootstrap.ClientBootstrap
            org.jboss.netty.channel.socket.ClientSocketChannelFactory r8 = r11.socketChannelFactory
            r5.<init>(r8)
            r11.webSocketBootstrap = r5
            org.jboss.netty.bootstrap.ClientBootstrap r5 = new org.jboss.netty.bootstrap.ClientBootstrap
            org.jboss.netty.channel.socket.ClientSocketChannelFactory r8 = r11.socketChannelFactory
            r5.<init>(r8)
            r11.secureWebSocketBootstrap = r5
            r11.config = r12
            r11.configureNetty()
            com.ning.http.client.ConnectionsPool r0 = r12.getConnectionsPool()
            if (r0 != 0) goto L_0x0163
            boolean r5 = r12.getAllowPoolingConnection()
            if (r5 == 0) goto L_0x0163
            com.ning.http.client.providers.netty.NettyConnectionsPool r0 = new com.ning.http.client.providers.netty.NettyConnectionsPool
            org.jboss.netty.util.HashedWheelTimer r5 = r11.hashedWheelTimer
            r0.<init>(r11, r5)
        L_0x00cc:
            r11.connectionsPool = r0
            int r5 = r12.getMaxTotalConnections()
            r8 = -1
            if (r5 == r8) goto L_0x016c
            r11.trackConnections = r6
            java.util.concurrent.Semaphore r5 = new java.util.concurrent.Semaphore
            int r6 = r12.getMaxTotalConnections()
            r5.<init>(r6)
            r11.freeConnections = r5
        L_0x00e2:
            boolean r5 = r12.isUseRawUrl()
            r11.useRawUrl = r5
            com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig r5 = r11.providerConfig
            boolean r5 = r5.isDisableZeroCopy()
            r11.disableZeroCopy = r5
            return
        L_0x00f1:
            com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig r5 = new com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig
            r5.<init>()
            r11.providerConfig = r5
            goto L_0x004f
        L_0x00fa:
            com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig r5 = r11.providerConfig
            java.lang.String r8 = "socketChannelFactory"
            java.lang.Object r4 = r5.getProperty(r8)
            boolean r5 = r4 instanceof org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory
            if (r5 == 0) goto L_0x0115
            java.lang.Class<org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory> r5 = org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory.class
            java.lang.Object r5 = r5.cast(r4)
            org.jboss.netty.channel.socket.ClientSocketChannelFactory r5 = (org.jboss.netty.channel.socket.ClientSocketChannelFactory) r5
            r11.socketChannelFactory = r5
            r11.allowReleaseSocketChannelFactory = r7
            goto L_0x0075
        L_0x0115:
            com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig r5 = r11.providerConfig
            java.lang.String r8 = "bossExecutorService"
            java.lang.Object r3 = r5.getProperty(r8)
            boolean r5 = r3 instanceof java.util.concurrent.ExecutorService
            if (r5 == 0) goto L_0x0153
            java.lang.Class<java.util.concurrent.ExecutorService> r5 = java.util.concurrent.ExecutorService.class
            java.lang.Object r1 = r5.cast(r3)
            java.util.concurrent.ExecutorService r1 = (java.util.concurrent.ExecutorService) r1
        L_0x012a:
            int r5 = r12.getIoThreadMultiplier()
            java.lang.Runtime r8 = java.lang.Runtime.getRuntime()
            int r8 = r8.availableProcessors()
            int r2 = r5 * r8
            org.slf4j.Logger r5 = log
            java.lang.String r8 = "Number of application's worker threads is {}"
            java.lang.Integer r9 = java.lang.Integer.valueOf(r2)
            r5.trace(r8, r9)
            org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory r5 = new org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory
            java.util.concurrent.ExecutorService r8 = r12.executorService()
            r5.<init>(r1, r8, r2)
            r11.socketChannelFactory = r5
            r11.allowReleaseSocketChannelFactory = r6
            goto L_0x0075
        L_0x0153:
            java.util.concurrent.ExecutorService r1 = java.util.concurrent.Executors.newCachedThreadPool()
            goto L_0x012a
        L_0x0158:
            r5 = r7
            goto L_0x007e
        L_0x015b:
            com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig r5 = r11.providerConfig
            org.jboss.netty.util.HashedWheelTimer r5 = r5.getHashedWheelTimer()
            goto L_0x0089
        L_0x0163:
            if (r0 != 0) goto L_0x00cc
            com.ning.http.client.providers.netty.NettyAsyncHttpProvider$NonConnectionsPool r0 = new com.ning.http.client.providers.netty.NettyAsyncHttpProvider$NonConnectionsPool
            r0.<init>()
            goto L_0x00cc
        L_0x016c:
            r11.trackConnections = r7
            goto L_0x00e2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ning.http.client.providers.netty.NettyAsyncHttpProvider.<init>(com.ning.http.client.AsyncHttpClientConfig):void");
    }

    public String toString() {
        int availablePermits;
        if (this.freeConnections != null) {
            availablePermits = this.freeConnections.availablePermits();
        } else {
            availablePermits = 0;
        }
        return String.format("NettyAsyncHttpProvider:\n\t- maxConnections: %d\n\t- openChannels: %s\n\t- connectionPools: %s", new Object[]{Integer.valueOf(this.config.getMaxTotalConnections() - availablePermits), this.openChannels.toString(), this.connectionsPool.toString()});
    }

    /* access modifiers changed from: 0000 */
    public void configureNetty() {
        if (this.providerConfig != null) {
            for (Entry<String, Object> entry : this.providerConfig.propertiesSet()) {
                this.plainBootstrap.setOption(entry.getKey(), entry.getValue());
            }
            configureHttpClientCodec();
            configureHttpsClientCodec();
        }
        this.plainBootstrap.setPipelineFactory(new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() throws Exception {
                ChannelPipeline pipeline = Channels.pipeline();
                pipeline.addLast(NettyAsyncHttpProvider.HTTP_HANDLER, NettyAsyncHttpProvider.this.createHttpClientCodec());
                if (NettyAsyncHttpProvider.this.config.isCompressionEnabled()) {
                    pipeline.addLast("inflater", new HttpContentDecompressor());
                }
                pipeline.addLast("chunkedWriter", new ChunkedWriteHandler());
                pipeline.addLast(NettyAsyncHttpProvider.HTTP_PROCESSOR, NettyAsyncHttpProvider.this);
                return pipeline;
            }
        });
        DefaultChannelFuture.setUseDeadLockChecker(false);
        if (this.providerConfig != null) {
            Object value = this.providerConfig.getProperty((String) NettyAsyncHttpProviderConfig.EXECUTE_ASYNC_CONNECT);
            if (value instanceof Boolean) {
                this.executeConnectAsync = Boolean.class.cast(value).booleanValue();
            } else if (this.providerConfig.getProperty((String) NettyAsyncHttpProviderConfig.DISABLE_NESTED_REQUEST) != null) {
                DefaultChannelFuture.setUseDeadLockChecker(true);
            }
        }
        this.webSocketBootstrap.setPipelineFactory(new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() throws Exception {
                ChannelPipeline pipeline = Channels.pipeline();
                pipeline.addLast(NettyAsyncHttpProvider.HTTP_HANDLER, NettyAsyncHttpProvider.this.createHttpClientCodec());
                pipeline.addLast(NettyAsyncHttpProvider.WS_PROCESSOR, NettyAsyncHttpProvider.this);
                return pipeline;
            }
        });
    }

    /* access modifiers changed from: protected */
    public void configureHttpClientCodec() {
        this.httpClientCodecMaxInitialLineLength = ((Integer) this.providerConfig.getProperty(NettyAsyncHttpProviderConfig.HTTP_CLIENT_CODEC_MAX_INITIAL_LINE_LENGTH, Integer.class, Integer.valueOf(this.httpClientCodecMaxInitialLineLength))).intValue();
        this.httpClientCodecMaxHeaderSize = ((Integer) this.providerConfig.getProperty(NettyAsyncHttpProviderConfig.HTTP_CLIENT_CODEC_MAX_HEADER_SIZE, Integer.class, Integer.valueOf(this.httpClientCodecMaxHeaderSize))).intValue();
        this.httpClientCodecMaxChunkSize = ((Integer) this.providerConfig.getProperty(NettyAsyncHttpProviderConfig.HTTP_CLIENT_CODEC_MAX_CHUNK_SIZE, Integer.class, Integer.valueOf(this.httpClientCodecMaxChunkSize))).intValue();
    }

    /* access modifiers changed from: protected */
    public void configureHttpsClientCodec() {
        this.httpsClientCodecMaxInitialLineLength = ((Integer) this.providerConfig.getProperty(NettyAsyncHttpProviderConfig.HTTPS_CLIENT_CODEC_MAX_INITIAL_LINE_LENGTH, Integer.class, Integer.valueOf(this.httpsClientCodecMaxInitialLineLength))).intValue();
        this.httpsClientCodecMaxHeaderSize = ((Integer) this.providerConfig.getProperty(NettyAsyncHttpProviderConfig.HTTPS_CLIENT_CODEC_MAX_HEADER_SIZE, Integer.class, Integer.valueOf(this.httpsClientCodecMaxHeaderSize))).intValue();
        this.httpsClientCodecMaxChunkSize = ((Integer) this.providerConfig.getProperty(NettyAsyncHttpProviderConfig.HTTPS_CLIENT_CODEC_MAX_CHUNK_SIZE, Integer.class, Integer.valueOf(this.httpsClientCodecMaxChunkSize))).intValue();
    }

    /* access modifiers changed from: 0000 */
    public void constructSSLPipeline(final NettyConnectListener<?> cl) {
        this.secureBootstrap.setPipelineFactory(new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() throws Exception {
                ChannelPipeline pipeline = Channels.pipeline();
                try {
                    pipeline.addLast(NettyAsyncHttpProvider.SSL_HANDLER, new SslHandler(NettyAsyncHttpProvider.this.createSSLEngine()));
                } catch (Throwable ex) {
                    NettyAsyncHttpProvider.this.abort(cl.future(), ex);
                }
                pipeline.addLast(NettyAsyncHttpProvider.HTTP_HANDLER, NettyAsyncHttpProvider.this.createHttpsClientCodec());
                if (NettyAsyncHttpProvider.this.config.isCompressionEnabled()) {
                    pipeline.addLast("inflater", new HttpContentDecompressor());
                }
                pipeline.addLast("chunkedWriter", new ChunkedWriteHandler());
                pipeline.addLast(NettyAsyncHttpProvider.HTTP_PROCESSOR, NettyAsyncHttpProvider.this);
                return pipeline;
            }
        });
        this.secureWebSocketBootstrap.setPipelineFactory(new ChannelPipelineFactory() {
            public ChannelPipeline getPipeline() throws Exception {
                ChannelPipeline pipeline = Channels.pipeline();
                try {
                    pipeline.addLast(NettyAsyncHttpProvider.SSL_HANDLER, new SslHandler(NettyAsyncHttpProvider.this.createSSLEngine()));
                } catch (Throwable ex) {
                    NettyAsyncHttpProvider.this.abort(cl.future(), ex);
                }
                pipeline.addLast(NettyAsyncHttpProvider.HTTP_HANDLER, NettyAsyncHttpProvider.this.createHttpsClientCodec());
                pipeline.addLast(NettyAsyncHttpProvider.WS_PROCESSOR, NettyAsyncHttpProvider.this);
                return pipeline;
            }
        });
        if (this.providerConfig != null) {
            for (Entry<String, Object> entry : this.providerConfig.propertiesSet()) {
                this.secureBootstrap.setOption(entry.getKey(), entry.getValue());
                this.secureWebSocketBootstrap.setOption(entry.getKey(), entry.getValue());
            }
        }
    }

    private Channel lookupInCache(URI uri, ConnectionPoolKeyStrategy connectionPoolKeyStrategy) {
        Channel channel = (Channel) this.connectionsPool.poll(connectionPoolKeyStrategy.getKey(uri));
        if (channel != null) {
            log.debug((String) "Using cached Channel {}\n for uri {}\n", (Object) channel, (Object) uri);
            try {
                return verifyChannelPipeline(channel, uri.getScheme());
            } catch (Exception ex) {
                log.debug(ex.getMessage(), (Throwable) ex);
            }
        }
        return null;
    }

    /* access modifiers changed from: private */
    public SSLEngine createSSLEngine() throws IOException, GeneralSecurityException {
        SSLEngine sslEngine = this.config.getSSLEngineFactory().newSSLEngine();
        if (sslEngine == null) {
            return SslUtils.getSSLEngine();
        }
        return sslEngine;
    }

    /* access modifiers changed from: private */
    public HttpClientCodec createHttpClientCodec() {
        return new HttpClientCodec(this.httpClientCodecMaxInitialLineLength, this.httpClientCodecMaxHeaderSize, this.httpClientCodecMaxChunkSize);
    }

    /* access modifiers changed from: private */
    public HttpClientCodec createHttpsClientCodec() {
        return new HttpClientCodec(this.httpsClientCodecMaxInitialLineLength, this.httpsClientCodecMaxHeaderSize, this.httpsClientCodecMaxChunkSize);
    }

    private Channel verifyChannelPipeline(Channel channel, String scheme) throws IOException, GeneralSecurityException {
        if (channel.getPipeline().get((String) SSL_HANDLER) != null && HTTP.equalsIgnoreCase(scheme)) {
            channel.getPipeline().remove((String) SSL_HANDLER);
        } else if ((channel.getPipeline().get((String) HTTP_HANDLER) == null || !HTTP.equalsIgnoreCase(scheme)) && channel.getPipeline().get((String) SSL_HANDLER) == null && isSecure(scheme)) {
            channel.getPipeline().addFirst(SSL_HANDLER, new SslHandler(createSSLEngine()));
        }
        return channel;
    }

    /* JADX WARNING: type inference failed for: r21v1 */
    /* JADX WARNING: type inference failed for: r11v0, types: [com.ning.http.client.Body] */
    /* JADX WARNING: type inference failed for: r1v3, types: [com.ning.http.client.Body] */
    /* JADX WARNING: type inference failed for: r0v24 */
    /* access modifiers changed from: protected */
    /* JADX WARNING: Multi-variable type inference failed */
    /* JADX WARNING: No exception handlers in catch block: Catch:{  } */
    /* JADX WARNING: Unknown variable types count: 3 */
    public final <T> void writeRequest(Channel channel, AsyncHttpClientConfig config2, NettyResponseFuture<T> future) {
        ChannelFuture writeFuture;
        RandomAccessFile raf;
        ChannelFuture writeFuture2;
        HttpRequest nettyRequest = future.getNettyRequest();
        boolean ssl = channel.getPipeline().get(SslHandler.class) != null;
        try {
            if (channel.isOpen() && channel.isConnected()) {
                MultipartBody multipartBody = 0;
                if (!nettyRequest.getMethod().equals(HttpMethod.CONNECT)) {
                    BodyGenerator bg = future.getRequest().getBodyGenerator();
                    if (bg != null) {
                        if (bg instanceof InputStreamBodyGenerator) {
                            InputStreamBodyGenerator.class.cast(bg).patchNettyChunkingIssue(true);
                        }
                        Body body = bg.createBody();
                        long length = body.getContentLength();
                        if (length >= 0) {
                            nettyRequest.setHeader((String) "Content-Length", (Object) Long.valueOf(length));
                            multipartBody = body;
                        } else {
                            nettyRequest.setHeader((String) Names.TRANSFER_ENCODING, (Object) Values.CHUNKED);
                            multipartBody = body;
                        }
                    } else if (future.getRequest().getParts() != null) {
                        String contentType = nettyRequest.getHeader("Content-Type");
                        String contentLength = nettyRequest.getHeader("Content-Length");
                        long length2 = -1;
                        if (contentLength != null) {
                            length2 = Long.parseLong(contentLength);
                        } else {
                            nettyRequest.addHeader(Names.TRANSFER_ENCODING, Values.CHUNKED);
                        }
                        MultipartBody multipartBody2 = new MultipartBody(future.getRequest().getParts(), contentType, length2);
                        multipartBody = multipartBody2;
                    }
                }
                if (future.getAsyncHandler() instanceof TransferCompletionHandler) {
                    FluentCaseInsensitiveStringsMap h = new FluentCaseInsensitiveStringsMap();
                    for (String s : nettyRequest.getHeaderNames()) {
                        for (String header : nettyRequest.getHeaders(s)) {
                            h.add(s, header);
                        }
                    }
                    TransferCompletionHandler.class.cast(future.getAsyncHandler()).transferAdapter(new NettyTransferAdapter(h, nettyRequest.getContent(), future.getRequest().getFile()));
                }
                if (future.getAndSetWriteHeaders(true)) {
                    try {
                        if (future.getAsyncHandler() instanceof AsyncHandlerExtensions) {
                            AsyncHandlerExtensions.class.cast(future.getAsyncHandler()).onRequestSent();
                        }
                        channel.write(nettyRequest).addListener(new ProgressListener(true, future.getAsyncHandler(), future));
                    } catch (Throwable cause) {
                        log.debug(cause.getMessage(), cause);
                        try {
                            channel.close();
                            return;
                        } catch (RuntimeException ex) {
                            log.debug(ex.getMessage(), (Throwable) ex);
                            return;
                        }
                    }
                }
                if (future.getAndSetWriteBody(true) && !nettyRequest.getMethod().equals(HttpMethod.CONNECT)) {
                    if (future.getRequest().getFile() != null) {
                        raf = new RandomAccessFile(future.getRequest().getFile(), "r");
                        if (this.disableZeroCopy || ssl) {
                            writeFuture2 = channel.write(new ChunkedFile(raf, 0, raf.length(), 8192));
                        } else {
                            writeFuture2 = channel.write(new OptimizedFileRegion(raf, 0, raf.length()));
                        }
                        final RandomAccessFile randomAccessFile = raf;
                        writeFuture2.addListener(new ProgressListener(false, future.getAsyncHandler(), future) {
                            public void operationComplete(ChannelFuture cf) {
                                try {
                                    randomAccessFile.close();
                                } catch (IOException e) {
                                    NettyAsyncHttpProvider.log.warn((String) "Failed to close request body: {}", (Object) e.getMessage(), (Object) e);
                                }
                                super.operationComplete(cf);
                            }
                        });
                    } else if (multipartBody != 0) {
                        final ? r11 = multipartBody;
                        if (this.disableZeroCopy || ssl || !(multipartBody instanceof RandomAccessBody)) {
                            BodyChunkedInput bodyChunkedInput = new BodyChunkedInput(multipartBody);
                            writeFuture = channel.write(bodyChunkedInput);
                        } else {
                            BodyFileRegion bodyFileRegion = new BodyFileRegion((RandomAccessBody) multipartBody);
                            writeFuture = channel.write(bodyFileRegion);
                        }
                        writeFuture.addListener(new ProgressListener(false, future.getAsyncHandler(), future) {
                            public void operationComplete(ChannelFuture cf) {
                                try {
                                    r11.close();
                                } catch (IOException e) {
                                    NettyAsyncHttpProvider.log.warn((String) "Failed to close request body: {}", (Object) e.getMessage(), (Object) e);
                                }
                                super.operationComplete(cf);
                            }
                        });
                    }
                }
                future.touch();
                int requestTimeoutInMs = AsyncHttpProviderUtils.requestTimeout(config2, future.getRequest());
                TimeoutsHolder timeoutsHolder = new TimeoutsHolder();
                if (requestTimeoutInMs != -1) {
                    timeoutsHolder.requestTimeout = newTimeoutInMs(new RequestTimeoutTimerTask(future, this, timeoutsHolder), (long) requestTimeoutInMs);
                }
                int idleConnectionTimeoutInMs = config2.getIdleConnectionTimeoutInMs();
                if (idleConnectionTimeoutInMs != -1 && idleConnectionTimeoutInMs <= requestTimeoutInMs) {
                    timeoutsHolder.idleConnectionTimeout = newTimeoutInMs(new IdleConnectionTimeoutTimerTask(future, this, timeoutsHolder, (long) requestTimeoutInMs, (long) idleConnectionTimeoutInMs), (long) idleConnectionTimeoutInMs);
                }
                future.setTimeoutsHolder(timeoutsHolder);
            }
        } catch (IOException ex2) {
            if (raf != null) {
                try {
                    raf.close();
                } catch (IOException e) {
                }
            }
            throw ex2;
        } catch (IOException ex3) {
            throw new IllegalStateException(ex3);
        } catch (RejectedExecutionException ex4) {
            abort(future, ex4);
        } catch (Throwable th) {
            try {
                channel.close();
            } catch (RuntimeException ex5) {
                log.debug(ex5.getMessage(), (Throwable) ex5);
            }
        }
    }

    protected static final HttpRequest buildRequest(AsyncHttpClientConfig config2, Request request, URI uri, boolean allowConnect, ChannelBuffer buffer, ProxyServer proxyServer) throws IOException {
        String method = request.getMethod();
        if (allowConnect && proxyServer != null && isSecure(uri)) {
            method = HttpMethod.CONNECT.toString();
        }
        return construct(config2, request, new HttpMethod(method), uri, buffer, proxyServer);
    }

    private static SpnegoEngine getSpnegoEngine() {
        if (spnegoEngine == null) {
            spnegoEngine = new SpnegoEngine();
        }
        return spnegoEngine;
    }

    private static HttpRequest construct(AsyncHttpClientConfig config2, Request request, HttpMethod m, URI uri, ChannelBuffer buffer, ProxyServer proxyServer) throws IOException {
        String host;
        String path;
        DefaultHttpRequest defaultHttpRequest;
        if (request.getVirtualHost() != null) {
            host = request.getVirtualHost();
        } else {
            host = AsyncHttpProviderUtils.getHost(uri);
        }
        if (m.equals(HttpMethod.CONNECT)) {
            defaultHttpRequest = new DefaultHttpRequest(HttpVersion.HTTP_1_0, m, AsyncHttpProviderUtils.getAuthority(uri));
        } else {
            if (proxyServer != null && (!isSecure(uri) || !config2.isUseRelativeURIsWithSSLProxies())) {
                path = uri.toString();
            } else if (uri.getRawQuery() != null) {
                path = uri.getRawPath() + "?" + uri.getRawQuery();
            } else {
                path = uri.getRawPath();
            }
            defaultHttpRequest = new DefaultHttpRequest(HttpVersion.HTTP_1_1, m, path);
        }
        boolean webSocket = isWebSocket(uri.getScheme());
        if (!m.equals(HttpMethod.CONNECT) && webSocket) {
            defaultHttpRequest.addHeader("Upgrade", Values.WEBSOCKET);
            defaultHttpRequest.addHeader("Connection", "Upgrade");
            defaultHttpRequest.addHeader(Names.ORIGIN, "http://" + uri.getHost() + ":" + uri.getPort());
            defaultHttpRequest.addHeader(Names.SEC_WEBSOCKET_KEY, WebSocketUtil.getKey());
            defaultHttpRequest.addHeader(Names.SEC_WEBSOCKET_VERSION, "13");
        }
        if (host == null) {
            host = "127.0.0.1";
        } else if (request.getVirtualHost() != null || uri.getPort() == -1) {
            defaultHttpRequest.setHeader((String) "Host", (Object) host);
        } else {
            defaultHttpRequest.setHeader((String) "Host", (Object) host + ":" + uri.getPort());
        }
        if (!m.equals(HttpMethod.CONNECT)) {
            Iterator<Entry<String, List<String>>> it = request.getHeaders().iterator();
            while (it.hasNext()) {
                Entry<String, List<String>> header = it.next();
                String name = header.getKey();
                if (!"Host".equalsIgnoreCase(name)) {
                    for (String value : header.getValue()) {
                        defaultHttpRequest.addHeader(name, value);
                    }
                }
            }
            if (config2.isCompressionEnabled()) {
                defaultHttpRequest.setHeader((String) "Accept-Encoding", (Object) GZIP_DEFLATE);
            }
        } else {
            List<String> auth = request.getHeaders().get((Object) "Proxy-Authorization");
            if (isNTLM(auth)) {
                defaultHttpRequest.addHeader("Proxy-Authorization", auth.get(0));
            }
        }
        Realm realm = request.getRealm() != null ? request.getRealm() : config2.getRealm();
        if (realm != null && realm.getUsePreemptiveAuth()) {
            String domain = realm.getNtlmDomain();
            if (!(proxyServer == null || proxyServer.getNtlmDomain() == null)) {
                domain = proxyServer.getNtlmDomain();
            }
            String authHost = realm.getNtlmHost();
            if (!(proxyServer == null || proxyServer.getHost() == null)) {
                host = proxyServer.getHost();
            }
            switch (realm.getAuthScheme()) {
                case BASIC:
                    defaultHttpRequest.addHeader("Authorization", AuthenticatorUtils.computeBasicAuthentication(realm));
                    break;
                case DIGEST:
                    if (MiscUtil.isNonEmpty(realm.getNonce())) {
                        try {
                            r1 = "Authorization";
                            defaultHttpRequest.addHeader("Authorization", AuthenticatorUtils.computeDigestAuthentication(realm));
                            break;
                        } catch (NoSuchAlgorithmException e) {
                            SecurityException securityException = new SecurityException(e);
                            throw securityException;
                        }
                    }
                    break;
                case NTLM:
                    try {
                        r1 = "Authorization";
                        defaultHttpRequest.addHeader("Authorization", ntlmEngine.generateType1Msg("NTLM " + domain, authHost));
                        break;
                    } catch (NTLMEngineException e2) {
                        IOException ie = new IOException();
                        ie.initCause(e2);
                        throw ie;
                    }
                case KERBEROS:
                case SPNEGO:
                    try {
                        defaultHttpRequest.addHeader("Authorization", "Negotiate " + getSpnegoEngine().generateToken(proxyServer == null ? host : proxyServer.getHost()));
                        break;
                    } catch (Throwable e3) {
                        IOException ie2 = new IOException();
                        ie2.initCause(e3);
                        throw ie2;
                    }
                case NONE:
                    break;
                default:
                    throw new IllegalStateException(String.format("Invalid Authentication %s", new Object[]{realm.toString()}));
            }
        }
        if (!webSocket && !request.getHeaders().containsKey("Connection")) {
            defaultHttpRequest.setHeader((String) "Connection", (Object) AsyncHttpProviderUtils.keepAliveHeaderValue(config2));
        }
        if (proxyServer != null) {
            if (!request.getHeaders().containsKey("Proxy-Connection")) {
                defaultHttpRequest.setHeader((String) "Proxy-Connection", (Object) AsyncHttpProviderUtils.keepAliveHeaderValue(config2));
            }
            if (proxyServer.getPrincipal() != null) {
                if (!MiscUtil.isNonEmpty(proxyServer.getNtlmDomain())) {
                    defaultHttpRequest.setHeader((String) "Proxy-Authorization", (Object) AuthenticatorUtils.computeBasicAuthentication(proxyServer));
                } else if (!isNTLM(request.getHeaders().get((Object) "Proxy-Authorization"))) {
                    try {
                        defaultHttpRequest.setHeader((String) "Proxy-Authorization", (Object) "NTLM " + ntlmEngine.generateType1Msg(proxyServer.getNtlmDomain(), proxyServer.getHost()));
                    } catch (NTLMEngineException e4) {
                        IOException ie3 = new IOException();
                        ie3.initCause(e4);
                        throw ie3;
                    }
                }
            }
        }
        if (!request.getHeaders().containsKey("Accept")) {
            defaultHttpRequest.setHeader((String) "Accept", (Object) "*/*");
        }
        String userAgentHeader = request.getHeaders().getFirstValue("User-Agent");
        if (userAgentHeader != null) {
            defaultHttpRequest.setHeader((String) "User-Agent", (Object) userAgentHeader);
        } else if (config2.getUserAgent() != null) {
            defaultHttpRequest.setHeader((String) "User-Agent", (Object) config2.getUserAgent());
        } else {
            defaultHttpRequest.setHeader((String) "User-Agent", (Object) AsyncHttpProviderUtils.constructUserAgent(NettyAsyncHttpProvider.class));
        }
        if (!m.equals(HttpMethod.CONNECT)) {
            if (MiscUtil.isNonEmpty(request.getCookies())) {
                defaultHttpRequest.setHeader((String) Names.COOKIE, (Object) CookieEncoder.encode(request.getCookies()));
            }
            String bodyCharset = request.getBodyEncoding() == null ? "ISO-8859-1" : request.getBodyEncoding();
            if (buffer != null && buffer.writerIndex() != 0) {
                defaultHttpRequest.setHeader((String) "Content-Length", (Object) Integer.valueOf(buffer.writerIndex()));
                defaultHttpRequest.setContent(buffer);
            } else if (request.getByteData() != null) {
                defaultHttpRequest.setHeader((String) "Content-Length", (Object) String.valueOf(request.getByteData().length));
                defaultHttpRequest.setContent(ChannelBuffers.wrappedBuffer(request.getByteData()));
            } else if (request.getStringData() != null) {
                byte[] bytes = request.getStringData().getBytes(bodyCharset);
                defaultHttpRequest.setHeader((String) "Content-Length", (Object) String.valueOf(bytes.length));
                defaultHttpRequest.setContent(ChannelBuffers.wrappedBuffer(bytes));
            } else if (request.getStreamData() != null) {
                int[] lengthWrapper = new int[1];
                byte[] bytes2 = AsyncHttpProviderUtils.readFully(request.getStreamData(), lengthWrapper);
                int length = lengthWrapper[0];
                defaultHttpRequest.setHeader((String) "Content-Length", (Object) String.valueOf(length));
                defaultHttpRequest.setContent(ChannelBuffers.wrappedBuffer(bytes2, 0, length));
            } else if (MiscUtil.isNonEmpty((Map<?, ?>) request.getParams())) {
                StringBuilder sb = new StringBuilder();
                Iterator<Entry<String, List<String>>> it2 = request.getParams().iterator();
                while (it2.hasNext()) {
                    Entry<String, List<String>> paramEntry = it2.next();
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
                defaultHttpRequest.setHeader((String) "Content-Length", (Object) String.valueOf(sb.length()));
                defaultHttpRequest.setContent(ChannelBuffers.wrappedBuffer(sb.toString().getBytes(bodyCharset)));
                if (!request.getHeaders().containsKey("Content-Type")) {
                    defaultHttpRequest.setHeader((String) "Content-Type", (Object) "application/x-www-form-urlencoded");
                }
            } else if (request.getParts() != null) {
                MultipartRequestEntity mre = AsyncHttpProviderUtils.createMultipartRequestEntity(request.getParts(), request.getHeaders());
                defaultHttpRequest.setHeader((String) "Content-Type", (Object) mre.getContentType());
                long contentLength = mre.getContentLength();
                if (contentLength >= 0) {
                    defaultHttpRequest.setHeader((String) "Content-Length", (Object) String.valueOf(contentLength));
                }
            } else if (request.getEntityWriter() != null) {
                int length2 = (int) request.getContentLength();
                if (length2 == -1) {
                    length2 = 8192;
                }
                ChannelBuffer b = ChannelBuffers.dynamicBuffer(length2);
                EntityWriter entityWriter = request.getEntityWriter();
                ChannelBufferOutputStream channelBufferOutputStream = new ChannelBufferOutputStream(b);
                entityWriter.writeEntity(channelBufferOutputStream);
                defaultHttpRequest.setHeader((String) "Content-Length", (Object) Integer.valueOf(b.writerIndex()));
                defaultHttpRequest.setContent(b);
            } else if (request.getFile() != null) {
                File file = request.getFile();
                if (!file.isFile()) {
                    throw new IOException(String.format("File %s is not a file or doesn't exist", new Object[]{file.getAbsolutePath()}));
                }
                defaultHttpRequest.setHeader((String) "Content-Length", (Object) Long.valueOf(file.length()));
            }
        }
        return defaultHttpRequest;
    }

    public void close() {
        if (this.isClose.compareAndSet(false, true)) {
            try {
                this.connectionsPool.destroy();
                this.openChannels.close();
                for (Channel channel : this.openChannels) {
                    ChannelHandlerContext ctx = channel.getPipeline().getContext(NettyAsyncHttpProvider.class);
                    if (ctx.getAttachment() instanceof NettyResponseFuture) {
                        ((NettyResponseFuture) ctx.getAttachment()).cancelTimeouts();
                    }
                }
                this.config.executorService().shutdown();
                if (this.allowReleaseSocketChannelFactory) {
                    this.socketChannelFactory.releaseExternalResources();
                    this.plainBootstrap.releaseExternalResources();
                    this.secureBootstrap.releaseExternalResources();
                    this.webSocketBootstrap.releaseExternalResources();
                    this.secureWebSocketBootstrap.releaseExternalResources();
                }
                if (this.allowStopHashedWheelTimer) {
                    this.hashedWheelTimer.stop();
                }
            } catch (Throwable t) {
                log.warn((String) "Unexpected error on close", t);
            }
        }
    }

    public Response prepareResponse(com.ning.http.client.HttpResponseStatus status, HttpResponseHeaders headers, List<HttpResponseBodyPart> bodyParts) {
        return new NettyResponse(status, headers, bodyParts);
    }

    public <T> ListenableFuture<T> execute(Request request, AsyncHandler<T> asyncHandler) throws IOException {
        return doConnect(request, asyncHandler, null, true, this.executeConnectAsync, false);
    }

    private <T> void execute(Request request, NettyResponseFuture<T> f, boolean useCache, boolean asyncConnect, boolean reclaimCache) throws IOException {
        doConnect(request, f.getAsyncHandler(), f, useCache, asyncConnect, reclaimCache);
    }

    private <T> NettyResponseFuture<T> buildNettyResponseFutureWithCachedChannel(Request request, AsyncHandler<T> asyncHandler, NettyResponseFuture<T> f, ProxyServer proxyServer, URI uri, ChannelBuffer bufferedBytes, int maxTry) throws IOException {
        URI connectionKeyUri;
        Channel channel;
        int i = 0;
        while (i < maxTry) {
            if (maxTry == 0) {
                return null;
            }
            if (f == null || !f.reuseChannel() || f.channel() == null) {
                if (proxyServer != null) {
                    connectionKeyUri = proxyServer.getURI();
                } else {
                    connectionKeyUri = uri;
                }
                channel = lookupInCache(connectionKeyUri, request.getConnectionPoolKeyStrategy());
            } else {
                channel = f.channel();
            }
            if (channel == null) {
                return null;
            }
            if (f == null) {
                f = newFuture(uri, request, asyncHandler, buildRequest(this.config, request, uri, false, bufferedBytes, proxyServer), this.config, this, proxyServer);
            } else if (i == 0) {
                NettyResponseFuture<T> nettyResponseFuture = f;
                nettyResponseFuture.setNettyRequest(buildRequest(this.config, request, uri, f.isConnectAllowed(), bufferedBytes, proxyServer));
            }
            f.setState(STATE.POOLED);
            f.attachChannel(channel, false);
            if (!channel.isOpen() || !channel.isConnected()) {
                f.attachChannel(null);
                i++;
            } else {
                f.channel().getPipeline().getContext(NettyAsyncHttpProvider.class).setAttachment(f);
                return f;
            }
        }
        return null;
    }

    private <T> ListenableFuture<T> doConnect(Request request, AsyncHandler<T> asyncHandler, NettyResponseFuture<T> f, boolean useCache, boolean asyncConnect, boolean reclaimCache) throws IOException {
        URI uri;
        InetSocketAddress remoteAddress;
        ChannelFuture channelFuture;
        IOException iOException;
        if (isClose()) {
            throw new IOException("Closed");
        } else if (!request.getUrl().startsWith(WEBSOCKET) || validateWebSocketRequest(request, asyncHandler)) {
            ProxyServer proxyServer = ProxyUtils.getProxyServer(this.config, request);
            boolean useProxy = proxyServer != null && !(f != null && f.getNettyRequest() != null && f.getNettyRequest().getMethod().equals(HttpMethod.CONNECT));
            if (this.useRawUrl) {
                uri = request.getRawURI();
            } else {
                uri = request.getURI();
            }
            ChannelBuffer bufferedBytes = null;
            if (f != null && f.getRequest().getFile() == null && !f.getNettyRequest().getMethod().getName().equals(HttpMethod.CONNECT.getName())) {
                bufferedBytes = f.getNettyRequest().getContent();
            }
            boolean useSSl = isSecure(uri) && !useProxy;
            if (useCache) {
                NettyResponseFuture<T> connectedFuture = buildNettyResponseFutureWithCachedChannel(request, asyncHandler, f, proxyServer, uri, bufferedBytes, 3);
                if (connectedFuture != null) {
                    log.debug((String) "\nUsing cached Channel {}\n for request \n{}\n", (Object) connectedFuture.channel(), (Object) connectedFuture.getNettyRequest());
                    try {
                        writeRequest(connectedFuture.channel(), this.config, connectedFuture);
                        return connectedFuture;
                    } catch (Exception ex) {
                        log.debug((String) "writeRequest failure", (Throwable) ex);
                        if (!useSSl || ex.getMessage() == null || !ex.getMessage().contains("SSLEngine")) {
                            asyncHandler.onThrowable(ex);
                        } else {
                            log.debug((String) "SSLEngine failure", (Throwable) ex);
                            return null;
                        }
                    } catch (Throwable t) {
                        log.warn((String) "doConnect.writeRequest()", t);
                    }
                }
            }
            if (reclaimCache || this.connectionsPool.canCacheConnection()) {
                boolean acquiredConnection = false;
                if (this.trackConnections && !reclaimCache) {
                    if (!this.freeConnections.tryAcquire()) {
                        IOException iOException2 = new IOException(String.format("Too many connections %s", new Object[]{Integer.valueOf(this.config.getMaxTotalConnections())}));
                        try {
                            asyncHandler.onThrowable(iOException2);
                        } catch (Throwable t2) {
                            log.warn((String) "!connectionsPool.canCacheConnection()", t2);
                        }
                        throw iOException2;
                    }
                    acquiredConnection = true;
                }
                NettyConnectListener<T> c = new Builder(this.config, request, asyncHandler, f, this, bufferedBytes).build(uri);
                if (useSSl) {
                    constructSSLPipeline(c);
                }
                ClientBootstrap bootstrap = (!request.getUrl().startsWith(WEBSOCKET) || useProxy) ? useSSl ? this.secureBootstrap : this.plainBootstrap : useSSl ? this.secureWebSocketBootstrap : this.webSocketBootstrap;
                bootstrap.setOption("connectTimeoutMillis", Integer.valueOf(this.config.getConnectionTimeoutInMs()));
                if (!System.getProperty("os.name").toLowerCase(Locale.ENGLISH).contains("win")) {
                    bootstrap.setOption(NettyAsyncHttpProviderConfig.REUSE_ADDRESS, this.providerConfig.getProperty((String) NettyAsyncHttpProviderConfig.REUSE_ADDRESS));
                }
                try {
                    if (request.getInetAddress() != null) {
                        remoteAddress = new InetSocketAddress(request.getInetAddress(), AsyncHttpProviderUtils.getPort(uri));
                    } else if (!useProxy) {
                        remoteAddress = new InetSocketAddress(AsyncHttpProviderUtils.getHost(uri), AsyncHttpProviderUtils.getPort(uri));
                    } else {
                        remoteAddress = new InetSocketAddress(proxyServer.getHost(), proxyServer.getPort());
                    }
                    if (request.getLocalAddress() != null) {
                        channelFuture = bootstrap.connect(remoteAddress, new InetSocketAddress(request.getLocalAddress(), 0));
                    } else {
                        channelFuture = bootstrap.connect(remoteAddress);
                    }
                    if (!(!IN_IO_THREAD.get().booleanValue() || !DefaultChannelFuture.isUseDeadLockChecker()) || asyncConnect || request.getFile() != null) {
                        channelFuture.addListener(c);
                    } else {
                        int timeOut = this.config.getConnectionTimeoutInMs() > 0 ? this.config.getConnectionTimeoutInMs() : ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
                        if (!channelFuture.awaitUninterruptibly((long) timeOut, TimeUnit.MILLISECONDS)) {
                            if (acquiredConnection) {
                                this.freeConnections.release();
                            }
                            channelFuture.cancel();
                            abort(c.future(), new ConnectException(String.format("Connect operation to %s timeout %s", new Object[]{uri, Integer.valueOf(timeOut)})));
                        }
                        try {
                            c.operationComplete(channelFuture);
                        } catch (Exception e) {
                            if (acquiredConnection) {
                                this.freeConnections.release();
                            }
                            iOException = new IOException(e.getMessage());
                            iOException.initCause(e);
                            asyncHandler.onThrowable(iOException);
                        } catch (Throwable t3) {
                            log.warn((String) "c.operationComplete()", t3);
                        }
                    }
                    log.debug((String) "\nNon cached request \n{}\n\nusing Channel \n{}\n", (Object) c.future().getNettyRequest(), (Object) channelFuture.getChannel());
                    if (!c.future().isCancelled() || !c.future().isDone()) {
                        this.openChannels.add(channelFuture.getChannel());
                        c.future().attachChannel(channelFuture.getChannel(), false);
                    }
                    return c.future();
                } catch (Throwable th) {
                    t = th;
                    if (acquiredConnection) {
                        this.freeConnections.release();
                    }
                    NettyResponseFuture future = c.future();
                    if (t.getCause() != null) {
                        t = t.getCause();
                    }
                    abort(future, t);
                    return c.future();
                }
            } else {
                IOException iOException3 = new IOException(String.format("Too many connections %s", new Object[]{Integer.valueOf(this.config.getMaxTotalConnections())}));
                try {
                    asyncHandler.onThrowable(iOException3);
                } catch (Throwable t4) {
                    log.warn((String) "!connectionsPool.canCacheConnection()", t4);
                }
                throw iOException3;
            }
        } else {
            throw new IOException("WebSocket method must be a GET");
        }
        throw iOException;
        IOException iOException4 = new IOException(ex.getMessage());
        iOException4.initCause(ex);
        throw iOException4;
    }

    protected static int requestTimeoutInMs(AsyncHttpClientConfig config2, PerRequestConfig perRequestConfig) {
        if (perRequestConfig == null) {
            return config2.getRequestTimeoutInMs();
        }
        int prRequestTimeout = perRequestConfig.getRequestTimeoutInMs();
        return prRequestTimeout != 0 ? prRequestTimeout : config2.getRequestTimeoutInMs();
    }

    private void closeChannel(ChannelHandlerContext ctx) {
        this.connectionsPool.removeAll(ctx.getChannel());
        finishChannel(ctx);
    }

    /* access modifiers changed from: private */
    public void finishChannel(ChannelHandlerContext ctx) {
        ctx.setAttachment(new DiscardEvent());
        if (ctx.getChannel() != null) {
            log.debug((String) "Closing Channel {} ", (Object) ctx.getChannel());
            try {
                ctx.getChannel().close();
            } catch (Throwable t) {
                log.debug((String) "Error closing a connection", t);
            }
            if (ctx.getChannel() != null) {
                this.openChannels.remove(ctx.getChannel());
            }
        }
    }

    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        super.messageReceived(ctx, e);
        IN_IO_THREAD.set(Boolean.TRUE);
        if (ctx.getAttachment() == null) {
            log.debug("ChannelHandlerContext wasn't having any attachment");
        }
        if (!(ctx.getAttachment() instanceof DiscardEvent)) {
            if (ctx.getAttachment() instanceof AsyncCallable) {
                if (!(e.getMessage() instanceof HttpChunk)) {
                    ((AsyncCallable) ctx.getAttachment()).call();
                } else if (((HttpChunk) e.getMessage()).isLast()) {
                    ((AsyncCallable) ctx.getAttachment()).call();
                } else {
                    return;
                }
                ctx.setAttachment(new DiscardEvent());
            } else if (!(ctx.getAttachment() instanceof NettyResponseFuture)) {
                try {
                    ctx.getChannel().close();
                } catch (Throwable th) {
                    log.trace((String) "Closing an orphan channel {}", (Object) ctx.getChannel());
                }
            } else {
                (ctx.getPipeline().get((String) HTTP_PROCESSOR) != null ? this.httpProtocol : this.webSocketProtocol).handle(ctx, e);
            }
        }
    }

    /* access modifiers changed from: private */
    public Realm kerberosChallenge(List<String> proxyAuth, Request request, ProxyServer proxyServer, FluentCaseInsensitiveStringsMap headers, Realm realm, NettyResponseFuture<?> future) throws NTLMEngineException {
        RealmBuilder realmBuilder;
        URI uri = request.getURI();
        try {
            String challengeHeader = getSpnegoEngine().generateToken(proxyServer == null ? request.getVirtualHost() == null ? AsyncHttpProviderUtils.getHost(uri) : request.getVirtualHost() : proxyServer.getHost());
            headers.remove((Object) "Authorization");
            headers.add((String) "Authorization", "Negotiate " + challengeHeader);
            if (realm != null) {
                realmBuilder = new RealmBuilder().clone(realm);
            } else {
                realmBuilder = new RealmBuilder();
            }
            return realmBuilder.setUri(uri.getRawPath()).setMethodName(request.getMethod()).setScheme(AuthScheme.KERBEROS).build();
        } catch (Throwable throwable) {
            if (isNTLM(proxyAuth)) {
                return ntlmChallenge(proxyAuth, request, proxyServer, headers, realm, future);
            }
            abort(future, throwable);
            return null;
        }
    }

    private void addNTLMAuthorization(FluentCaseInsensitiveStringsMap headers, String challengeHeader) {
        headers.add((String) "Authorization", "NTLM " + challengeHeader);
    }

    private void addType3NTLMAuthorizationHeader(List<String> auth, FluentCaseInsensitiveStringsMap headers, String username, String password, String domain, String workstation) throws NTLMEngineException {
        headers.remove((Object) "Authorization");
        if (MiscUtil.isNonEmpty((Collection<?>) auth) && auth.get(0).startsWith("NTLM ")) {
            addNTLMAuthorization(headers, ntlmEngine.generateType3Msg(username, password, domain, workstation, auth.get(0).trim().substring("NTLM ".length())));
        }
    }

    /* access modifiers changed from: private */
    public Realm ntlmChallenge(List<String> wwwAuth, Request request, ProxyServer proxyServer, FluentCaseInsensitiveStringsMap headers, Realm realm, NettyResponseFuture<?> future) throws NTLMEngineException {
        RealmBuilder realmBuilder;
        AuthScheme authScheme;
        boolean useRealm = proxyServer == null && realm != null;
        String ntlmDomain = useRealm ? realm.getNtlmDomain() : proxyServer.getNtlmDomain();
        String ntlmHost = useRealm ? realm.getNtlmHost() : proxyServer.getHost();
        String principal = useRealm ? realm.getPrincipal() : proxyServer.getPrincipal();
        String password = useRealm ? realm.getPassword() : proxyServer.getPassword();
        if (realm == null || realm.isNtlmMessageType2Received()) {
            addType3NTLMAuthorizationHeader(wwwAuth, headers, principal, password, ntlmDomain, ntlmHost);
            if (realm != null) {
                realmBuilder = new RealmBuilder().clone(realm);
                authScheme = realm.getAuthScheme();
            } else {
                realmBuilder = new RealmBuilder();
                authScheme = AuthScheme.NTLM;
            }
            return realmBuilder.setScheme(authScheme).setUri(request.getURI().getPath()).setMethodName(request.getMethod()).build();
        }
        String challengeHeader = ntlmEngine.generateType1Msg(ntlmDomain, ntlmHost);
        URI uri = request.getURI();
        addNTLMAuthorization(headers, challengeHeader);
        Realm newRealm = new RealmBuilder().clone(realm).setScheme(realm.getAuthScheme()).setUri(uri.getRawPath()).setMethodName(request.getMethod()).setNtlmMessageType2Received(true).build();
        future.getAndSetAuth(false);
        return newRealm;
    }

    /* access modifiers changed from: private */
    public Realm ntlmProxyChallenge(List<String> wwwAuth, Request request, ProxyServer proxyServer, FluentCaseInsensitiveStringsMap headers, Realm realm, NettyResponseFuture<?> future) throws NTLMEngineException {
        future.getAndSetAuth(false);
        addType3NTLMAuthorizationHeader(wwwAuth, headers, proxyServer.getPrincipal(), proxyServer.getPassword(), proxyServer.getNtlmDomain(), proxyServer.getHost());
        RealmBuilder realmBuilder = new RealmBuilder();
        if (realm != null) {
            realmBuilder = realmBuilder.clone(realm);
        }
        return realmBuilder.setUri(request.getURI().getPath()).setMethodName(request.getMethod()).build();
    }

    /* access modifiers changed from: private */
    public String getPoolKey(NettyResponseFuture<?> future) {
        String serverPart = future.getConnectionPoolKeyStrategy().getKey(future.getURI());
        ProxyServer proxy = future.getProxyServer();
        return proxy != null ? AsyncHttpProviderUtils.getBaseUrl(proxy.getURI()) + serverPart : serverPart;
    }

    /* access modifiers changed from: private */
    public void drainChannel(final ChannelHandlerContext ctx, final NettyResponseFuture<?> future) {
        ctx.setAttachment(new AsyncCallable(future) {
            public Object call() throws Exception {
                if (!future.getKeepAlive() || !ctx.getChannel().isReadable() || !NettyAsyncHttpProvider.this.connectionsPool.offer(NettyAsyncHttpProvider.this.getPoolKey(future), ctx.getChannel())) {
                    NettyAsyncHttpProvider.this.finishChannel(ctx);
                }
                return null;
            }

            public String toString() {
                return String.format("Draining task for channel %s", new Object[]{ctx.getChannel()});
            }
        });
    }

    /* access modifiers changed from: private */
    public FilterContext handleIoException(FilterContext fc, NettyResponseFuture<?> future) {
        for (IOExceptionFilter asyncFilter : this.config.getIOExceptionFilters()) {
            try {
                fc = asyncFilter.filter(fc);
                if (fc == null) {
                    throw new NullPointerException("FilterContext is null");
                }
            } catch (FilterException efe) {
                abort(future, efe);
            }
        }
        return fc;
    }

    /* access modifiers changed from: private */
    public void replayRequest(NettyResponseFuture<?> future, FilterContext fc, HttpResponse response, ChannelHandlerContext ctx) throws IOException {
        if (future.getAsyncHandler() instanceof AsyncHandlerExtensions) {
            AsyncHandlerExtensions.class.cast(future.getAsyncHandler()).onRetry();
        }
        Request newRequest = fc.getRequest();
        future.setAsyncHandler(fc.getAsyncHandler());
        future.setState(STATE.NEW);
        future.touch();
        log.debug((String) "\n\nReplaying Request {}\n for Future {}\n", (Object) newRequest, (Object) future);
        drainChannel(ctx, future);
        nextRequest(newRequest, future);
    }

    /* access modifiers changed from: private */
    public List<String> getAuthorizationToken(List<Entry<String, String>> list, String headerAuth) {
        ArrayList<String> l = new ArrayList<>();
        for (Entry<String, String> e : list) {
            if (e.getKey().equalsIgnoreCase(headerAuth)) {
                l.add(e.getValue().trim());
            }
        }
        return l;
    }

    /* access modifiers changed from: private */
    public void nextRequest(Request request, NettyResponseFuture<?> future) throws IOException {
        nextRequest(request, future, true);
    }

    private void nextRequest(Request request, NettyResponseFuture<?> future, boolean useCache) throws IOException {
        execute(request, future, useCache, true, true);
    }

    public void abort(NettyResponseFuture<?> future, Throwable t) {
        Channel channel = future.channel();
        if (channel != null && this.openChannels.contains(channel)) {
            closeChannel(channel.getPipeline().getContext(NettyAsyncHttpProvider.class));
            this.openChannels.remove(channel);
        }
        if (!future.isCancelled() && !future.isDone()) {
            log.debug((String) "Aborting Future {}\n", (Object) future);
            log.debug(t.getMessage(), t);
        }
        future.abort(t);
    }

    /* access modifiers changed from: private */
    public void upgradeProtocol(ChannelPipeline p, String scheme) throws IOException, GeneralSecurityException {
        if (p.get((String) HTTP_HANDLER) != null) {
            p.remove((String) HTTP_HANDLER);
        }
        if (!isSecure(scheme)) {
            p.addFirst(HTTP_HANDLER, createHttpClientCodec());
        } else if (p.get((String) SSL_HANDLER) == null) {
            p.addFirst(HTTP_HANDLER, createHttpClientCodec());
            p.addFirst(SSL_HANDLER, new SslHandler(createSSLEngine()));
        } else {
            p.addAfter(SSL_HANDLER, HTTP_HANDLER, createHttpClientCodec());
        }
        if (isWebSocket(scheme)) {
            p.replace((String) HTTP_PROCESSOR, (String) WS_PROCESSOR, (ChannelHandler) this);
        }
    }

    public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        if (!isClose()) {
            this.connectionsPool.removeAll(ctx.getChannel());
            try {
                super.channelClosed(ctx, e);
            } catch (Exception ex) {
                log.trace((String) "super.channelClosed", (Throwable) ex);
            }
            log.debug((String) "Channel Closed: {} with attachment {}", (Object) e.getChannel(), ctx.getAttachment());
            if (ctx.getAttachment() instanceof AsyncCallable) {
                AsyncCallable ac = (AsyncCallable) ctx.getAttachment();
                ctx.setAttachment(ac.future());
                ac.call();
            } else if (ctx.getAttachment() instanceof NettyResponseFuture) {
                NettyResponseFuture<?> future = (NettyResponseFuture) ctx.getAttachment();
                future.touch();
                if (!this.config.getIOExceptionFilters().isEmpty()) {
                    FilterContext<?> fc = handleIoException(new FilterContextBuilder().asyncHandler(future.getAsyncHandler()).request(future.getRequest()).ioException(new IOException("Channel Closed")).build(), future);
                    if (fc.replayRequest() && !future.cannotBeReplay()) {
                        replayRequest(future, fc, null, ctx);
                        return;
                    }
                }
                (ctx.getPipeline().get(HttpClientCodec.class) != null ? this.httpProtocol : this.webSocketProtocol).onClose(ctx, e);
                if (future == null || future.isDone() || future.isCancelled()) {
                    closeChannel(ctx);
                } else if (remotelyClosed(ctx.getChannel(), future)) {
                    abort(future, REMOTELY_CLOSED_EXCEPTION);
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public boolean remotelyClosed(Channel channel, NettyResponseFuture<?> future) {
        if (isClose()) {
            return true;
        }
        this.connectionsPool.removeAll(channel);
        if (future == null) {
            Object attachment = channel.getPipeline().getContext(NettyAsyncHttpProvider.class).getAttachment();
            if (attachment instanceof NettyResponseFuture) {
                future = (NettyResponseFuture) attachment;
            }
        }
        if (future == null || future.cannotBeReplay()) {
            log.debug((String) "Unable to recover future {}\n", (Object) future);
            return true;
        }
        future.setState(STATE.RECONNECTED);
        log.debug((String) "Trying to recover request {}\n", (Object) future.getNettyRequest());
        if (future.getAsyncHandler() instanceof AsyncHandlerExtensions) {
            AsyncHandlerExtensions.class.cast(future.getAsyncHandler()).onRetry();
        }
        try {
            nextRequest(future.getRequest(), future);
            return false;
        } catch (IOException iox) {
            future.setState(STATE.CLOSED);
            future.abort(iox);
            log.error((String) "Remotely Closed, unable to recover", (Throwable) iox);
            return true;
        }
    }

    /* access modifiers changed from: private */
    public void markAsDone(NettyResponseFuture<?> future, ChannelHandlerContext ctx) throws MalformedURLException {
        try {
            future.done();
        } catch (Throwable t) {
            log.debug(t.getMessage(), t);
        }
        if (!future.getKeepAlive() || !ctx.getChannel().isReadable()) {
            closeChannel(ctx);
        }
    }

    /* access modifiers changed from: private */
    public void finishUpdate(NettyResponseFuture<?> future, ChannelHandlerContext ctx, boolean lastValidChunk) throws IOException {
        if (lastValidChunk && future.getKeepAlive()) {
            drainChannel(ctx, future);
        } else if (!future.getKeepAlive() || !ctx.getChannel().isReadable() || !this.connectionsPool.offer(getPoolKey(future), ctx.getChannel())) {
            finishChannel(ctx);
        } else {
            markAsDone(future, ctx);
            return;
        }
        markAsDone(future, ctx);
    }

    /* access modifiers changed from: private */
    public final boolean updateStatusAndInterrupt(AsyncHandler handler, com.ning.http.client.HttpResponseStatus c) throws Exception {
        return handler.onStatusReceived(c) != STATE.CONTINUE;
    }

    /* access modifiers changed from: private */
    public final boolean updateHeadersAndInterrupt(AsyncHandler handler, HttpResponseHeaders c) throws Exception {
        return handler.onHeadersReceived(c) != STATE.CONTINUE;
    }

    /* access modifiers changed from: private */
    public final boolean updateBodyAndInterrupt(NettyResponseFuture<?> future, AsyncHandler handler, HttpResponseBodyPart c) throws Exception {
        boolean state;
        if (handler.onBodyPartReceived(c) != STATE.CONTINUE) {
            state = true;
        } else {
            state = false;
        }
        if (c.closeUnderlyingConnection()) {
            future.setKeepAlive(false);
        }
        return state;
    }

    public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
        Channel channel = e.getChannel();
        Throwable cause = e.getCause();
        NettyResponseFuture<?> future = null;
        if (!(e.getCause() instanceof PrematureChannelClosureException)) {
            if (log.isDebugEnabled()) {
                log.debug((String) "Unexpected I/O exception on channel {}", (Object) channel, (Object) cause);
            }
            try {
                if (!(cause instanceof ClosedChannelException)) {
                    if (ctx.getAttachment() instanceof NettyResponseFuture) {
                        future = (NettyResponseFuture) ctx.getAttachment();
                        future.attachChannel(null, false);
                        future.touch();
                        if (cause instanceof IOException) {
                            if (!this.config.getIOExceptionFilters().isEmpty()) {
                                FilterContext<?> fc = handleIoException(new FilterContextBuilder().asyncHandler(future.getAsyncHandler()).request(future.getRequest()).ioException(new IOException("Channel Closed")).build(), future);
                                if (fc.replayRequest()) {
                                    replayRequest(future, fc, null, ctx);
                                    return;
                                }
                            } else {
                                try {
                                    ctx.getChannel().close();
                                    return;
                                } catch (Throwable th) {
                                    return;
                                }
                            }
                        }
                        if (abortOnReadCloseException(cause) || abortOnWriteCloseException(cause)) {
                            log.debug((String) "Trying to recover from dead Channel: {}", (Object) channel);
                            return;
                        }
                    } else if (ctx.getAttachment() instanceof AsyncCallable) {
                        future = ((AsyncCallable) ctx.getAttachment()).future();
                    }
                    if (future != null) {
                        try {
                            log.debug((String) "Was unable to recover Future: {}", (Object) future);
                            abort(future, cause);
                        } catch (Throwable t) {
                            log.error(t.getMessage(), t);
                        }
                    }
                    (ctx.getPipeline().get(HttpClientCodec.class) != null ? this.httpProtocol : this.webSocketProtocol).onError(ctx, e);
                    closeChannel(ctx);
                    ctx.sendUpstream(e);
                }
            } catch (Throwable t2) {
                cause = t2;
            }
        }
    }

    protected static boolean abortOnConnectCloseException(Throwable cause) {
        StackTraceElement[] arr$;
        try {
            for (StackTraceElement element : cause.getStackTrace()) {
                if (element.getClassName().equals("sun.nio.ch.SocketChannelImpl") && element.getMethodName().equals("checkConnect")) {
                    return true;
                }
            }
            if (cause.getCause() != null) {
                return abortOnConnectCloseException(cause.getCause());
            }
        } catch (Throwable th) {
        }
        return false;
    }

    protected static boolean abortOnDisconnectException(Throwable cause) {
        StackTraceElement[] arr$;
        try {
            for (StackTraceElement element : cause.getStackTrace()) {
                if (element.getClassName().equals("org.jboss.netty.handler.ssl.SslHandler") && element.getMethodName().equals("channelDisconnected")) {
                    return true;
                }
            }
            if (cause.getCause() != null) {
                return abortOnConnectCloseException(cause.getCause());
            }
        } catch (Throwable th) {
        }
        return false;
    }

    protected static boolean abortOnReadCloseException(Throwable cause) {
        StackTraceElement[] arr$;
        for (StackTraceElement element : cause.getStackTrace()) {
            if (element.getClassName().equals("sun.nio.ch.SocketDispatcher") && element.getMethodName().equals("read")) {
                return true;
            }
        }
        if (cause.getCause() != null) {
            return abortOnReadCloseException(cause.getCause());
        }
        return false;
    }

    protected static boolean abortOnWriteCloseException(Throwable cause) {
        StackTraceElement[] arr$;
        for (StackTraceElement element : cause.getStackTrace()) {
            if (element.getClassName().equals("sun.nio.ch.SocketDispatcher") && element.getMethodName().equals("write")) {
                return true;
            }
        }
        if (cause.getCause() != null) {
            return abortOnWriteCloseException(cause.getCause());
        }
        return false;
    }

    public static <T> NettyResponseFuture<T> newFuture(URI uri, Request request, AsyncHandler<T> asyncHandler, HttpRequest nettyRequest, AsyncHttpClientConfig config2, NettyAsyncHttpProvider provider, ProxyServer proxyServer) {
        NettyResponseFuture<T> f = new NettyResponseFuture<>(uri, request, asyncHandler, nettyRequest, requestTimeoutInMs(config2, request.getPerRequestConfig()), config2.getIdleConnectionTimeoutInMs(), provider, request.getConnectionPoolKeyStrategy(), proxyServer);
        String expectHeader = request.getHeaders().getFirstValue(Names.EXPECT);
        if (expectHeader != null && expectHeader.equalsIgnoreCase("100-continue")) {
            f.getAndSetWriteBody(false);
        }
        return f;
    }

    /* access modifiers changed from: protected */
    public AsyncHttpClientConfig getConfig() {
        return this.config;
    }

    private static final boolean validateWebSocketRequest(Request request, AsyncHandler<?> asyncHandler) {
        if (request.getMethod() != io.fabric.sdk.android.services.network.HttpRequest.METHOD_GET || !(asyncHandler instanceof WebSocketUpgradeHandler)) {
            return false;
        }
        return true;
    }

    /* access modifiers changed from: private */
    public boolean redirect(Request request, NettyResponseFuture<?> future, HttpResponse response, ChannelHandlerContext ctx) throws Exception {
        boolean redirectEnabled;
        RequestBuilder nBuilder;
        int statusCode = response.getStatus().getCode();
        if (request.isRedirectOverrideSet()) {
            redirectEnabled = request.isRedirectEnabled();
        } else {
            redirectEnabled = this.config.isRedirectEnabled();
        }
        if (redirectEnabled && (statusCode == 302 || statusCode == 301 || statusCode == 303 || statusCode == 307)) {
            if (future.incrementAndGetCurrentRedirectCount() < this.config.getMaxRedirects()) {
                future.getAndSetAuth(false);
                URI uri = AsyncHttpProviderUtils.getRedirectUri(future.getURI(), response.getHeader("Location"));
                boolean stripQueryString = this.config.isRemoveQueryParamOnRedirect();
                if (!uri.toString().equals(future.getURI().toString())) {
                    if (stripQueryString) {
                        nBuilder = new RequestBuilder(future.getRequest()).setQueryParameters((FluentStringsMap) null);
                    } else {
                        nBuilder = new RequestBuilder(future.getRequest());
                    }
                    if (statusCode >= 302 && statusCode <= 303 && (statusCode != 302 || !this.config.isStrict302Handling())) {
                        nBuilder.setMethod((String) io.fabric.sdk.android.services.network.HttpRequest.METHOD_GET);
                    }
                    final boolean initialConnectionKeepAlive = future.getKeepAlive();
                    final String initialPoolKey = getPoolKey(future);
                    future.setURI(uri);
                    String newUrl = uri.toString();
                    if (request.getUrl().startsWith(WEBSOCKET)) {
                        newUrl = newUrl.replace(HTTP, WEBSOCKET);
                    }
                    log.debug((String) "Redirecting to {}", (Object) newUrl);
                    List<String> setCookieHeaders = future.getHttpResponse().getHeaders(Names.SET_COOKIE2);
                    if (!MiscUtil.isNonEmpty((Collection<?>) setCookieHeaders)) {
                        setCookieHeaders = future.getHttpResponse().getHeaders(Names.SET_COOKIE);
                    }
                    for (String cookieStr : setCookieHeaders) {
                        nBuilder.addOrReplaceCookie(CookieDecoder.decode(cookieStr));
                    }
                    final ChannelHandlerContext channelHandlerContext = ctx;
                    AsyncCallable ac = new AsyncCallable(future) {
                        public Object call() throws Exception {
                            if (!initialConnectionKeepAlive || !channelHandlerContext.getChannel().isReadable() || !NettyAsyncHttpProvider.this.connectionsPool.offer(initialPoolKey, channelHandlerContext.getChannel())) {
                                NettyAsyncHttpProvider.this.finishChannel(channelHandlerContext);
                            }
                            return null;
                        }
                    };
                    if (response.isChunked()) {
                        ctx.setAttachment(ac);
                    } else {
                        ac.call();
                    }
                    nextRequest(nBuilder.setUrl(newUrl).build(), future);
                    return true;
                }
            } else {
                throw new MaxRedirectException("Maximum redirect reached: " + this.config.getMaxRedirects());
            }
        }
        return false;
    }

    public boolean isClose() {
        return this.isClose.get();
    }

    public Timeout newTimeoutInMs(TimerTask task, long delayInMs) {
        return this.hashedWheelTimer.newTimeout(task, delayInMs, TimeUnit.MILLISECONDS);
    }

    private static boolean isWebSocket(String scheme) {
        return WEBSOCKET.equalsIgnoreCase(scheme) || WEBSOCKET_SSL.equalsIgnoreCase(scheme);
    }

    private static boolean isSecure(String scheme) {
        return "https".equalsIgnoreCase(scheme) || WEBSOCKET_SSL.equalsIgnoreCase(scheme);
    }

    private static boolean isSecure(URI uri) {
        return isSecure(uri.getScheme());
    }
}