package com.ning.http.client.providers.netty;

import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.ProxyServer;
import com.ning.http.client.Request;
import com.ning.http.util.AllowAllHostnameVerifier;
import com.ning.http.util.ProxyUtils;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.channels.ClosedChannelException;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.HostnameVerifier;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.ssl.SslHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class NettyConnectListener<T> implements ChannelFutureListener {
    private static final Logger logger = LoggerFactory.getLogger(NettyConnectListener.class);
    private final AsyncHttpClientConfig config;
    private final NettyResponseFuture<T> future;
    private final AtomicBoolean handshakeDone;
    private final HttpRequest nettyRequest;

    public static class Builder<T> {
        private final AsyncHandler<T> asyncHandler;
        private final ChannelBuffer buffer;
        private final AsyncHttpClientConfig config;
        private NettyResponseFuture<T> future;
        private final NettyAsyncHttpProvider provider;
        private final Request request;

        public Builder(AsyncHttpClientConfig config2, Request request2, AsyncHandler<T> asyncHandler2, NettyAsyncHttpProvider provider2, ChannelBuffer buffer2) {
            this.config = config2;
            this.request = request2;
            this.asyncHandler = asyncHandler2;
            this.future = null;
            this.provider = provider2;
            this.buffer = buffer2;
        }

        public Builder(AsyncHttpClientConfig config2, Request request2, AsyncHandler<T> asyncHandler2, NettyResponseFuture<T> future2, NettyAsyncHttpProvider provider2, ChannelBuffer buffer2) {
            this.config = config2;
            this.request = request2;
            this.asyncHandler = asyncHandler2;
            this.future = future2;
            this.provider = provider2;
            this.buffer = buffer2;
        }

        public NettyConnectListener<T> build(URI uri) throws IOException {
            ProxyServer proxyServer = ProxyUtils.getProxyServer(this.config, this.request);
            HttpRequest nettyRequest = NettyAsyncHttpProvider.buildRequest(this.config, this.request, uri, true, this.buffer, proxyServer);
            if (this.future == null) {
                this.future = NettyAsyncHttpProvider.newFuture(uri, this.request, this.asyncHandler, nettyRequest, this.config, this.provider, proxyServer);
            } else {
                this.future.setNettyRequest(nettyRequest);
                this.future.setRequest(this.request);
            }
            return new NettyConnectListener<>(this.config, this.future);
        }
    }

    private NettyConnectListener(AsyncHttpClientConfig config2, NettyResponseFuture<T> future2) {
        this.handshakeDone = new AtomicBoolean(false);
        this.config = config2;
        this.future = future2;
        this.nettyRequest = future2.getNettyRequest();
    }

    public NettyResponseFuture<T> future() {
        return this.future;
    }

    public final void operationComplete(ChannelFuture f) throws Exception {
        boolean printCause = true;
        if (f.isSuccess()) {
            Channel channel = f.getChannel();
            channel.getPipeline().getContext(NettyAsyncHttpProvider.class).setAttachment(this.future);
            SslHandler sslHandler = (SslHandler) channel.getPipeline().get((String) NettyAsyncHttpProvider.SSL_HANDLER);
            if (this.handshakeDone.getAndSet(true) || sslHandler == null) {
                HostnameVerifier v = this.config.getHostnameVerifier();
                if (sslHandler == null || (v instanceof AllowAllHostnameVerifier) || v.verify(InetSocketAddress.class.cast(channel.getRemoteAddress()).getHostName(), sslHandler.getEngine().getSession())) {
                    this.future.provider().writeRequest(f.getChannel(), this.config, this.future);
                    return;
                }
                throw new ConnectException("HostnameVerifier exception.");
            }
            ((SslHandler) channel.getPipeline().get((String) NettyAsyncHttpProvider.SSL_HANDLER)).handshake().addListener(this);
            return;
        }
        Throwable cause = f.getCause();
        boolean canRetry = this.future.canRetry();
        logger.debug((String) "Trying to recover a dead cached channel {} with a retry value of {} ", (Object) f.getChannel(), (Object) Boolean.valueOf(canRetry));
        if (canRetry && cause != null && (NettyAsyncHttpProvider.abortOnDisconnectException(cause) || (cause instanceof ClosedChannelException) || this.future.getState() != STATE.NEW)) {
            logger.debug((String) "Retrying {} ", (Object) this.nettyRequest);
            if (this.future.provider().remotelyClosed(f.getChannel(), this.future)) {
                return;
            }
        }
        logger.debug((String) "Failed to recover from exception: {} with channel {}", (Object) cause, (Object) f.getChannel());
        if (f.getCause() == null || cause.getMessage() == null) {
            printCause = false;
        }
        ConnectException e = new ConnectException(printCause ? cause.getMessage() + " to " + this.future.getURI().toString() : this.future.getURI().toString());
        if (cause != null) {
            e.initCause(cause);
        }
        this.future.abort(e);
    }
}