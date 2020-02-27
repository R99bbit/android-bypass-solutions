package org.jboss.netty.channel.socket.http;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.NotYetConnectedException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.AbstractChannel;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelSink;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.DefaultChannelPipeline;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.channel.socket.ClientSocketChannelFactory;
import org.jboss.netty.channel.socket.SocketChannel;
import org.jboss.netty.handler.codec.http.DefaultHttpChunk;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpRequestEncoder;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseDecoder;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.handler.ssl.SslHandler;

class HttpTunnelingClientSocketChannel extends AbstractChannel implements SocketChannel {
    final HttpTunnelingSocketChannelConfig config = new HttpTunnelingSocketChannelConfig(this);
    private final ServletChannelHandler handler = new ServletChannelHandler();
    final Object interestOpsLock = new Object();
    final SocketChannel realChannel;
    volatile boolean requestHeaderWritten;

    final class ServletChannelHandler extends SimpleChannelUpstreamHandler {
        private volatile boolean readingChunks;
        final SocketChannel virtualChannel = HttpTunnelingClientSocketChannel.this;

        ServletChannelHandler() {
        }

        public void channelBound(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
            Channels.fireChannelBound((Channel) this.virtualChannel, (SocketAddress) e.getValue());
        }

        public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
            if (!this.readingChunks) {
                HttpResponse res = (HttpResponse) e.getMessage();
                if (res.getStatus().getCode() != HttpResponseStatus.OK.getCode()) {
                    throw new ChannelException("Unexpected HTTP response status: " + res.getStatus());
                } else if (res.isChunked()) {
                    this.readingChunks = true;
                } else {
                    ChannelBuffer content = res.getContent();
                    if (content.readable()) {
                        Channels.fireMessageReceived((Channel) HttpTunnelingClientSocketChannel.this, (Object) content);
                    }
                    HttpTunnelingClientSocketChannel.this.closeReal(Channels.succeededFuture(this.virtualChannel));
                }
            } else {
                HttpChunk chunk = (HttpChunk) e.getMessage();
                if (!chunk.isLast()) {
                    Channels.fireMessageReceived((Channel) HttpTunnelingClientSocketChannel.this, (Object) chunk.getContent());
                    return;
                }
                this.readingChunks = false;
                HttpTunnelingClientSocketChannel.this.closeReal(Channels.succeededFuture(this.virtualChannel));
            }
        }

        public void channelInterestChanged(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
            Channels.fireChannelInterestChanged((Channel) this.virtualChannel);
        }

        public void channelDisconnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
            Channels.fireChannelDisconnected((Channel) this.virtualChannel);
        }

        public void channelUnbound(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
            Channels.fireChannelUnbound((Channel) this.virtualChannel);
        }

        public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
            Channels.fireChannelClosed((Channel) this.virtualChannel);
        }

        public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
            Channels.fireExceptionCaught((Channel) this.virtualChannel, e.getCause());
            HttpTunnelingClientSocketChannel.this.realChannel.close();
        }
    }

    HttpTunnelingClientSocketChannel(ChannelFactory factory, ChannelPipeline pipeline, ChannelSink sink, ClientSocketChannelFactory clientSocketChannelFactory) {
        super(null, factory, pipeline, sink);
        DefaultChannelPipeline channelPipeline = new DefaultChannelPipeline();
        channelPipeline.addLast("decoder", new HttpResponseDecoder());
        channelPipeline.addLast("encoder", new HttpRequestEncoder());
        channelPipeline.addLast("handler", this.handler);
        this.realChannel = clientSocketChannelFactory.newChannel(channelPipeline);
        Channels.fireChannelOpen((Channel) this);
    }

    public HttpTunnelingSocketChannelConfig getConfig() {
        return this.config;
    }

    public InetSocketAddress getLocalAddress() {
        return this.realChannel.getLocalAddress();
    }

    public InetSocketAddress getRemoteAddress() {
        return this.realChannel.getRemoteAddress();
    }

    public boolean isBound() {
        return this.realChannel.isBound();
    }

    public boolean isConnected() {
        return this.realChannel.isConnected();
    }

    public int getInterestOps() {
        return this.realChannel.getInterestOps();
    }

    public boolean isWritable() {
        return this.realChannel.isWritable();
    }

    /* access modifiers changed from: protected */
    public boolean setClosed() {
        return super.setClosed();
    }

    public ChannelFuture write(Object message, SocketAddress remoteAddress) {
        if (remoteAddress == null || remoteAddress.equals(getRemoteAddress())) {
            return super.write(message, null);
        }
        return getUnsupportedOperationFuture();
    }

    /* access modifiers changed from: 0000 */
    public void bindReal(SocketAddress localAddress, final ChannelFuture future) {
        this.realChannel.bind(localAddress).addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture f) {
                if (f.isSuccess()) {
                    future.setSuccess();
                } else {
                    future.setFailure(f.getCause());
                }
            }
        });
    }

    /* access modifiers changed from: 0000 */
    public void connectReal(final SocketAddress remoteAddress, final ChannelFuture future) {
        this.realChannel.connect(remoteAddress).addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture f) {
                SSLEngine engine;
                String serverName = HttpTunnelingClientSocketChannel.this.config.getServerName();
                int serverPort = ((InetSocketAddress) remoteAddress).getPort();
                String serverPath = HttpTunnelingClientSocketChannel.this.config.getServerPath();
                if (f.isSuccess()) {
                    SSLContext sslContext = HttpTunnelingClientSocketChannel.this.config.getSslContext();
                    ChannelFuture sslHandshakeFuture = null;
                    if (sslContext != null) {
                        if (serverName != null) {
                            engine = sslContext.createSSLEngine(serverName, serverPort);
                        } else {
                            engine = sslContext.createSSLEngine();
                        }
                        engine.setUseClientMode(true);
                        engine.setEnableSessionCreation(HttpTunnelingClientSocketChannel.this.config.isEnableSslSessionCreation());
                        String[] enabledCipherSuites = HttpTunnelingClientSocketChannel.this.config.getEnabledSslCipherSuites();
                        if (enabledCipherSuites != null) {
                            engine.setEnabledCipherSuites(enabledCipherSuites);
                        }
                        String[] enabledProtocols = HttpTunnelingClientSocketChannel.this.config.getEnabledSslProtocols();
                        if (enabledProtocols != null) {
                            engine.setEnabledProtocols(enabledProtocols);
                        }
                        SslHandler sslHandler = new SslHandler(engine);
                        HttpTunnelingClientSocketChannel.this.realChannel.getPipeline().addFirst("ssl", sslHandler);
                        sslHandshakeFuture = sslHandler.handshake();
                    }
                    final HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, serverPath);
                    if (serverName != null) {
                        req.headers().set((String) "Host", (Object) serverName);
                    }
                    req.headers().set((String) "Content-Type", (Object) "application/octet-stream");
                    req.headers().set((String) Names.TRANSFER_ENCODING, (Object) Values.CHUNKED);
                    req.headers().set((String) Names.CONTENT_TRANSFER_ENCODING, (Object) "binary");
                    req.headers().set((String) "User-Agent", (Object) HttpTunnelingClientSocketChannel.class.getName());
                    if (sslHandshakeFuture == null) {
                        HttpTunnelingClientSocketChannel.this.realChannel.write(req);
                        HttpTunnelingClientSocketChannel.this.requestHeaderWritten = true;
                        future.setSuccess();
                        Channels.fireChannelConnected((Channel) this, remoteAddress);
                        return;
                    }
                    sslHandshakeFuture.addListener(new ChannelFutureListener() {
                        public void operationComplete(ChannelFuture f) {
                            if (f.isSuccess()) {
                                HttpTunnelingClientSocketChannel.this.realChannel.write(req);
                                HttpTunnelingClientSocketChannel.this.requestHeaderWritten = true;
                                future.setSuccess();
                                Channels.fireChannelConnected((Channel) this, remoteAddress);
                                return;
                            }
                            future.setFailure(f.getCause());
                            Channels.fireExceptionCaught((Channel) this, f.getCause());
                        }
                    });
                    return;
                }
                future.setFailure(f.getCause());
                Channels.fireExceptionCaught((Channel) this, f.getCause());
            }
        });
    }

    /* access modifiers changed from: 0000 */
    public void writeReal(ChannelBuffer a, final ChannelFuture future) {
        ChannelFuture f;
        if (!this.requestHeaderWritten) {
            throw new NotYetConnectedException();
        }
        final int size = a.readableBytes();
        if (size == 0) {
            f = this.realChannel.write(ChannelBuffers.EMPTY_BUFFER);
        } else {
            f = this.realChannel.write(new DefaultHttpChunk(a));
        }
        f.addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture f) {
                if (f.isSuccess()) {
                    future.setSuccess();
                    if (size != 0) {
                        Channels.fireWriteComplete((Channel) HttpTunnelingClientSocketChannel.this, (long) size);
                        return;
                    }
                    return;
                }
                future.setFailure(f.getCause());
            }
        });
    }

    private ChannelFuture writeLastChunk() {
        if (!this.requestHeaderWritten) {
            return Channels.failedFuture(this, new NotYetConnectedException());
        }
        return this.realChannel.write(HttpChunk.LAST_CHUNK);
    }

    /* access modifiers changed from: 0000 */
    public void setInterestOpsReal(int interestOps, final ChannelFuture future) {
        this.realChannel.setInterestOps(interestOps).addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture f) {
                if (f.isSuccess()) {
                    future.setSuccess();
                } else {
                    future.setFailure(f.getCause());
                }
            }
        });
    }

    /* access modifiers changed from: 0000 */
    public void disconnectReal(final ChannelFuture future) {
        writeLastChunk().addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture f) {
                HttpTunnelingClientSocketChannel.this.realChannel.disconnect().addListener(new ChannelFutureListener() {
                    public void operationComplete(ChannelFuture f) {
                        if (f.isSuccess()) {
                            future.setSuccess();
                        } else {
                            future.setFailure(f.getCause());
                        }
                    }
                });
            }
        });
    }

    /* access modifiers changed from: 0000 */
    public void unbindReal(final ChannelFuture future) {
        writeLastChunk().addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture f) {
                HttpTunnelingClientSocketChannel.this.realChannel.unbind().addListener(new ChannelFutureListener() {
                    public void operationComplete(ChannelFuture f) {
                        if (f.isSuccess()) {
                            future.setSuccess();
                        } else {
                            future.setFailure(f.getCause());
                        }
                    }
                });
            }
        });
    }

    /* access modifiers changed from: 0000 */
    public void closeReal(final ChannelFuture future) {
        writeLastChunk().addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture f) {
                HttpTunnelingClientSocketChannel.this.realChannel.close().addListener(new ChannelFutureListener() {
                    public void operationComplete(ChannelFuture f) {
                        if (f.isSuccess()) {
                            future.setSuccess();
                        } else {
                            future.setFailure(f.getCause());
                        }
                        HttpTunnelingClientSocketChannel.this.setClosed();
                    }
                });
            }
        });
    }
}