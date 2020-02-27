package org.jboss.netty.channel.socket.http;

import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.SocketAddress;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.channel.local.DefaultLocalClientChannelFactory;
import org.jboss.netty.channel.local.LocalAddress;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

public class HttpTunnelingServlet extends HttpServlet {
    static final /* synthetic */ boolean $assertionsDisabled = (!HttpTunnelingServlet.class.desiredAssertionStatus());
    private static final String ENDPOINT = "endpoint";
    static final InternalLogger logger = InternalLoggerFactory.getInstance(HttpTunnelingServlet.class);
    private static final long serialVersionUID = 4259910275899756070L;
    private volatile ChannelFactory channelFactory;
    private volatile SocketAddress remoteAddress;

    private static final class OutboundConnectionHandler extends SimpleChannelUpstreamHandler {
        private final ServletOutputStream out;

        public OutboundConnectionHandler(ServletOutputStream out2) {
            this.out = out2;
        }

        public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
            ChannelBuffer buffer = (ChannelBuffer) e.getMessage();
            synchronized (this) {
                buffer.readBytes((OutputStream) this.out, buffer.readableBytes());
                this.out.flush();
            }
        }

        public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
            if (HttpTunnelingServlet.logger.isWarnEnabled()) {
                HttpTunnelingServlet.logger.warn("Unexpected exception while HTTP tunneling", e.getCause());
            }
            e.getChannel().close();
        }
    }

    public void init() throws ServletException {
        String endpoint = getServletConfig().getInitParameter(ENDPOINT);
        if (endpoint == null) {
            throw new ServletException("init-param 'endpoint' must be specified.");
        }
        try {
            this.remoteAddress = parseEndpoint(endpoint.trim());
            try {
                this.channelFactory = createChannelFactory(this.remoteAddress);
            } catch (ServletException e) {
                throw e;
            } catch (Exception e2) {
                throw new ServletException("Failed to create a channel factory.", e2);
            }
        } catch (ServletException e3) {
            throw e3;
        } catch (Exception e4) {
            throw new ServletException("Failed to parse an endpoint.", e4);
        }
    }

    /* access modifiers changed from: protected */
    public SocketAddress parseEndpoint(String endpoint) throws Exception {
        if (endpoint.startsWith("local:")) {
            return new LocalAddress(endpoint.substring(6).trim());
        }
        throw new ServletException("Invalid or unknown endpoint: " + endpoint);
    }

    /* access modifiers changed from: protected */
    public ChannelFactory createChannelFactory(SocketAddress remoteAddress2) throws Exception {
        if (remoteAddress2 instanceof LocalAddress) {
            return new DefaultLocalClientChannelFactory();
        }
        throw new ServletException("Unsupported remote address type: " + remoteAddress2.getClass().getName());
    }

    public void destroy() {
        try {
            destroyChannelFactory(this.channelFactory);
        } catch (Exception e) {
            if (logger.isWarnEnabled()) {
                logger.warn("Failed to destroy a channel factory.", e);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void destroyChannelFactory(ChannelFactory factory) throws Exception {
        factory.releaseExternalResources();
    }

    /* JADX INFO: finally extract failed */
    /* access modifiers changed from: protected */
    public void service(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        if (!HttpRequest.METHOD_POST.equalsIgnoreCase(req.getMethod())) {
            if (logger.isWarnEnabled()) {
                logger.warn("Unallowed method: " + req.getMethod());
            }
            res.sendError(405);
            return;
        }
        ChannelPipeline pipeline = Channels.pipeline();
        ServletOutputStream out = res.getOutputStream();
        pipeline.addLast("handler", new OutboundConnectionHandler(out));
        Channel channel = this.channelFactory.newChannel(pipeline);
        ChannelFuture future = channel.connect(this.remoteAddress).awaitUninterruptibly();
        if (!future.isSuccess()) {
            if (logger.isWarnEnabled()) {
                Throwable cause = future.getCause();
                logger.warn("Endpoint unavailable: " + cause.getMessage(), cause);
            }
            res.sendError(503);
            return;
        }
        ChannelFuture lastWriteFuture = null;
        try {
            res.setStatus(200);
            res.setHeader("Content-Type", "application/octet-stream");
            res.setHeader(Names.CONTENT_TRANSFER_ENCODING, "binary");
            out.flush();
            PushbackInputStream in = new PushbackInputStream(req.getInputStream());
            while (channel.isConnected()) {
                try {
                    ChannelBuffer buffer = read(in);
                    if (buffer == null) {
                        break;
                    }
                    lastWriteFuture = channel.write(buffer);
                } catch (EOFException e) {
                }
            }
            if (lastWriteFuture == null) {
                channel.close();
            } else {
                lastWriteFuture.addListener(ChannelFutureListener.CLOSE);
            }
        } catch (Throwable th) {
            if (lastWriteFuture == null) {
                channel.close();
            } else {
                lastWriteFuture.addListener(ChannelFutureListener.CLOSE);
            }
            throw th;
        }
    }

    private static ChannelBuffer read(PushbackInputStream in) throws IOException {
        byte[] buf;
        int readBytes;
        int bytesToRead = in.available();
        if (bytesToRead > 0) {
            buf = new byte[bytesToRead];
            readBytes = in.read(buf);
        } else if (bytesToRead != 0) {
            return null;
        } else {
            int b = in.read();
            if (b < 0 || in.available() < 0) {
                return null;
            }
            in.unread(b);
            buf = new byte[in.available()];
            readBytes = in.read(buf);
        }
        if (!$assertionsDisabled && readBytes <= 0) {
            throw new AssertionError();
        } else if (readBytes == buf.length) {
            return ChannelBuffers.wrappedBuffer(buf);
        } else {
            return ChannelBuffers.wrappedBuffer(buf, 0, readBytes);
        }
    }
}