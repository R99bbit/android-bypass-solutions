package com.ning.http.client.providers.netty;

import com.ning.http.client.websocket.WebSocket;
import com.ning.http.client.websocket.WebSocketByteListener;
import com.ning.http.client.websocket.WebSocketCloseCodeReasonListener;
import com.ning.http.client.websocket.WebSocketListener;
import com.ning.http.client.websocket.WebSocketTextListener;
import java.io.ByteArrayOutputStream;
import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import org.jboss.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import org.jboss.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import org.jboss.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import org.jboss.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NettyWebSocket implements WebSocket {
    private static final Logger logger = LoggerFactory.getLogger(NettyWebSocket.class);
    private final ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream();
    private final Channel channel;
    private final ConcurrentLinkedQueue<WebSocketListener> listeners = new ConcurrentLinkedQueue<>();
    private int maxBufferSize = 128000000;
    private final StringBuilder textBuffer = new StringBuilder();

    public NettyWebSocket(Channel channel2) {
        this.channel = channel2;
    }

    public WebSocket sendMessage(byte[] message) {
        this.channel.write(new BinaryWebSocketFrame(ChannelBuffers.wrappedBuffer(message)));
        return this;
    }

    public WebSocket stream(byte[] fragment, boolean last) {
        throw new UnsupportedOperationException("Streaming currently only supported by the Grizzly provider.");
    }

    public WebSocket stream(byte[] fragment, int offset, int len, boolean last) {
        throw new UnsupportedOperationException("Streaming currently only supported by the Grizzly provider.");
    }

    public WebSocket sendTextMessage(String message) {
        this.channel.write(new TextWebSocketFrame(message));
        return this;
    }

    public WebSocket streamText(String fragment, boolean last) {
        throw new UnsupportedOperationException("Streaming currently only supported by the Grizzly provider.");
    }

    public WebSocket sendPing(byte[] payload) {
        this.channel.write(new PingWebSocketFrame(ChannelBuffers.wrappedBuffer(payload)));
        return this;
    }

    public WebSocket sendPong(byte[] payload) {
        this.channel.write(new PongWebSocketFrame(ChannelBuffers.wrappedBuffer(payload)));
        return this;
    }

    public WebSocket addWebSocketListener(WebSocketListener l) {
        this.listeners.add(l);
        return this;
    }

    public WebSocket removeWebSocketListener(WebSocketListener l) {
        this.listeners.remove(l);
        return this;
    }

    public int getMaxBufferSize() {
        return this.maxBufferSize;
    }

    public void setMaxBufferSize(int bufferSize) {
        this.maxBufferSize = bufferSize;
        if (this.maxBufferSize < 8192) {
            this.maxBufferSize = 8192;
        }
    }

    public boolean isOpen() {
        return this.channel.isOpen();
    }

    public void close() {
        if (this.channel.isOpen()) {
            onClose();
            this.listeners.clear();
            this.channel.write(new CloseWebSocketFrame()).addListener(ChannelFutureListener.CLOSE);
        }
    }

    public void close(int statusCode, String reason) {
        onClose(statusCode, reason);
        this.listeners.clear();
    }

    /* access modifiers changed from: protected */
    public void onBinaryFragment(byte[] message, boolean last) {
        if (!last) {
            try {
                this.byteBuffer.write(message);
                if (this.byteBuffer.size() > this.maxBufferSize) {
                    this.byteBuffer.reset();
                    onError(new Exception("Exceeded Netty Web Socket maximum buffer size of " + getMaxBufferSize()));
                    close();
                    return;
                }
            } catch (Exception ex) {
                this.byteBuffer.reset();
                onError(ex);
                return;
            }
        }
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            WebSocketListener l = i$.next();
            if (l instanceof WebSocketByteListener) {
                if (!last) {
                    try {
                        WebSocketByteListener.class.cast(l).onFragment(message, last);
                    } catch (Exception ex2) {
                        l.onError(ex2);
                    }
                } else if (this.byteBuffer.size() > 0) {
                    this.byteBuffer.write(message);
                    WebSocketByteListener.class.cast(l).onFragment(message, last);
                    WebSocketByteListener.class.cast(l).onMessage(this.byteBuffer.toByteArray());
                } else {
                    WebSocketByteListener.class.cast(l).onMessage(message);
                }
            }
        }
        if (last) {
            this.byteBuffer.reset();
        }
    }

    /* access modifiers changed from: protected */
    public void onTextFragment(String message, boolean last) {
        if (!last) {
            this.textBuffer.append(message);
            if (this.textBuffer.length() > this.maxBufferSize) {
                this.textBuffer.setLength(0);
                onError(new Exception("Exceeded Netty Web Socket maximum buffer size of " + getMaxBufferSize()));
                close();
                return;
            }
        }
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            WebSocketListener l = i$.next();
            if (l instanceof WebSocketTextListener) {
                if (!last) {
                    try {
                        WebSocketTextListener.class.cast(l).onFragment(message, last);
                    } catch (Exception ex) {
                        l.onError(ex);
                    }
                } else if (this.textBuffer.length() > 0) {
                    WebSocketTextListener.class.cast(l).onFragment(message, last);
                    WebSocketTextListener.class.cast(l).onMessage(this.textBuffer.append(message).toString());
                } else {
                    WebSocketTextListener.class.cast(l).onMessage(message);
                }
            }
        }
        if (last) {
            this.textBuffer.setLength(0);
        }
    }

    /* access modifiers changed from: protected */
    public void onError(Throwable t) {
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            try {
                i$.next().onError(t);
            } catch (Throwable t2) {
                logger.error((String) "", t2);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onClose() {
        onClose(1000, "Normal closure; the connection successfully completed whatever purpose for which it was created.");
    }

    /* access modifiers changed from: protected */
    public void onClose(int code, String reason) {
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            WebSocketListener l = i$.next();
            try {
                if (l instanceof WebSocketCloseCodeReasonListener) {
                    WebSocketCloseCodeReasonListener.class.cast(l).onClose(this, code, reason);
                }
                l.onClose(this);
            } catch (Throwable t) {
                l.onError(t);
            }
        }
    }

    public String toString() {
        return "NettyWebSocket{channel=" + this.channel + '}';
    }
}