package com.ning.http.client.websocket;

import android.support.v4.media.session.PlaybackStateCompat;
import com.ning.http.client.AsyncHandler;
import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.UpgradeHandler;
import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

public class WebSocketUpgradeHandler implements UpgradeHandler<WebSocket>, AsyncHandler<WebSocket> {
    private final ConcurrentLinkedQueue<WebSocketListener> l;
    private final long maxByteSize;
    private final long maxTextSize;
    private final AtomicBoolean ok = new AtomicBoolean(false);
    private final AtomicBoolean onSuccessCalled = new AtomicBoolean(false);
    private final String protocol;
    private int status;
    private WebSocket webSocket;

    public static final class Builder {
        /* access modifiers changed from: private */
        public ConcurrentLinkedQueue<WebSocketListener> l = new ConcurrentLinkedQueue<>();
        /* access modifiers changed from: private */
        public long maxByteSize = PlaybackStateCompat.ACTION_PLAY_FROM_URI;
        /* access modifiers changed from: private */
        public long maxTextSize = PlaybackStateCompat.ACTION_PLAY_FROM_URI;
        /* access modifiers changed from: private */
        public String protocol = "";

        public Builder addWebSocketListener(WebSocketListener listener) {
            this.l.add(listener);
            return this;
        }

        public Builder removeWebSocketListener(WebSocketListener listener) {
            this.l.remove(listener);
            return this;
        }

        public Builder setProtocol(String protocol2) {
            this.protocol = protocol2;
            return this;
        }

        public Builder setMaxByteSize(long maxByteSize2) {
            this.maxByteSize = maxByteSize2;
            return this;
        }

        public Builder setMaxTextSize(long maxTextSize2) {
            this.maxTextSize = maxTextSize2;
            return this;
        }

        public WebSocketUpgradeHandler build() {
            return new WebSocketUpgradeHandler(this);
        }
    }

    protected WebSocketUpgradeHandler(Builder b) {
        this.l = b.l;
        this.protocol = b.protocol;
        this.maxByteSize = b.maxByteSize;
        this.maxTextSize = b.maxTextSize;
    }

    public void onThrowable(Throwable t) {
        onFailure(t);
    }

    public boolean touchSuccess() {
        return this.onSuccessCalled.getAndSet(true);
    }

    public void resetSuccess() {
        this.onSuccessCalled.set(false);
    }

    public STATE onBodyPartReceived(HttpResponseBodyPart bodyPart) throws Exception {
        return STATE.CONTINUE;
    }

    public STATE onStatusReceived(HttpResponseStatus responseStatus) throws Exception {
        this.status = responseStatus.getStatusCode();
        if (responseStatus.getStatusCode() == 101) {
            return STATE.UPGRADE;
        }
        return STATE.ABORT;
    }

    public STATE onHeadersReceived(HttpResponseHeaders headers) throws Exception {
        return STATE.CONTINUE;
    }

    public WebSocket onCompleted() throws Exception {
        if (this.status != 101) {
            Iterator i$ = this.l.iterator();
            while (i$.hasNext()) {
                i$.next().onError(new IllegalStateException(String.format("Invalid Status Code %d", new Object[]{Integer.valueOf(this.status)})));
            }
            return null;
        } else if (this.webSocket != null) {
            return this.webSocket;
        } else {
            throw new IllegalStateException("WebSocket is null");
        }
    }

    public void onSuccess(WebSocket webSocket2) {
        this.webSocket = webSocket2;
        Iterator i$ = this.l.iterator();
        while (i$.hasNext()) {
            WebSocketListener w = i$.next();
            webSocket2.addWebSocketListener(w);
            w.onOpen(webSocket2);
        }
        this.ok.set(true);
    }

    public void onFailure(Throwable t) {
        Iterator i$ = this.l.iterator();
        while (i$.hasNext()) {
            WebSocketListener w = i$.next();
            if (!this.ok.get() && this.webSocket != null) {
                this.webSocket.addWebSocketListener(w);
            }
            w.onError(t);
        }
    }

    public void onClose(WebSocket webSocket2, int status2, String reasonPhrase) {
        if (this.webSocket == null) {
            this.webSocket = webSocket2;
        }
        Iterator i$ = this.l.iterator();
        while (i$.hasNext()) {
            WebSocketListener w = i$.next();
            if (webSocket2 != null) {
                webSocket2.addWebSocketListener(w);
            }
            w.onClose(webSocket2);
            if (w instanceof WebSocketCloseCodeReasonListener) {
                WebSocketCloseCodeReasonListener.class.cast(w).onClose(webSocket2, status2, reasonPhrase);
            }
        }
    }
}