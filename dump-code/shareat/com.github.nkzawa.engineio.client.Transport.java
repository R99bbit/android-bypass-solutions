package com.github.nkzawa.engineio.client;

import com.github.nkzawa.emitter.Emitter;
import com.github.nkzawa.engineio.parser.Packet;
import com.github.nkzawa.engineio.parser.Parser;
import com.github.nkzawa.thread.EventThread;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

public abstract class Transport extends Emitter {
    public static final String EVENT_CLOSE = "close";
    public static final String EVENT_DRAIN = "drain";
    public static final String EVENT_ERROR = "error";
    public static final String EVENT_OPEN = "open";
    public static final String EVENT_PACKET = "packet";
    public static final String EVENT_REQUEST_HEADERS = "requestHeaders";
    public static final String EVENT_RESPONSE_HEADERS = "responseHeaders";
    protected static int timestamps = 0;
    protected String hostname;
    protected HostnameVerifier hostnameVerifier;
    public String name;
    protected String path;
    protected int port;
    public Map<String, String> query;
    /* access modifiers changed from: protected */
    public ReadyState readyState;
    protected boolean secure;
    protected Socket socket;
    protected SSLContext sslContext;
    protected String timestampParam;
    protected boolean timestampRequests;
    public boolean writable;

    public static class Options {
        public String hostname;
        public HostnameVerifier hostnameVerifier;
        public String path;
        public int policyPort = -1;
        public int port = -1;
        public Map<String, String> query;
        public boolean secure;
        protected Socket socket;
        public SSLContext sslContext;
        public String timestampParam;
        public boolean timestampRequests;
    }

    protected enum ReadyState {
        OPENING,
        OPEN,
        CLOSED,
        PAUSED;

        public String toString() {
            return super.toString().toLowerCase();
        }
    }

    /* access modifiers changed from: protected */
    public abstract void doClose();

    /* access modifiers changed from: protected */
    public abstract void doOpen();

    /* access modifiers changed from: protected */
    public abstract void write(Packet[] packetArr);

    public Transport(Options opts) {
        this.path = opts.path;
        this.hostname = opts.hostname;
        this.port = opts.port;
        this.secure = opts.secure;
        this.query = opts.query;
        this.timestampParam = opts.timestampParam;
        this.timestampRequests = opts.timestampRequests;
        this.sslContext = opts.sslContext;
        this.socket = opts.socket;
        this.hostnameVerifier = opts.hostnameVerifier;
    }

    /* access modifiers changed from: protected */
    public Transport onError(String msg, Exception desc) {
        emit("error", new EngineIOException(msg, desc));
        return this;
    }

    public Transport open() {
        EventThread.exec(new Runnable() {
            public void run() {
                if (Transport.this.readyState == ReadyState.CLOSED || Transport.this.readyState == null) {
                    Transport.this.readyState = ReadyState.OPENING;
                    Transport.this.doOpen();
                }
            }
        });
        return this;
    }

    public Transport close() {
        EventThread.exec(new Runnable() {
            public void run() {
                if (Transport.this.readyState == ReadyState.OPENING || Transport.this.readyState == ReadyState.OPEN) {
                    Transport.this.doClose();
                    Transport.this.onClose();
                }
            }
        });
        return this;
    }

    public void send(final Packet[] packets) {
        EventThread.exec(new Runnable() {
            public void run() {
                if (Transport.this.readyState == ReadyState.OPEN) {
                    Transport.this.write(packets);
                    return;
                }
                throw new RuntimeException("Transport not open");
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onOpen() {
        this.readyState = ReadyState.OPEN;
        this.writable = true;
        emit("open", new Object[0]);
    }

    /* access modifiers changed from: protected */
    public void onData(String data) {
        onPacket(Parser.decodePacket(data));
    }

    /* access modifiers changed from: protected */
    public void onData(byte[] data) {
        onPacket(Parser.decodePacket(data));
    }

    /* access modifiers changed from: protected */
    public void onPacket(Packet packet) {
        emit("packet", packet);
    }

    /* access modifiers changed from: protected */
    public void onClose() {
        this.readyState = ReadyState.CLOSED;
        emit("close", new Object[0]);
    }
}