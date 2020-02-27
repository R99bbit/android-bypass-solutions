package com.github.nkzawa.engineio.client.transports;

import com.github.nkzawa.engineio.client.Transport;
import com.github.nkzawa.engineio.client.Transport.Options;
import com.github.nkzawa.engineio.parser.Packet;
import com.github.nkzawa.engineio.parser.Parser;
import com.github.nkzawa.engineio.parser.Parser.EncodeCallback;
import com.github.nkzawa.parseqs.ParseQS;
import com.github.nkzawa.thread.EventThread;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request.Builder;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.ws.WebSocket.PayloadType;
import com.squareup.okhttp.ws.WebSocketCall;
import com.squareup.okhttp.ws.WebSocketListener;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.logging.Logger;
import okio.Buffer;
import okio.BufferedSource;

public class WebSocket extends Transport {
    public static final String NAME = "websocket";
    /* access modifiers changed from: private */
    public static final Logger logger = Logger.getLogger(PollingXHR.class.getName());
    /* access modifiers changed from: private */
    public com.squareup.okhttp.ws.WebSocket ws;
    private WebSocketCall wsCall;

    /* renamed from: com.github.nkzawa.engineio.client.transports.WebSocket$4 reason: invalid class name */
    static /* synthetic */ class AnonymousClass4 {
        static final /* synthetic */ int[] $SwitchMap$com$squareup$okhttp$ws$WebSocket$PayloadType = new int[PayloadType.values().length];

        static {
            try {
                $SwitchMap$com$squareup$okhttp$ws$WebSocket$PayloadType[PayloadType.TEXT.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$squareup$okhttp$ws$WebSocket$PayloadType[PayloadType.BINARY.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
        }
    }

    public WebSocket(Options opts) {
        super(opts);
        this.name = NAME;
    }

    /* access modifiers changed from: protected */
    public void doOpen() {
        Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        emit("requestHeaders", headers);
        OkHttpClient client = new OkHttpClient();
        if (this.sslContext != null) {
            client.setSslSocketFactory(this.sslContext.getSocketFactory());
        }
        if (this.hostnameVerifier != null) {
            client.setHostnameVerifier(this.hostnameVerifier);
        }
        Builder builder = new Builder().url(uri());
        for (Entry<String, List<String>> entry : headers.entrySet()) {
            for (String v : entry.getValue()) {
                builder.addHeader(entry.getKey(), v);
            }
        }
        this.wsCall = WebSocketCall.create(client, builder.build());
        this.wsCall.enqueue(new WebSocketListener() {
            public void onOpen(com.squareup.okhttp.ws.WebSocket webSocket, Response response) {
                WebSocket.this.ws = webSocket;
                final Map<String, List<String>> headers = response.headers().toMultimap();
                EventThread.exec(new Runnable() {
                    public void run() {
                        this.emit("responseHeaders", headers);
                        this.onOpen();
                    }
                });
            }

            public void onMessage(BufferedSource payload, final PayloadType type) throws IOException {
                final Object finalData = null;
                switch (AnonymousClass4.$SwitchMap$com$squareup$okhttp$ws$WebSocket$PayloadType[type.ordinal()]) {
                    case 1:
                        finalData = payload.readUtf8();
                        break;
                    case 2:
                        finalData = payload.readByteArray();
                        break;
                    default:
                        EventThread.exec(new Runnable() {
                            public void run() {
                                this.onError("Unknown payload type: " + type, new IllegalStateException());
                            }
                        });
                        break;
                }
                payload.close();
                EventThread.exec(new Runnable() {
                    public void run() {
                        if (finalData != null) {
                            if (finalData instanceof String) {
                                this.onData((String) finalData);
                            } else {
                                this.onData((byte[]) finalData);
                            }
                        }
                    }
                });
            }

            public void onPong(Buffer payload) {
            }

            public void onClose(int code, String reason) {
                EventThread.exec(new Runnable() {
                    public void run() {
                        this.onClose();
                    }
                });
            }

            public void onFailure(final IOException e, Response response) {
                EventThread.exec(new Runnable() {
                    public void run() {
                        this.onError("websocket error", e);
                    }
                });
            }
        });
        client.getDispatcher().getExecutorService().shutdown();
    }

    /* access modifiers changed from: protected */
    public void write(Packet[] packets) {
        this.writable = false;
        for (Packet packet : packets) {
            Parser.encodePacket(packet, new EncodeCallback() {
                public void call(Object packet) {
                    try {
                        if (packet instanceof String) {
                            this.ws.sendMessage(PayloadType.TEXT, new Buffer().writeUtf8((String) packet));
                        } else if (packet instanceof byte[]) {
                            this.ws.sendMessage(PayloadType.BINARY, new Buffer().write((byte[]) (byte[]) packet));
                        }
                    } catch (IOException e) {
                        WebSocket.logger.fine("websocket closed before onclose event");
                    }
                }
            });
        }
        EventThread.nextTick(new Runnable() {
            public void run() {
                this.writable = true;
                this.emit("drain", new Object[0]);
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onClose() {
        super.onClose();
    }

    /* access modifiers changed from: protected */
    public void doClose() {
        if (this.wsCall != null) {
            this.wsCall.cancel();
        }
        if (this.ws != null) {
            try {
                this.ws.close(1000, "");
            } catch (IOException | IllegalStateException e) {
            }
        }
    }

    /* access modifiers changed from: protected */
    public String uri() {
        Map<String, String> query = this.query;
        if (query == null) {
            query = new HashMap<>();
        }
        String schema = this.secure ? "wss" : "ws";
        String port = "";
        if (this.port > 0 && (("wss".equals(schema) && this.port != 443) || ("ws".equals(schema) && this.port != 80))) {
            port = ":" + this.port;
        }
        if (this.timestampRequests) {
            query.put(this.timestampParam, String.valueOf(new Date().getTime()));
        }
        String _query = ParseQS.encode(query);
        if (_query.length() > 0) {
            _query = "?" + _query;
        }
        return schema + "://" + this.hostname + port + this.path + _query;
    }
}