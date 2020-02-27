package com.squareup.okhttp.ws;

import com.github.nkzawa.engineio.client.transports.WebSocket;
import com.squareup.okhttp.Call;
import com.squareup.okhttp.Callback;
import com.squareup.okhttp.Connection;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Protocol;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.internal.Internal;
import com.squareup.okhttp.internal.Util;
import com.squareup.okhttp.internal.ws.RealWebSocket;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.IOException;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import okio.BufferedSink;
import okio.BufferedSource;
import okio.ByteString;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;

public final class WebSocketCall {
    private final Call call;
    private final String key;
    private final Random random;
    private final Request request;

    private static class ConnectionWebSocket extends RealWebSocket {
        private final Connection connection;

        static RealWebSocket create(Response response, Connection connection2, BufferedSource source, BufferedSink sink, Random random, WebSocketListener listener) {
            String url = response.request().urlString();
            ThreadPoolExecutor replyExecutor = new ThreadPoolExecutor(1, 1, 1, TimeUnit.SECONDS, new LinkedBlockingDeque(), Util.threadFactory(String.format("OkHttp %s WebSocket", new Object[]{url}), true));
            replyExecutor.allowCoreThreadTimeOut(true);
            return new ConnectionWebSocket(connection2, source, sink, random, replyExecutor, listener, url);
        }

        private ConnectionWebSocket(Connection connection2, BufferedSource source, BufferedSink sink, Random random, Executor replyExecutor, WebSocketListener listener, String url) {
            super(true, source, sink, random, replyExecutor, listener, url);
            this.connection = connection2;
        }

        /* access modifiers changed from: protected */
        public void closeConnection() throws IOException {
            Internal.instance.closeIfOwnedBy(this.connection, this);
        }
    }

    public static WebSocketCall create(OkHttpClient client, Request request2) {
        return new WebSocketCall(client, request2);
    }

    WebSocketCall(OkHttpClient client, Request request2) {
        this(client, request2, new SecureRandom());
    }

    WebSocketCall(OkHttpClient client, Request request2, Random random2) {
        if (!HttpRequest.METHOD_GET.equals(request2.method())) {
            throw new IllegalArgumentException("Request must be GET: " + request2.method());
        }
        this.random = random2;
        byte[] nonce = new byte[16];
        random2.nextBytes(nonce);
        this.key = ByteString.of(nonce).base64();
        OkHttpClient client2 = client.clone();
        client2.setProtocols(Collections.singletonList(Protocol.HTTP_1_1));
        Request request3 = request2.newBuilder().header("Upgrade", WebSocket.NAME).header("Connection", "Upgrade").header(Names.SEC_WEBSOCKET_KEY, this.key).header(Names.SEC_WEBSOCKET_VERSION, "13").build();
        this.request = request3;
        this.call = client2.newCall(request3);
    }

    public void enqueue(final WebSocketListener listener) {
        Internal.instance.callEnqueue(this.call, new Callback() {
            public void onResponse(Response response) throws IOException {
                try {
                    WebSocketCall.this.createWebSocket(response, listener);
                } catch (IOException e) {
                    listener.onFailure(e, response);
                }
            }

            public void onFailure(Request request, IOException e) {
                listener.onFailure(e, null);
            }
        }, true);
    }

    public void cancel() {
        this.call.cancel();
    }

    /* access modifiers changed from: private */
    public void createWebSocket(Response response, WebSocketListener listener) throws IOException {
        if (response.code() != 101) {
            Internal.instance.callEngineReleaseConnection(this.call);
            throw new ProtocolException("Expected HTTP 101 response but was '" + response.code() + " " + response.message() + "'");
        }
        String headerConnection = response.header("Connection");
        if (!"Upgrade".equalsIgnoreCase(headerConnection)) {
            throw new ProtocolException("Expected 'Connection' header value 'Upgrade' but was '" + headerConnection + "'");
        }
        String headerUpgrade = response.header("Upgrade");
        if (!WebSocket.NAME.equalsIgnoreCase(headerUpgrade)) {
            throw new ProtocolException("Expected 'Upgrade' header value 'websocket' but was '" + headerUpgrade + "'");
        }
        String headerAccept = response.header(Names.SEC_WEBSOCKET_ACCEPT);
        String acceptExpected = Util.shaBase64(this.key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        if (!acceptExpected.equals(headerAccept)) {
            throw new ProtocolException("Expected 'Sec-WebSocket-Accept' header value '" + acceptExpected + "' but was '" + headerAccept + "'");
        }
        Connection connection = Internal.instance.callEngineGetConnection(this.call);
        if (!Internal.instance.clearOwner(connection)) {
            throw new IllegalStateException("Unable to take ownership of connection.");
        }
        RealWebSocket webSocket = ConnectionWebSocket.create(response, connection, Internal.instance.connectionRawSource(connection), Internal.instance.connectionRawSink(connection), this.random, listener);
        Internal.instance.connectionSetOwner(connection, webSocket);
        listener.onOpen(webSocket, response);
        do {
        } while (webSocket.readMessage());
    }
}