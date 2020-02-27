package com.squareup.okhttp;

import com.squareup.okhttp.internal.http.HttpConnection;
import com.squareup.okhttp.internal.http.HttpEngine;
import com.squareup.okhttp.internal.http.HttpTransport;
import com.squareup.okhttp.internal.http.RouteException;
import com.squareup.okhttp.internal.http.SocketConnector;
import com.squareup.okhttp.internal.http.SocketConnector.ConnectedSocket;
import com.squareup.okhttp.internal.http.SpdyTransport;
import com.squareup.okhttp.internal.http.Transport;
import com.squareup.okhttp.internal.spdy.SpdyConnection;
import com.squareup.okhttp.internal.spdy.SpdyConnection.Builder;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownServiceException;
import java.util.List;
import okio.BufferedSink;
import okio.BufferedSource;

public final class Connection {
    private boolean connected = false;
    private Handshake handshake;
    private HttpConnection httpConnection;
    private long idleStartTimeNs;
    private Object owner;
    private final ConnectionPool pool;
    private Protocol protocol = Protocol.HTTP_1_1;
    private int recycleCount;
    private final Route route;
    private Socket socket;
    private SpdyConnection spdyConnection;

    public Connection(ConnectionPool pool2, Route route2) {
        this.pool = pool2;
        this.route = route2;
    }

    /* access modifiers changed from: 0000 */
    public Object getOwner() {
        Object obj;
        synchronized (this.pool) {
            obj = this.owner;
        }
        return obj;
    }

    /* access modifiers changed from: 0000 */
    public void setOwner(Object owner2) {
        if (!isSpdy()) {
            synchronized (this.pool) {
                if (this.owner != null) {
                    throw new IllegalStateException("Connection already has an owner!");
                }
                this.owner = owner2;
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean clearOwner() {
        boolean z;
        synchronized (this.pool) {
            try {
                if (this.owner == null) {
                    z = false;
                } else {
                    this.owner = null;
                    z = true;
                }
            }
        }
        return z;
    }

    /* access modifiers changed from: 0000 */
    public void closeIfOwnedBy(Object owner2) throws IOException {
        if (isSpdy()) {
            throw new IllegalStateException();
        }
        synchronized (this.pool) {
            if (this.owner == owner2) {
                this.owner = null;
                this.socket.close();
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void connect(int connectTimeout, int readTimeout, int writeTimeout, Request request, List<ConnectionSpec> connectionSpecs, boolean connectionRetryEnabled) throws RouteException {
        ConnectedSocket connectedSocket;
        if (this.connected) {
            throw new IllegalStateException("already connected");
        }
        SocketConnector socketConnector = new SocketConnector(this, this.pool);
        if (this.route.address.getSslSocketFactory() != null) {
            connectedSocket = socketConnector.connectTls(connectTimeout, readTimeout, writeTimeout, request, this.route, connectionSpecs, connectionRetryEnabled);
        } else if (!connectionSpecs.contains(ConnectionSpec.CLEARTEXT)) {
            throw new RouteException(new UnknownServiceException("CLEARTEXT communication not supported: " + connectionSpecs));
        } else {
            connectedSocket = socketConnector.connectCleartext(connectTimeout, readTimeout, this.route);
        }
        this.socket = connectedSocket.socket;
        this.handshake = connectedSocket.handshake;
        this.protocol = connectedSocket.alpnProtocol == null ? Protocol.HTTP_1_1 : connectedSocket.alpnProtocol;
        try {
            if (this.protocol == Protocol.SPDY_3 || this.protocol == Protocol.HTTP_2) {
                this.socket.setSoTimeout(0);
                this.spdyConnection = new Builder(this.route.address.uriHost, true, this.socket).protocol(this.protocol).build();
                this.spdyConnection.sendConnectionPreface();
            } else {
                this.httpConnection = new HttpConnection(this.pool, this, this.socket);
            }
            this.connected = true;
        } catch (IOException e) {
            throw new RouteException(e);
        }
    }

    /* access modifiers changed from: 0000 */
    public void connectAndSetOwner(OkHttpClient client, Object owner2, Request request) throws RouteException {
        setOwner(owner2);
        if (!isConnected()) {
            Request request2 = request;
            connect(client.getConnectTimeout(), client.getReadTimeout(), client.getWriteTimeout(), request2, this.route.address.getConnectionSpecs(), client.getRetryOnConnectionFailure());
            if (isSpdy()) {
                client.getConnectionPool().share(this);
            }
            client.routeDatabase().connected(getRoute());
        }
        setTimeouts(client.getReadTimeout(), client.getWriteTimeout());
    }

    /* access modifiers changed from: 0000 */
    public boolean isConnected() {
        return this.connected;
    }

    public Route getRoute() {
        return this.route;
    }

    public Socket getSocket() {
        return this.socket;
    }

    /* access modifiers changed from: 0000 */
    public BufferedSource rawSource() {
        if (this.httpConnection != null) {
            return this.httpConnection.rawSource();
        }
        throw new UnsupportedOperationException();
    }

    /* access modifiers changed from: 0000 */
    public BufferedSink rawSink() {
        if (this.httpConnection != null) {
            return this.httpConnection.rawSink();
        }
        throw new UnsupportedOperationException();
    }

    /* access modifiers changed from: 0000 */
    public boolean isAlive() {
        return !this.socket.isClosed() && !this.socket.isInputShutdown() && !this.socket.isOutputShutdown();
    }

    /* access modifiers changed from: 0000 */
    public boolean isReadable() {
        if (this.httpConnection != null) {
            return this.httpConnection.isReadable();
        }
        return true;
    }

    /* access modifiers changed from: 0000 */
    public void resetIdleStartTime() {
        if (this.spdyConnection != null) {
            throw new IllegalStateException("spdyConnection != null");
        }
        this.idleStartTimeNs = System.nanoTime();
    }

    /* access modifiers changed from: 0000 */
    public boolean isIdle() {
        return this.spdyConnection == null || this.spdyConnection.isIdle();
    }

    /* access modifiers changed from: 0000 */
    public long getIdleStartTimeNs() {
        return this.spdyConnection == null ? this.idleStartTimeNs : this.spdyConnection.getIdleStartTimeNs();
    }

    public Handshake getHandshake() {
        return this.handshake;
    }

    /* access modifiers changed from: 0000 */
    public Transport newTransport(HttpEngine httpEngine) throws IOException {
        return this.spdyConnection != null ? new SpdyTransport(httpEngine, this.spdyConnection) : new HttpTransport(httpEngine, this.httpConnection);
    }

    /* access modifiers changed from: 0000 */
    public boolean isSpdy() {
        return this.spdyConnection != null;
    }

    public Protocol getProtocol() {
        return this.protocol;
    }

    /* access modifiers changed from: 0000 */
    public void setProtocol(Protocol protocol2) {
        if (protocol2 == null) {
            throw new IllegalArgumentException("protocol == null");
        }
        this.protocol = protocol2;
    }

    /* access modifiers changed from: 0000 */
    public void setTimeouts(int readTimeoutMillis, int writeTimeoutMillis) throws RouteException {
        if (!this.connected) {
            throw new IllegalStateException("setTimeouts - not connected");
        } else if (this.httpConnection != null) {
            try {
                this.socket.setSoTimeout(readTimeoutMillis);
                this.httpConnection.setTimeouts(readTimeoutMillis, writeTimeoutMillis);
            } catch (IOException e) {
                throw new RouteException(e);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void incrementRecycleCount() {
        this.recycleCount++;
    }

    /* access modifiers changed from: 0000 */
    public int recycleCount() {
        return this.recycleCount;
    }

    public String toString() {
        return "Connection{" + this.route.address.uriHost + ":" + this.route.address.uriPort + ", proxy=" + this.route.proxy + " hostAddress=" + this.route.inetSocketAddress.getAddress().getHostAddress() + " cipherSuite=" + (this.handshake != null ? this.handshake.cipherSuite() : "none") + " protocol=" + this.protocol + '}';
    }
}