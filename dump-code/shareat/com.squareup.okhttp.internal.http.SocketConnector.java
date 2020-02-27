package com.squareup.okhttp.internal.http;

import com.kakao.util.helper.CommonProtocol;
import com.squareup.okhttp.Address;
import com.squareup.okhttp.CertificatePinner;
import com.squareup.okhttp.Connection;
import com.squareup.okhttp.ConnectionPool;
import com.squareup.okhttp.ConnectionSpec;
import com.squareup.okhttp.Handshake;
import com.squareup.okhttp.Protocol;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Request.Builder;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.Route;
import com.squareup.okhttp.internal.ConnectionSpecSelector;
import com.squareup.okhttp.internal.Platform;
import com.squareup.okhttp.internal.Util;
import com.squareup.okhttp.internal.tls.OkHostnameVerifier;
import java.io.IOException;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.Socket;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import okio.Source;

public class SocketConnector {
    private final Connection connection;
    private final ConnectionPool connectionPool;

    public static class ConnectedSocket {
        public final Protocol alpnProtocol;
        public final Handshake handshake;
        public final Route route;
        public final Socket socket;

        public ConnectedSocket(Route route2, Socket socket2) {
            this.route = route2;
            this.socket = socket2;
            this.alpnProtocol = null;
            this.handshake = null;
        }

        public ConnectedSocket(Route route2, SSLSocket socket2, Protocol alpnProtocol2, Handshake handshake2) {
            this.route = route2;
            this.socket = socket2;
            this.alpnProtocol = alpnProtocol2;
            this.handshake = handshake2;
        }
    }

    public SocketConnector(Connection connection2, ConnectionPool connectionPool2) {
        this.connection = connection2;
        this.connectionPool = connectionPool2;
    }

    public ConnectedSocket connectCleartext(int connectTimeout, int readTimeout, Route route) throws RouteException {
        return new ConnectedSocket(route, connectRawSocket(readTimeout, connectTimeout, route));
    }

    /* JADX INFO: finally extract failed */
    public ConnectedSocket connectTls(int connectTimeout, int readTimeout, int writeTimeout, Request request, Route route, List<ConnectionSpec> connectionSpecs, boolean connectionRetryEnabled) throws RouteException {
        boolean canRetry;
        Platform platform;
        Address address = route.getAddress();
        ConnectionSpecSelector connectionSpecSelector = new ConnectionSpecSelector(connectionSpecs);
        RouteException routeException = null;
        do {
            Socket socket = connectRawSocket(readTimeout, connectTimeout, route);
            if (route.requiresTunnel()) {
                createTunnel(readTimeout, writeTimeout, request, route, socket);
            }
            SSLSocket sslSocket = null;
            try {
                sslSocket = (SSLSocket) address.getSslSocketFactory().createSocket(socket, address.getUriHost(), address.getUriPort(), true);
                ConnectionSpec connectionSpec = connectionSpecSelector.configureSecureSocket(sslSocket);
                platform = Platform.get();
                Protocol alpnProtocol = null;
                if (connectionSpec.supportsTlsExtensions()) {
                    platform.configureTlsExtensions(sslSocket, address.getUriHost(), address.getProtocols());
                }
                sslSocket.startHandshake();
                Handshake handshake = Handshake.get(sslSocket.getSession());
                if (connectionSpec.supportsTlsExtensions()) {
                    String maybeProtocol = platform.getSelectedProtocol(sslSocket);
                    if (maybeProtocol != null) {
                        alpnProtocol = Protocol.get(maybeProtocol);
                    }
                }
                platform.afterHandshake(sslSocket);
                if (!address.getHostnameVerifier().verify(address.getUriHost(), sslSocket.getSession())) {
                    X509Certificate cert = (X509Certificate) sslSocket.getSession().getPeerCertificates()[0];
                    throw new SSLPeerUnverifiedException("Hostname " + address.getUriHost() + " not verified:" + "\n    certificate: " + CertificatePinner.pin(cert) + "\n    DN: " + cert.getSubjectDN().getName() + "\n    subjectAltNames: " + OkHostnameVerifier.allSubjectAltNames(cert));
                }
                address.getCertificatePinner().check(address.getUriHost(), handshake.peerCertificates());
                return new ConnectedSocket(route, sslSocket, alpnProtocol, handshake);
            } catch (IOException e) {
                canRetry = connectionRetryEnabled && connectionSpecSelector.connectionFailed(e);
                Util.closeQuietly((Socket) sslSocket);
                Util.closeQuietly(socket);
                if (routeException == null) {
                    routeException = new RouteException(e);
                    continue;
                } else {
                    routeException.addConnectException(e);
                    continue;
                }
                if (!canRetry) {
                    throw routeException;
                }
            } catch (Throwable th) {
                platform.afterHandshake(sslSocket);
                throw th;
            }
        } while (!canRetry);
        throw routeException;
    }

    private Socket connectRawSocket(int soTimeout, int connectTimeout, Route route) throws RouteException {
        Socket socket;
        Platform platform = Platform.get();
        try {
            Proxy proxy = route.getProxy();
            Address address = route.getAddress();
            if (proxy.type() == Type.DIRECT || proxy.type() == Type.HTTP) {
                socket = address.getSocketFactory().createSocket();
            } else {
                socket = new Socket(proxy);
            }
            socket.setSoTimeout(soTimeout);
            platform.connectSocket(socket, route.getSocketAddress(), connectTimeout);
            return socket;
        } catch (IOException e) {
            throw new RouteException(e);
        }
    }

    private void createTunnel(int readTimeout, int writeTimeout, Request request, Route route, Socket socket) throws RouteException {
        try {
            Request tunnelRequest = createTunnelRequest(request);
            HttpConnection tunnelConnection = new HttpConnection(this.connectionPool, this.connection, socket);
            tunnelConnection.setTimeouts(readTimeout, writeTimeout);
            URL url = tunnelRequest.url();
            String requestLine = "CONNECT " + url.getHost() + ":" + Util.getEffectivePort(url) + " HTTP/1.1";
            do {
                tunnelConnection.writeRequest(tunnelRequest.headers(), requestLine);
                tunnelConnection.flush();
                Response response = tunnelConnection.readResponse().request(tunnelRequest).build();
                long contentLength = OkHeaders.contentLength(response);
                if (contentLength == -1) {
                    contentLength = 0;
                }
                Source body = tunnelConnection.newFixedLengthSource(contentLength);
                Util.skipAll(body, ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED, TimeUnit.MILLISECONDS);
                body.close();
                switch (response.code()) {
                    case 200:
                        if (tunnelConnection.bufferSize() > 0) {
                            throw new IOException("TLS tunnel buffered too many bytes!");
                        }
                        return;
                    case 407:
                        tunnelRequest = OkHeaders.processAuthHeader(route.getAddress().getAuthenticator(), response, route.getProxy());
                        break;
                    default:
                        throw new IOException("Unexpected response code for CONNECT: " + response.code());
                }
                throw new RouteException(e);
            } while (tunnelRequest != null);
            throw new IOException("Failed to authenticate with proxy");
        } catch (IOException e) {
            throw new RouteException(e);
        }
    }

    private Request createTunnelRequest(Request request) throws IOException {
        String host = request.url().getHost();
        int port = Util.getEffectivePort(request.url());
        Builder result = new Builder().url(new URL(CommonProtocol.URL_SCHEME, host, port, "/")).header("Host", port == Util.getDefaultPort(CommonProtocol.URL_SCHEME) ? host : host + ":" + port).header("Proxy-Connection", "Keep-Alive");
        String userAgent = request.header("User-Agent");
        if (userAgent != null) {
            result.header("User-Agent", userAgent);
        }
        String proxyAuthorization = request.header("Proxy-Authorization");
        if (proxyAuthorization != null) {
            result.header("Proxy-Authorization", proxyAuthorization);
        }
        return result.build();
    }
}