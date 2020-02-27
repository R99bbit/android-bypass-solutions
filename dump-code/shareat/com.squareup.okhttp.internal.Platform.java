package com.squareup.okhttp.internal;

import com.google.android.gms.analytics.ecommerce.ProductAction;
import com.squareup.okhttp.Protocol;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import javax.net.ssl.SSLSocket;
import okio.Buffer;

public class Platform {
    private static final Platform PLATFORM = findPlatform();

    private static class Android extends Platform {
        private final OptionalMethod<Socket> getAlpnSelectedProtocol;
        private final OptionalMethod<Socket> setAlpnProtocols;
        private final OptionalMethod<Socket> setHostname;
        private final OptionalMethod<Socket> setUseSessionTickets;
        private final Method trafficStatsTagSocket;
        private final Method trafficStatsUntagSocket;

        public Android(OptionalMethod<Socket> setUseSessionTickets2, OptionalMethod<Socket> setHostname2, Method trafficStatsTagSocket2, Method trafficStatsUntagSocket2, OptionalMethod<Socket> getAlpnSelectedProtocol2, OptionalMethod<Socket> setAlpnProtocols2) {
            this.setUseSessionTickets = setUseSessionTickets2;
            this.setHostname = setHostname2;
            this.trafficStatsTagSocket = trafficStatsTagSocket2;
            this.trafficStatsUntagSocket = trafficStatsUntagSocket2;
            this.getAlpnSelectedProtocol = getAlpnSelectedProtocol2;
            this.setAlpnProtocols = setAlpnProtocols2;
        }

        public void connectSocket(Socket socket, InetSocketAddress address, int connectTimeout) throws IOException {
            try {
                socket.connect(address, connectTimeout);
            } catch (SecurityException se) {
                IOException ioException = new IOException("Exception in connect");
                ioException.initCause(se);
                throw ioException;
            }
        }

        public void configureTlsExtensions(SSLSocket sslSocket, String hostname, List<Protocol> protocols) {
            if (hostname != null) {
                this.setUseSessionTickets.invokeOptionalWithoutCheckedException(sslSocket, Boolean.valueOf(true));
                this.setHostname.invokeOptionalWithoutCheckedException(sslSocket, hostname);
            }
            if (this.setAlpnProtocols != null && this.setAlpnProtocols.isSupported(sslSocket)) {
                this.setAlpnProtocols.invokeWithoutCheckedException(sslSocket, concatLengthPrefixed(protocols));
            }
        }

        public String getSelectedProtocol(SSLSocket socket) {
            if (this.getAlpnSelectedProtocol == null || !this.getAlpnSelectedProtocol.isSupported(socket)) {
                return null;
            }
            byte[] alpnResult = (byte[]) this.getAlpnSelectedProtocol.invokeWithoutCheckedException(socket, new Object[0]);
            return alpnResult != null ? new String(alpnResult, Util.UTF_8) : null;
        }

        public void tagSocket(Socket socket) throws SocketException {
            if (this.trafficStatsTagSocket != null) {
                try {
                    this.trafficStatsTagSocket.invoke(null, new Object[]{socket});
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                } catch (InvocationTargetException e2) {
                    throw new RuntimeException(e2.getCause());
                }
            }
        }

        public void untagSocket(Socket socket) throws SocketException {
            if (this.trafficStatsUntagSocket != null) {
                try {
                    this.trafficStatsUntagSocket.invoke(null, new Object[]{socket});
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                } catch (InvocationTargetException e2) {
                    throw new RuntimeException(e2.getCause());
                }
            }
        }
    }

    private static class JdkWithJettyBootPlatform extends Platform {
        private final Class<?> clientProviderClass;
        private final Method getMethod;
        private final Method putMethod;
        private final Method removeMethod;
        private final Class<?> serverProviderClass;

        public JdkWithJettyBootPlatform(Method putMethod2, Method getMethod2, Method removeMethod2, Class<?> clientProviderClass2, Class<?> serverProviderClass2) {
            this.putMethod = putMethod2;
            this.getMethod = getMethod2;
            this.removeMethod = removeMethod2;
            this.clientProviderClass = clientProviderClass2;
            this.serverProviderClass = serverProviderClass2;
        }

        public void configureTlsExtensions(SSLSocket sslSocket, String hostname, List<Protocol> protocols) {
            List<String> names = new ArrayList<>(protocols.size());
            int size = protocols.size();
            for (int i = 0; i < size; i++) {
                Protocol protocol = protocols.get(i);
                if (protocol != Protocol.HTTP_1_0) {
                    names.add(protocol.toString());
                }
            }
            try {
                Object provider = Proxy.newProxyInstance(Platform.class.getClassLoader(), new Class[]{this.clientProviderClass, this.serverProviderClass}, new JettyNegoProvider(names));
                this.putMethod.invoke(null, new Object[]{sslSocket, provider});
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new AssertionError(e);
            }
        }

        public void afterHandshake(SSLSocket sslSocket) {
            try {
                this.removeMethod.invoke(null, new Object[]{sslSocket});
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new AssertionError();
            }
        }

        public String getSelectedProtocol(SSLSocket socket) {
            try {
                JettyNegoProvider provider = (JettyNegoProvider) Proxy.getInvocationHandler(this.getMethod.invoke(null, new Object[]{socket}));
                if (!provider.unsupported && provider.selected == null) {
                    Internal.logger.log(Level.INFO, "ALPN callback dropped: SPDY and HTTP/2 are disabled. Is alpn-boot on the boot class path?");
                    return null;
                } else if (!provider.unsupported) {
                    return provider.selected;
                } else {
                    return null;
                }
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new AssertionError();
            }
        }
    }

    private static class JettyNegoProvider implements InvocationHandler {
        private final List<String> protocols;
        /* access modifiers changed from: private */
        public String selected;
        /* access modifiers changed from: private */
        public boolean unsupported;

        public JettyNegoProvider(List<String> protocols2) {
            this.protocols = protocols2;
        }

        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String methodName = method.getName();
            Class<?> returnType = method.getReturnType();
            if (args == null) {
                args = Util.EMPTY_STRING_ARRAY;
            }
            if (methodName.equals("supports") && Boolean.TYPE == returnType) {
                return Boolean.valueOf(true);
            }
            if (methodName.equals("unsupported") && Void.TYPE == returnType) {
                this.unsupported = true;
                return null;
            } else if (methodName.equals("protocols") && args.length == 0) {
                return this.protocols;
            } else {
                if ((methodName.equals("selectProtocol") || methodName.equals("select")) && String.class == returnType && args.length == 1 && (args[0] instanceof List)) {
                    List<String> peerProtocols = (List) args[0];
                    int size = peerProtocols.size();
                    for (int i = 0; i < size; i++) {
                        if (this.protocols.contains(peerProtocols.get(i))) {
                            String str = peerProtocols.get(i);
                            this.selected = str;
                            return str;
                        }
                    }
                    String str2 = this.protocols.get(0);
                    this.selected = str2;
                    return str2;
                } else if ((!methodName.equals("protocolSelected") && !methodName.equals("selected")) || args.length != 1) {
                    return method.invoke(this, args);
                } else {
                    this.selected = (String) args[0];
                    return null;
                }
            }
        }
    }

    public static Platform get() {
        return PLATFORM;
    }

    public String getPrefix() {
        return "OkHttp";
    }

    public void logW(String warning) {
        System.out.println(warning);
    }

    public void tagSocket(Socket socket) throws SocketException {
    }

    public void untagSocket(Socket socket) throws SocketException {
    }

    public void configureTlsExtensions(SSLSocket sslSocket, String hostname, List<Protocol> list) {
    }

    public void afterHandshake(SSLSocket sslSocket) {
    }

    public String getSelectedProtocol(SSLSocket socket) {
        return null;
    }

    public void connectSocket(Socket socket, InetSocketAddress address, int connectTimeout) throws IOException {
        socket.connect(address, connectTimeout);
    }

    /* JADX WARNING: Failed to process nested try/catch */
    /* JADX WARNING: Removed duplicated region for block: B:25:0x0156 A[ExcHandler: ClassNotFoundException | NoSuchMethodException (e java.lang.Throwable), PHI: r5 
      PHI: (r5v1 'trafficStatsTagSocket' java.lang.reflect.Method) = (r5v0 'trafficStatsTagSocket' java.lang.reflect.Method), (r5v4 'trafficStatsTagSocket' java.lang.reflect.Method), (r5v4 'trafficStatsTagSocket' java.lang.reflect.Method), (r5v4 'trafficStatsTagSocket' java.lang.reflect.Method) binds: [B:6:0x003f, B:7:?, B:9:0x006a, B:10:?] A[DONT_GENERATE, DONT_INLINE], Splitter:B:6:0x003f] */
    private static Platform findPlatform() {
        try {
            Class.forName("com.android.org.conscrypt.OpenSSLSocketImpl");
        } catch (ClassNotFoundException e) {
            Class.forName("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl");
        }
        try {
            OptionalMethod<Socket> setUseSessionTickets = new OptionalMethod<>(null, "setUseSessionTickets", Boolean.TYPE);
            OptionalMethod<Socket> setHostname = new OptionalMethod<>(null, "setHostname", String.class);
            Method trafficStatsTagSocket = null;
            Method trafficStatsUntagSocket = null;
            OptionalMethod optionalMethod = null;
            OptionalMethod optionalMethod2 = null;
            try {
                Class<?> cls = Class.forName("android.net.TrafficStats");
                trafficStatsTagSocket = cls.getMethod("tagSocket", new Class[]{Socket.class});
                trafficStatsUntagSocket = cls.getMethod("untagSocket", new Class[]{Socket.class});
                Class.forName("android.net.Network");
                OptionalMethod optionalMethod3 = new OptionalMethod(byte[].class, "getAlpnSelectedProtocol", new Class[0]);
                try {
                    OptionalMethod optionalMethod4 = new OptionalMethod(null, "setAlpnProtocols", byte[].class);
                    optionalMethod2 = optionalMethod4;
                    optionalMethod = optionalMethod3;
                } catch (ClassNotFoundException e2) {
                    optionalMethod = optionalMethod3;
                } catch (NoSuchMethodException e3) {
                    optionalMethod = optionalMethod3;
                }
            } catch (ClassNotFoundException | NoSuchMethodException e4) {
            }
            return new Android(setUseSessionTickets, setHostname, trafficStatsTagSocket, trafficStatsUntagSocket, optionalMethod, optionalMethod2);
        } catch (ClassNotFoundException e5) {
            try {
                Class<?> cls2 = Class.forName("org.eclipse.jetty.alpn.ALPN");
                r0 = "org.eclipse.jetty.alpn.ALPN";
                Class<?> cls3 = Class.forName("org.eclipse.jetty.alpn.ALPN" + "$Provider");
                r0 = "org.eclipse.jetty.alpn.ALPN";
                Class<?> cls4 = Class.forName("org.eclipse.jetty.alpn.ALPN" + "$ClientProvider");
                r0 = "org.eclipse.jetty.alpn.ALPN";
                Class<?> cls5 = Class.forName("org.eclipse.jetty.alpn.ALPN" + "$ServerProvider");
                return new JdkWithJettyBootPlatform(cls2.getMethod("put", new Class[]{SSLSocket.class, cls3}), cls2.getMethod("get", new Class[]{SSLSocket.class}), cls2.getMethod(ProductAction.ACTION_REMOVE, new Class[]{SSLSocket.class}), cls4, cls5);
            } catch (ClassNotFoundException | NoSuchMethodException e6) {
                return new Platform();
            }
        }
    }

    static byte[] concatLengthPrefixed(List<Protocol> protocols) {
        Buffer result = new Buffer();
        int size = protocols.size();
        for (int i = 0; i < size; i++) {
            Protocol protocol = protocols.get(i);
            if (protocol != Protocol.HTTP_1_0) {
                result.writeByte(protocol.toString().length());
                result.writeUtf8(protocol.toString());
            }
        }
        return result.readByteArray();
    }
}