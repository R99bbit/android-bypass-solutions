package com.ning.http.util;

import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.ProxyServer;
import com.ning.http.client.ProxyServer.Protocol;
import com.ning.http.client.ProxyServerSelector;
import com.ning.http.client.Request;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.ProxySelector;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ProxyUtils {
    private static final String PROPERTY_PREFIX = "com.ning.http.client.AsyncHttpClientConfig.proxy.";
    public static final String PROXY_HOST = "http.proxyHost";
    public static final String PROXY_NONPROXYHOSTS = "http.nonProxyHosts";
    public static final String PROXY_PASSWORD = "com.ning.http.client.AsyncHttpClientConfig.proxy.password";
    public static final String PROXY_PORT = "http.proxyPort";
    public static final String PROXY_PROTOCOL = "com.ning.http.client.AsyncHttpClientConfig.proxy.protocol";
    public static final String PROXY_USER = "com.ning.http.client.AsyncHttpClientConfig.proxy.user";
    /* access modifiers changed from: private */
    public static final Logger log = LoggerFactory.getLogger(ProxyUtils.class);

    /* renamed from: com.ning.http.util.ProxyUtils$3 reason: invalid class name */
    static /* synthetic */ class AnonymousClass3 {
        static final /* synthetic */ int[] $SwitchMap$java$net$Proxy$Type = new int[Type.values().length];

        static {
            try {
                $SwitchMap$java$net$Proxy$Type[Type.HTTP.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$java$net$Proxy$Type[Type.DIRECT.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
        }
    }

    public static ProxyServer getProxyServer(AsyncHttpClientConfig config, Request request) {
        ProxyServer proxyServer = request.getProxyServer();
        if (proxyServer == null) {
            ProxyServerSelector selector = config.getProxyServerSelector();
            if (selector != null) {
                proxyServer = selector.select(request.getOriginalURI());
            }
        }
        if (avoidProxy(proxyServer, request)) {
            return null;
        }
        return proxyServer;
    }

    public static boolean avoidProxy(ProxyServer proxyServer, Request request) {
        return avoidProxy(proxyServer, AsyncHttpProviderUtils.getHost(request.getOriginalURI()));
    }

    public static boolean avoidProxy(ProxyServer proxyServer, String target) {
        if (proxyServer == null) {
            return true;
        }
        String targetHost = target.toLowerCase(Locale.ENGLISH);
        List<String> nonProxyHosts = proxyServer.getNonProxyHosts();
        if (nonProxyHosts != null) {
            for (String nonProxyHost : nonProxyHosts) {
                if (nonProxyHost.startsWith("*") && nonProxyHost.length() > 1 && targetHost.endsWith(nonProxyHost.substring(1).toLowerCase(Locale.ENGLISH))) {
                    return true;
                }
                if (nonProxyHost.endsWith("*") && nonProxyHost.length() > 1 && targetHost.startsWith(nonProxyHost.substring(0, nonProxyHost.length() - 1).toLowerCase(Locale.ENGLISH))) {
                    return true;
                }
                if (nonProxyHost.equalsIgnoreCase(targetHost)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static ProxyServerSelector createProxyServerSelector(Properties properties) {
        Protocol protocol;
        String host = properties.getProperty(PROXY_HOST);
        if (host == null) {
            return ProxyServerSelector.NO_PROXY_SELECTOR;
        }
        int port = Integer.valueOf(properties.getProperty(PROXY_PORT, "80")).intValue();
        try {
            protocol = Protocol.valueOf(properties.getProperty(PROXY_PROTOCOL, "HTTP"));
        } catch (IllegalArgumentException e) {
            protocol = Protocol.HTTP;
        }
        ProxyServer proxyServer = new ProxyServer(protocol, host, port, properties.getProperty(PROXY_USER), properties.getProperty(PROXY_PASSWORD));
        String nonProxyHosts = properties.getProperty(PROXY_NONPROXYHOSTS);
        if (nonProxyHosts != null) {
            for (String spec : nonProxyHosts.split("\\|")) {
                proxyServer.addNonProxyHost(spec);
            }
        }
        return createProxyServerSelector(proxyServer);
    }

    public static ProxyServerSelector getJdkDefaultProxyServerSelector() {
        return createProxyServerSelector(ProxySelector.getDefault());
    }

    public static ProxyServerSelector createProxyServerSelector(final ProxySelector proxySelector) {
        return new ProxyServerSelector() {
            public ProxyServer select(URI uri) {
                List<Proxy> select = proxySelector.select(uri);
                if (select == null) {
                    return null;
                }
                for (Proxy proxy : select) {
                    switch (AnonymousClass3.$SwitchMap$java$net$Proxy$Type[proxy.type().ordinal()]) {
                        case 1:
                            if (!(proxy.address() instanceof InetSocketAddress)) {
                                ProxyUtils.log.warn("Don't know how to connect to address " + proxy.address());
                                return null;
                            }
                            InetSocketAddress address = (InetSocketAddress) proxy.address();
                            return new ProxyServer(Protocol.HTTP, address.getHostName(), address.getPort());
                        case 2:
                            return null;
                        default:
                            ProxyUtils.log.warn("ProxySelector returned proxy type that we don't know how to use: " + proxy.type());
                    }
                }
                return null;
            }
        };
    }

    public static ProxyServerSelector createProxyServerSelector(final ProxyServer proxyServer) {
        return new ProxyServerSelector() {
            public ProxyServer select(URI uri) {
                return proxyServer;
            }
        };
    }
}