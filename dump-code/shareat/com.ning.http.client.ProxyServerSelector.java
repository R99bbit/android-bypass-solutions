package com.ning.http.client;

import java.net.URI;

public interface ProxyServerSelector {
    public static final ProxyServerSelector NO_PROXY_SELECTOR = new ProxyServerSelector() {
        public ProxyServer select(URI uri) {
            return null;
        }
    };

    ProxyServer select(URI uri);
}