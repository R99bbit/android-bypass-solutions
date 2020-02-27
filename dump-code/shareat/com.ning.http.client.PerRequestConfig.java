package com.ning.http.client;

public class PerRequestConfig {
    private final ProxyServer proxyServer;
    private int requestTimeoutInMs;

    public PerRequestConfig() {
        this(null, 0);
    }

    public PerRequestConfig(ProxyServer proxyServer2, int requestTimeoutInMs2) {
        this.proxyServer = proxyServer2;
        this.requestTimeoutInMs = requestTimeoutInMs2;
    }

    public ProxyServer getProxyServer() {
        return this.proxyServer;
    }

    public int getRequestTimeoutInMs() {
        return this.requestTimeoutInMs;
    }

    public void setRequestTimeoutInMs(int requestTimeoutInMs2) {
        this.requestTimeoutInMs = requestTimeoutInMs2;
    }
}