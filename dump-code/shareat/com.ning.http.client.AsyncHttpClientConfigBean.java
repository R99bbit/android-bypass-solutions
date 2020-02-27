package com.ning.http.client;

import com.ning.http.client.filter.IOExceptionFilter;
import com.ning.http.client.filter.RequestFilter;
import com.ning.http.client.filter.ResponseFilter;
import com.ning.http.util.ProxyUtils;
import java.util.LinkedList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

public class AsyncHttpClientConfigBean extends AsyncHttpClientConfig {
    public AsyncHttpClientConfigBean() {
        configureExecutors();
        configureDefaults();
        configureFilters();
    }

    /* access modifiers changed from: 0000 */
    public void configureFilters() {
        this.requestFilters = new LinkedList();
        this.responseFilters = new LinkedList();
        this.ioExceptionFilters = new LinkedList();
    }

    /* access modifiers changed from: 0000 */
    public void configureDefaults() {
        this.maxTotalConnections = Integer.getInteger(ASYNC_CLIENT + "defaultMaxTotalConnections", -1).intValue();
        this.maxConnectionPerHost = Integer.getInteger(ASYNC_CLIENT + "defaultMaxConnectionsPerHost", -1).intValue();
        this.connectionTimeOutInMs = Integer.getInteger(ASYNC_CLIENT + "defaultConnectionTimeoutInMS", 60000).intValue();
        this.idleConnectionInPoolTimeoutInMs = Integer.getInteger(ASYNC_CLIENT + "defaultIdleConnectionInPoolTimeoutInMS", 60000).intValue();
        this.idleConnectionTimeoutInMs = Integer.getInteger(ASYNC_CLIENT + "defaultIdleConnectionTimeoutInMS", 60000).intValue();
        this.requestTimeoutInMs = Integer.getInteger(ASYNC_CLIENT + "defaultRequestTimeoutInMS", 60000).intValue();
        this.redirectEnabled = Boolean.getBoolean(ASYNC_CLIENT + "defaultRedirectsEnabled");
        this.maxDefaultRedirects = Integer.getInteger(ASYNC_CLIENT + "defaultMaxRedirects", 5).intValue();
        this.compressionEnabled = Boolean.getBoolean(ASYNC_CLIENT + "compressionEnabled");
        this.userAgent = System.getProperty(ASYNC_CLIENT + "userAgent", "NING/1.0");
        this.ioThreadMultiplier = Integer.getInteger(ASYNC_CLIENT + "ioThreadMultiplier", 2).intValue();
        boolean useProxySelector = Boolean.getBoolean(ASYNC_CLIENT + "useProxySelector");
        boolean useProxyProperties = Boolean.getBoolean(ASYNC_CLIENT + "useProxyProperties");
        if (useProxySelector) {
            this.proxyServerSelector = ProxyUtils.getJdkDefaultProxyServerSelector();
        } else if (useProxyProperties) {
            this.proxyServerSelector = ProxyUtils.createProxyServerSelector(System.getProperties());
        }
        this.allowPoolingConnection = true;
        this.requestCompressionLevel = -1;
        this.maxRequestRetry = 5;
        this.allowSslConnectionPool = true;
        this.useRawUrl = false;
        this.removeQueryParamOnRedirect = true;
        this.hostnameVerifier = new HostnameVerifier() {
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }
        };
    }

    /* access modifiers changed from: 0000 */
    public void configureExecutors() {
        this.applicationThreadPool = Executors.newCachedThreadPool(new ThreadFactory() {
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "AsyncHttpClient-Callback");
                t.setDaemon(true);
                return t;
            }
        });
    }

    public AsyncHttpClientConfigBean setMaxTotalConnections(int maxTotalConnections) {
        this.maxTotalConnections = maxTotalConnections;
        return this;
    }

    public AsyncHttpClientConfigBean setMaxConnectionPerHost(int maxConnectionPerHost) {
        this.maxConnectionPerHost = maxConnectionPerHost;
        return this;
    }

    public AsyncHttpClientConfigBean setConnectionTimeOutInMs(int connectionTimeOutInMs) {
        this.connectionTimeOutInMs = connectionTimeOutInMs;
        return this;
    }

    public AsyncHttpClientConfigBean setIdleConnectionInPoolTimeoutInMs(int idleConnectionInPoolTimeoutInMs) {
        this.idleConnectionInPoolTimeoutInMs = idleConnectionInPoolTimeoutInMs;
        return this;
    }

    public AsyncHttpClientConfigBean setIdleConnectionTimeoutInMs(int idleConnectionTimeoutInMs) {
        this.idleConnectionTimeoutInMs = idleConnectionTimeoutInMs;
        return this;
    }

    public AsyncHttpClientConfigBean setRequestTimeoutInMs(int requestTimeoutInMs) {
        this.requestTimeoutInMs = requestTimeoutInMs;
        return this;
    }

    public AsyncHttpClientConfigBean setRedirectEnabled(boolean redirectEnabled) {
        this.redirectEnabled = redirectEnabled;
        return this;
    }

    public AsyncHttpClientConfigBean setMaxDefaultRedirects(int maxDefaultRedirects) {
        this.maxDefaultRedirects = maxDefaultRedirects;
        return this;
    }

    public AsyncHttpClientConfigBean setCompressionEnabled(boolean compressionEnabled) {
        this.compressionEnabled = compressionEnabled;
        return this;
    }

    public AsyncHttpClientConfigBean setUserAgent(String userAgent) {
        this.userAgent = userAgent;
        return this;
    }

    public AsyncHttpClientConfigBean setAllowPoolingConnection(boolean allowPoolingConnection) {
        this.allowPoolingConnection = allowPoolingConnection;
        return this;
    }

    public AsyncHttpClientConfigBean setApplicationThreadPool(ExecutorService applicationThreadPool) {
        if (this.applicationThreadPool != null) {
            this.applicationThreadPool.shutdownNow();
        }
        this.applicationThreadPool = applicationThreadPool;
        return this;
    }

    public AsyncHttpClientConfigBean setProxyServer(ProxyServer proxyServer) {
        this.proxyServerSelector = ProxyUtils.createProxyServerSelector(proxyServer);
        return this;
    }

    public AsyncHttpClientConfigBean setProxyServerSelector(ProxyServerSelector proxyServerSelector) {
        this.proxyServerSelector = proxyServerSelector;
        return this;
    }

    public AsyncHttpClientConfigBean setSslContext(SSLContext sslContext) {
        this.sslContext = sslContext;
        return this;
    }

    public AsyncHttpClientConfigBean setSslEngineFactory(SSLEngineFactory sslEngineFactory) {
        this.sslEngineFactory = sslEngineFactory;
        return this;
    }

    public AsyncHttpClientConfigBean setProviderConfig(AsyncHttpProviderConfig<?, ?> providerConfig) {
        this.providerConfig = providerConfig;
        return this;
    }

    public AsyncHttpClientConfigBean setConnectionsPool(ConnectionsPool<?, ?> connectionsPool) {
        this.connectionsPool = connectionsPool;
        return this;
    }

    public AsyncHttpClientConfigBean setRealm(Realm realm) {
        this.realm = realm;
        return this;
    }

    public AsyncHttpClientConfigBean addRequestFilter(RequestFilter requestFilter) {
        this.requestFilters.add(requestFilter);
        return this;
    }

    public AsyncHttpClientConfigBean addResponseFilters(ResponseFilter responseFilter) {
        this.responseFilters.add(responseFilter);
        return this;
    }

    public AsyncHttpClientConfigBean addIoExceptionFilters(IOExceptionFilter ioExceptionFilter) {
        this.ioExceptionFilters.add(ioExceptionFilter);
        return this;
    }

    public AsyncHttpClientConfigBean setRequestCompressionLevel(int requestCompressionLevel) {
        this.requestCompressionLevel = requestCompressionLevel;
        return this;
    }

    public AsyncHttpClientConfigBean setMaxRequestRetry(int maxRequestRetry) {
        this.maxRequestRetry = maxRequestRetry;
        return this;
    }

    public AsyncHttpClientConfigBean setAllowSslConnectionPool(boolean allowSslConnectionPool) {
        this.allowSslConnectionPool = allowSslConnectionPool;
        return this;
    }

    public AsyncHttpClientConfigBean setUseRawUrl(boolean useRawUrl) {
        this.useRawUrl = useRawUrl;
        return this;
    }

    public AsyncHttpClientConfigBean setRemoveQueryParamOnRedirect(boolean removeQueryParamOnRedirect) {
        this.removeQueryParamOnRedirect = removeQueryParamOnRedirect;
        return this;
    }

    public AsyncHttpClientConfigBean setHostnameVerifier(HostnameVerifier hostnameVerifier) {
        this.hostnameVerifier = hostnameVerifier;
        return this;
    }

    public AsyncHttpClientConfigBean setIoThreadMultiplier(int ioThreadMultiplier) {
        this.ioThreadMultiplier = ioThreadMultiplier;
        return this;
    }
}