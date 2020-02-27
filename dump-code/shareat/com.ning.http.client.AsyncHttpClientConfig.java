package com.ning.http.client;

import com.ning.http.client.date.TimeConverter;
import com.ning.http.client.filter.IOExceptionFilter;
import com.ning.http.client.filter.RequestFilter;
import com.ning.http.client.filter.ResponseFilter;
import com.ning.http.util.AllowAllHostnameVerifier;
import com.ning.http.util.ProxyUtils;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

public class AsyncHttpClientConfig {
    protected static final String ASYNC_CLIENT = (AsyncHttpClientConfig.class.getName() + ".");
    protected boolean allowPoolingConnection;
    protected boolean allowSslConnectionPool;
    protected ExecutorService applicationThreadPool;
    protected boolean compressionEnabled;
    protected int connectionTimeOutInMs;
    protected ConnectionsPool<?, ?> connectionsPool;
    protected HostnameVerifier hostnameVerifier;
    protected int idleConnectionInPoolTimeoutInMs;
    protected int idleConnectionTimeoutInMs;
    protected List<IOExceptionFilter> ioExceptionFilters;
    protected int ioThreadMultiplier;
    protected int maxConnectionLifeTimeInMs;
    protected int maxConnectionPerHost;
    protected int maxDefaultRedirects;
    protected int maxRequestRetry;
    protected int maxTotalConnections;
    protected AsyncHttpProviderConfig<?, ?> providerConfig;
    protected ProxyServerSelector proxyServerSelector;
    protected Realm realm;
    protected boolean redirectEnabled;
    protected boolean removeQueryParamOnRedirect;
    protected int requestCompressionLevel;
    protected List<RequestFilter> requestFilters;
    protected int requestTimeoutInMs;
    protected List<ResponseFilter> responseFilters;
    protected SSLContext sslContext;
    protected SSLEngineFactory sslEngineFactory;
    protected boolean strict302Handling;
    protected TimeConverter timeConverter;
    protected boolean useRawUrl;
    protected boolean useRelativeURIsWithSSLProxies;
    protected String userAgent;
    protected int webSocketIdleTimeoutInMs;

    public static class Builder {
        private boolean allowPoolingConnection = true;
        private boolean allowSslConnectionPool = true;
        private ExecutorService applicationThreadPool;
        private boolean compressionEnabled = Boolean.getBoolean(AsyncHttpClientConfig.ASYNC_CLIENT + "compressionEnabled");
        private ConnectionsPool<?, ?> connectionsPool;
        private int defaultConnectionTimeOutInMs = Integer.getInteger(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultConnectionTimeoutInMS", 60000).intValue();
        private int defaultIdleConnectionInPoolTimeoutInMs = Integer.getInteger(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultIdleConnectionInPoolTimeoutInMS", 60000).intValue();
        private int defaultIdleConnectionTimeoutInMs = Integer.getInteger(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultIdleConnectionTimeoutInMS", 60000).intValue();
        private int defaultMaxConnectionLifeTimeInMs = Integer.getInteger(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultMaxConnectionLifeTimeInMs", -1).intValue();
        private int defaultMaxConnectionPerHost = Integer.getInteger(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultMaxConnectionsPerHost", -1).intValue();
        private int defaultMaxTotalConnections = Integer.getInteger(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultMaxTotalConnections", -1).intValue();
        private int defaultRequestTimeoutInMs = Integer.getInteger(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultRequestTimeoutInMS", 60000).intValue();
        private int defaultWebsocketIdleTimeoutInMs = Integer.getInteger(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultWebsocketTimoutInMS", 900000).intValue();
        private HostnameVerifier hostnameVerifier = new AllowAllHostnameVerifier();
        private final List<IOExceptionFilter> ioExceptionFilters = new LinkedList();
        private int ioThreadMultiplier = 2;
        private int maxDefaultRedirects = Integer.getInteger(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultMaxRedirects", 5).intValue();
        private int maxRequestRetry = 5;
        private AsyncHttpProviderConfig<?, ?> providerConfig;
        private ProxyServerSelector proxyServerSelector = null;
        private Realm realm;
        private boolean redirectEnabled = Boolean.getBoolean(AsyncHttpClientConfig.ASYNC_CLIENT + "defaultRedirectsEnabled");
        private boolean removeQueryParamOnRedirect = true;
        private int requestCompressionLevel = -1;
        private final List<RequestFilter> requestFilters = new LinkedList();
        private final List<ResponseFilter> responseFilters = new LinkedList();
        private SSLContext sslContext;
        private SSLEngineFactory sslEngineFactory;
        private boolean strict302Handling;
        private TimeConverter timeConverter;
        private boolean useProxyProperties = Boolean.getBoolean(AsyncHttpClientConfig.ASYNC_CLIENT + "useProxyProperties");
        private boolean useProxySelector = Boolean.getBoolean(AsyncHttpClientConfig.ASYNC_CLIENT + "useProxySelector");
        private boolean useRawUrl = false;
        private boolean useRelativeURIsWithSSLProxies = Boolean.getBoolean(AsyncHttpClientConfig.ASYNC_CLIENT + "useRelativeURIsWithSSLProxies");
        private String userAgent = System.getProperty(AsyncHttpClientConfig.ASYNC_CLIENT + "userAgent", "NING/1.0");

        public Builder() {
        }

        public Builder setMaximumConnectionsTotal(int defaultMaxTotalConnections2) {
            this.defaultMaxTotalConnections = defaultMaxTotalConnections2;
            return this;
        }

        public Builder setMaximumConnectionsPerHost(int defaultMaxConnectionPerHost2) {
            this.defaultMaxConnectionPerHost = defaultMaxConnectionPerHost2;
            return this;
        }

        public Builder setConnectionTimeoutInMs(int defaultConnectionTimeOutInMs2) {
            this.defaultConnectionTimeOutInMs = defaultConnectionTimeOutInMs2;
            return this;
        }

        public Builder setWebSocketIdleTimeoutInMs(int defaultWebSocketIdleTimeoutInMs) {
            this.defaultWebsocketIdleTimeoutInMs = defaultWebSocketIdleTimeoutInMs;
            return this;
        }

        public Builder setIdleConnectionTimeoutInMs(int defaultIdleConnectionTimeoutInMs2) {
            this.defaultIdleConnectionTimeoutInMs = defaultIdleConnectionTimeoutInMs2;
            return this;
        }

        public Builder setIdleConnectionInPoolTimeoutInMs(int defaultIdleConnectionInPoolTimeoutInMs2) {
            this.defaultIdleConnectionInPoolTimeoutInMs = defaultIdleConnectionInPoolTimeoutInMs2;
            return this;
        }

        public Builder setRequestTimeoutInMs(int defaultRequestTimeoutInMs2) {
            this.defaultRequestTimeoutInMs = defaultRequestTimeoutInMs2;
            return this;
        }

        public Builder setFollowRedirects(boolean redirectEnabled2) {
            this.redirectEnabled = redirectEnabled2;
            return this;
        }

        public Builder setMaximumNumberOfRedirects(int maxDefaultRedirects2) {
            this.maxDefaultRedirects = maxDefaultRedirects2;
            return this;
        }

        public Builder setCompressionEnabled(boolean compressionEnabled2) {
            this.compressionEnabled = compressionEnabled2;
            return this;
        }

        public Builder setUserAgent(String userAgent2) {
            this.userAgent = userAgent2;
            return this;
        }

        public Builder setAllowPoolingConnection(boolean allowPoolingConnection2) {
            this.allowPoolingConnection = allowPoolingConnection2;
            return this;
        }

        public Builder setKeepAlive(boolean allowPoolingConnection2) {
            this.allowPoolingConnection = allowPoolingConnection2;
            return this;
        }

        public Builder setExecutorService(ExecutorService applicationThreadPool2) {
            this.applicationThreadPool = applicationThreadPool2;
            return this;
        }

        public Builder setProxyServerSelector(ProxyServerSelector proxyServerSelector2) {
            this.proxyServerSelector = proxyServerSelector2;
            return this;
        }

        public Builder setProxyServer(ProxyServer proxyServer) {
            this.proxyServerSelector = ProxyUtils.createProxyServerSelector(proxyServer);
            return this;
        }

        public Builder setSSLEngineFactory(SSLEngineFactory sslEngineFactory2) {
            this.sslEngineFactory = sslEngineFactory2;
            return this;
        }

        public Builder setSSLContext(final SSLContext sslContext2) {
            this.sslEngineFactory = new SSLEngineFactory() {
                public SSLEngine newSSLEngine() throws GeneralSecurityException {
                    SSLEngine sslEngine = sslContext2.createSSLEngine();
                    sslEngine.setUseClientMode(true);
                    return sslEngine;
                }
            };
            this.sslContext = sslContext2;
            return this;
        }

        public Builder setAsyncHttpClientProviderConfig(AsyncHttpProviderConfig<?, ?> providerConfig2) {
            this.providerConfig = providerConfig2;
            return this;
        }

        public Builder setConnectionsPool(ConnectionsPool<?, ?> connectionsPool2) {
            this.connectionsPool = connectionsPool2;
            return this;
        }

        public Builder setRealm(Realm realm2) {
            this.realm = realm2;
            return this;
        }

        public Builder addRequestFilter(RequestFilter requestFilter) {
            this.requestFilters.add(requestFilter);
            return this;
        }

        public Builder removeRequestFilter(RequestFilter requestFilter) {
            this.requestFilters.remove(requestFilter);
            return this;
        }

        public Builder addResponseFilter(ResponseFilter responseFilter) {
            this.responseFilters.add(responseFilter);
            return this;
        }

        public Builder removeResponseFilter(ResponseFilter responseFilter) {
            this.responseFilters.remove(responseFilter);
            return this;
        }

        public Builder addIOExceptionFilter(IOExceptionFilter ioExceptionFilter) {
            this.ioExceptionFilters.add(ioExceptionFilter);
            return this;
        }

        public Builder removeIOExceptionFilter(IOExceptionFilter ioExceptionFilter) {
            this.ioExceptionFilters.remove(ioExceptionFilter);
            return this;
        }

        public int getRequestCompressionLevel() {
            return this.requestCompressionLevel;
        }

        public Builder setRequestCompressionLevel(int requestCompressionLevel2) {
            this.requestCompressionLevel = requestCompressionLevel2;
            return this;
        }

        public Builder setMaxRequestRetry(int maxRequestRetry2) {
            this.maxRequestRetry = maxRequestRetry2;
            return this;
        }

        public Builder setAllowSslConnectionPool(boolean allowSslConnectionPool2) {
            this.allowSslConnectionPool = allowSslConnectionPool2;
            return this;
        }

        public Builder setUseRawUrl(boolean useRawUrl2) {
            this.useRawUrl = useRawUrl2;
            return this;
        }

        public Builder setRemoveQueryParamsOnRedirect(boolean removeQueryParamOnRedirect2) {
            this.removeQueryParamOnRedirect = removeQueryParamOnRedirect2;
            return this;
        }

        public Builder setUseProxySelector(boolean useProxySelector2) {
            this.useProxySelector = useProxySelector2;
            return this;
        }

        public Builder setUseProxyProperties(boolean useProxyProperties2) {
            this.useProxyProperties = useProxyProperties2;
            return this;
        }

        public Builder setIOThreadMultiplier(int multiplier) {
            this.ioThreadMultiplier = multiplier;
            return this;
        }

        public Builder setHostnameVerifier(HostnameVerifier hostnameVerifier2) {
            this.hostnameVerifier = hostnameVerifier2;
            return this;
        }

        public Builder setStrict302Handling(boolean strict302Handling2) {
            this.strict302Handling = strict302Handling2;
            return this;
        }

        public Builder setUseRelativeURIsWithSSLProxies(boolean useRelativeURIsWithSSLProxies2) {
            this.useRelativeURIsWithSSLProxies = useRelativeURIsWithSSLProxies2;
            return this;
        }

        public Builder setMaxConnectionLifeTimeInMs(int maxConnectionLifeTimeInMs) {
            this.defaultMaxConnectionLifeTimeInMs = maxConnectionLifeTimeInMs;
            return this;
        }

        public Builder setTimeConverter(TimeConverter timeConverter2) {
            this.timeConverter = timeConverter2;
            return this;
        }

        public Builder(AsyncHttpClientConfig prototype) {
            this.allowPoolingConnection = prototype.getAllowPoolingConnection();
            this.providerConfig = prototype.getAsyncHttpProviderConfig();
            this.connectionsPool = prototype.getConnectionsPool();
            this.defaultConnectionTimeOutInMs = prototype.getConnectionTimeoutInMs();
            this.defaultIdleConnectionInPoolTimeoutInMs = prototype.getIdleConnectionInPoolTimeoutInMs();
            this.defaultIdleConnectionTimeoutInMs = prototype.getIdleConnectionTimeoutInMs();
            this.defaultMaxConnectionPerHost = prototype.getMaxConnectionPerHost();
            this.defaultMaxConnectionLifeTimeInMs = prototype.getMaxConnectionLifeTimeInMs();
            this.maxDefaultRedirects = prototype.getMaxRedirects();
            this.defaultMaxTotalConnections = prototype.getMaxTotalConnections();
            this.proxyServerSelector = prototype.getProxyServerSelector();
            this.realm = prototype.getRealm();
            this.defaultRequestTimeoutInMs = prototype.getRequestTimeoutInMs();
            this.sslContext = prototype.getSSLContext();
            this.sslEngineFactory = prototype.getSSLEngineFactory();
            this.userAgent = prototype.getUserAgent();
            this.redirectEnabled = prototype.isRedirectEnabled();
            this.compressionEnabled = prototype.isCompressionEnabled();
            this.applicationThreadPool = prototype.executorService();
            this.requestFilters.clear();
            this.responseFilters.clear();
            this.ioExceptionFilters.clear();
            this.requestFilters.addAll(prototype.getRequestFilters());
            this.responseFilters.addAll(prototype.getResponseFilters());
            this.ioExceptionFilters.addAll(prototype.getIOExceptionFilters());
            this.requestCompressionLevel = prototype.getRequestCompressionLevel();
            this.useRawUrl = prototype.isUseRawUrl();
            this.ioThreadMultiplier = prototype.getIoThreadMultiplier();
            this.maxRequestRetry = prototype.getMaxRequestRetry();
            this.allowSslConnectionPool = prototype.getAllowPoolingConnection();
            this.removeQueryParamOnRedirect = prototype.isRemoveQueryParamOnRedirect();
            this.hostnameVerifier = prototype.getHostnameVerifier();
            this.strict302Handling = prototype.isStrict302Handling();
            this.timeConverter = prototype.timeConverter;
        }

        public AsyncHttpClientConfig build() {
            if (this.applicationThreadPool == null) {
                this.applicationThreadPool = Executors.newCachedThreadPool(new ThreadFactory() {
                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r, "AsyncHttpClient-Callback");
                        t.setDaemon(true);
                        return t;
                    }
                });
            }
            if (this.proxyServerSelector == null && this.useProxySelector) {
                this.proxyServerSelector = ProxyUtils.getJdkDefaultProxyServerSelector();
            }
            if (this.proxyServerSelector == null && this.useProxyProperties) {
                this.proxyServerSelector = ProxyUtils.createProxyServerSelector(System.getProperties());
            }
            if (this.proxyServerSelector == null) {
                this.proxyServerSelector = ProxyServerSelector.NO_PROXY_SELECTOR;
            }
            return new AsyncHttpClientConfig(this.defaultMaxTotalConnections, this.defaultMaxConnectionPerHost, this.defaultConnectionTimeOutInMs, this.defaultWebsocketIdleTimeoutInMs, this.defaultIdleConnectionInPoolTimeoutInMs, this.defaultIdleConnectionTimeoutInMs, this.defaultRequestTimeoutInMs, this.defaultMaxConnectionLifeTimeInMs, this.redirectEnabled, this.maxDefaultRedirects, this.compressionEnabled, this.userAgent, this.allowPoolingConnection, this.applicationThreadPool, this.proxyServerSelector, this.sslContext, this.sslEngineFactory, this.providerConfig, this.connectionsPool, this.realm, this.requestFilters, this.responseFilters, this.ioExceptionFilters, this.requestCompressionLevel, this.maxRequestRetry, this.allowSslConnectionPool, this.useRawUrl, this.removeQueryParamOnRedirect, this.hostnameVerifier, this.ioThreadMultiplier, this.strict302Handling, this.useRelativeURIsWithSSLProxies, this.timeConverter);
        }
    }

    protected AsyncHttpClientConfig() {
    }

    private AsyncHttpClientConfig(int maxTotalConnections2, int maxConnectionPerHost2, int connectionTimeOutInMs2, int webSocketTimeoutInMs, int idleConnectionInPoolTimeoutInMs2, int idleConnectionTimeoutInMs2, int requestTimeoutInMs2, int connectionMaxLifeTimeInMs, boolean redirectEnabled2, int maxDefaultRedirects2, boolean compressionEnabled2, String userAgent2, boolean keepAlive, ExecutorService applicationThreadPool2, ProxyServerSelector proxyServerSelector2, SSLContext sslContext2, SSLEngineFactory sslEngineFactory2, AsyncHttpProviderConfig<?, ?> providerConfig2, ConnectionsPool<?, ?> connectionsPool2, Realm realm2, List<RequestFilter> requestFilters2, List<ResponseFilter> responseFilters2, List<IOExceptionFilter> ioExceptionFilters2, int requestCompressionLevel2, int maxRequestRetry2, boolean allowSslConnectionCaching, boolean useRawUrl2, boolean removeQueryParamOnRedirect2, HostnameVerifier hostnameVerifier2, int ioThreadMultiplier2, boolean strict302Handling2, boolean useRelativeURIsWithSSLProxies2, TimeConverter timeConverter2) {
        this.maxTotalConnections = maxTotalConnections2;
        this.maxConnectionPerHost = maxConnectionPerHost2;
        this.connectionTimeOutInMs = connectionTimeOutInMs2;
        this.webSocketIdleTimeoutInMs = webSocketTimeoutInMs;
        this.idleConnectionInPoolTimeoutInMs = idleConnectionInPoolTimeoutInMs2;
        this.idleConnectionTimeoutInMs = idleConnectionTimeoutInMs2;
        this.requestTimeoutInMs = requestTimeoutInMs2;
        this.maxConnectionLifeTimeInMs = connectionMaxLifeTimeInMs;
        this.redirectEnabled = redirectEnabled2;
        this.maxDefaultRedirects = maxDefaultRedirects2;
        this.compressionEnabled = compressionEnabled2;
        this.userAgent = userAgent2;
        this.allowPoolingConnection = keepAlive;
        this.sslContext = sslContext2;
        this.sslEngineFactory = sslEngineFactory2;
        this.providerConfig = providerConfig2;
        this.connectionsPool = connectionsPool2;
        this.realm = realm2;
        this.requestFilters = requestFilters2;
        this.responseFilters = responseFilters2;
        this.ioExceptionFilters = ioExceptionFilters2;
        this.requestCompressionLevel = requestCompressionLevel2;
        this.maxRequestRetry = maxRequestRetry2;
        this.allowSslConnectionPool = allowSslConnectionCaching;
        this.removeQueryParamOnRedirect = removeQueryParamOnRedirect2;
        this.hostnameVerifier = hostnameVerifier2;
        this.ioThreadMultiplier = ioThreadMultiplier2;
        this.strict302Handling = strict302Handling2;
        this.useRelativeURIsWithSSLProxies = useRelativeURIsWithSSLProxies2;
        if (applicationThreadPool2 == null) {
            this.applicationThreadPool = Executors.newCachedThreadPool();
        } else {
            this.applicationThreadPool = applicationThreadPool2;
        }
        this.proxyServerSelector = proxyServerSelector2;
        this.useRawUrl = useRawUrl2;
        this.timeConverter = timeConverter2;
    }

    public int getMaxTotalConnections() {
        return this.maxTotalConnections;
    }

    public int getMaxConnectionPerHost() {
        return this.maxConnectionPerHost;
    }

    public int getConnectionTimeoutInMs() {
        return this.connectionTimeOutInMs;
    }

    public int getWebSocketIdleTimeoutInMs() {
        return this.webSocketIdleTimeoutInMs;
    }

    public int getIdleConnectionTimeoutInMs() {
        return this.idleConnectionTimeoutInMs;
    }

    public int getIdleConnectionInPoolTimeoutInMs() {
        return this.idleConnectionInPoolTimeoutInMs;
    }

    public int getRequestTimeoutInMs() {
        return this.requestTimeoutInMs;
    }

    public boolean isRedirectEnabled() {
        return this.redirectEnabled;
    }

    public int getMaxRedirects() {
        return this.maxDefaultRedirects;
    }

    public boolean getAllowPoolingConnection() {
        return this.allowPoolingConnection;
    }

    public boolean getKeepAlive() {
        return this.allowPoolingConnection;
    }

    public String getUserAgent() {
        return this.userAgent;
    }

    public boolean isCompressionEnabled() {
        return this.compressionEnabled;
    }

    public ExecutorService executorService() {
        return this.applicationThreadPool;
    }

    public ProxyServerSelector getProxyServerSelector() {
        return this.proxyServerSelector;
    }

    public SSLContext getSSLContext() {
        return this.sslContext;
    }

    public ConnectionsPool<?, ?> getConnectionsPool() {
        return this.connectionsPool;
    }

    public SSLEngineFactory getSSLEngineFactory() {
        return this.sslEngineFactory == null ? new SSLEngineFactory() {
            public SSLEngine newSSLEngine() {
                if (AsyncHttpClientConfig.this.sslContext == null) {
                    return null;
                }
                SSLEngine sslEngine = AsyncHttpClientConfig.this.sslContext.createSSLEngine();
                sslEngine.setUseClientMode(true);
                return sslEngine;
            }
        } : this.sslEngineFactory;
    }

    public AsyncHttpProviderConfig<?, ?> getAsyncHttpProviderConfig() {
        return this.providerConfig;
    }

    public Realm getRealm() {
        return this.realm;
    }

    public List<RequestFilter> getRequestFilters() {
        return Collections.unmodifiableList(this.requestFilters);
    }

    public List<ResponseFilter> getResponseFilters() {
        return Collections.unmodifiableList(this.responseFilters);
    }

    public List<IOExceptionFilter> getIOExceptionFilters() {
        return Collections.unmodifiableList(this.ioExceptionFilters);
    }

    public int getRequestCompressionLevel() {
        return this.requestCompressionLevel;
    }

    public int getMaxRequestRetry() {
        return this.maxRequestRetry;
    }

    public boolean isSslConnectionPoolEnabled() {
        return this.allowSslConnectionPool;
    }

    public boolean isUseRawUrl() {
        return this.useRawUrl;
    }

    public boolean isRemoveQueryParamOnRedirect() {
        return this.removeQueryParamOnRedirect;
    }

    public boolean isClosed() {
        return !isValid();
    }

    public boolean isValid() {
        boolean atpRunning = true;
        try {
            return this.applicationThreadPool.isShutdown();
        } catch (Exception e) {
            return atpRunning;
        }
    }

    public HostnameVerifier getHostnameVerifier() {
        return this.hostnameVerifier;
    }

    public int getIoThreadMultiplier() {
        return this.ioThreadMultiplier;
    }

    public boolean isStrict302Handling() {
        return this.strict302Handling;
    }

    public boolean isUseRelativeURIsWithSSLProxies() {
        return this.useRelativeURIsWithSSLProxies;
    }

    public int getMaxConnectionLifeTimeInMs() {
        return this.maxConnectionLifeTimeInMs;
    }

    public TimeConverter getTimeConverter() {
        return this.timeConverter;
    }
}