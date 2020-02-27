package com.ning.http.client;

import com.ning.http.client.Request.EntityWriter;
import com.ning.http.client.RequestBuilderBase;
import com.ning.http.client.cookie.Cookie;
import com.ning.http.util.AsyncHttpProviderUtils;
import com.ning.http.util.MiscUtil;
import com.ning.http.util.UTF8UrlEncoder;
import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class RequestBuilderBase<T extends RequestBuilderBase<T>> {
    /* access modifiers changed from: private */
    public static final URI DEFAULT_REQUEST_URL = URI.create("http://localhost");
    /* access modifiers changed from: private */
    public static final Logger logger = LoggerFactory.getLogger(RequestBuilderBase.class);
    private final Class<T> derived;
    protected final RequestImpl request;
    protected boolean useRawUrl = false;

    private static final class RequestImpl implements Request {
        /* access modifiers changed from: private */
        public InetAddress address;
        /* access modifiers changed from: private */
        public BodyGenerator bodyGenerator;
        /* access modifiers changed from: private */
        public byte[] byteData;
        public String charset;
        /* access modifiers changed from: private */
        public ConnectionPoolKeyStrategy connectionPoolKeyStrategy = DefaultConnectionPoolStrategy.INSTANCE;
        /* access modifiers changed from: private */
        public Collection<Cookie> cookies = new ArrayList();
        /* access modifiers changed from: private */
        public EntityWriter entityWriter;
        /* access modifiers changed from: private */
        public File file;
        /* access modifiers changed from: private */
        public Boolean followRedirects;
        /* access modifiers changed from: private */
        public FluentCaseInsensitiveStringsMap headers = new FluentCaseInsensitiveStringsMap();
        /* access modifiers changed from: private */
        public long length = -1;
        /* access modifiers changed from: private */
        public InetAddress localAddress;
        /* access modifiers changed from: private */
        public String method;
        /* access modifiers changed from: private */
        public URI originalUri;
        /* access modifiers changed from: private */
        public FluentStringsMap params;
        /* access modifiers changed from: private */
        public List<Part> parts;
        /* access modifiers changed from: private */
        public PerRequestConfig perRequestConfig;
        public ProxyServer proxyServer;
        public FluentStringsMap queryParams;
        /* access modifiers changed from: private */
        public long rangeOffset;
        /* access modifiers changed from: private */
        public URI rawUri;
        /* access modifiers changed from: private */
        public Realm realm;
        /* access modifiers changed from: private */
        public InputStream streamData;
        /* access modifiers changed from: private */
        public String stringData;
        /* access modifiers changed from: private */
        public URI uri;
        private boolean useRawUrl;
        /* access modifiers changed from: private */
        public String virtualHost;

        public RequestImpl(boolean useRawUrl2) {
            this.useRawUrl = useRawUrl2;
        }

        public RequestImpl(Request prototype) {
            Boolean bool = null;
            if (prototype != null) {
                this.method = prototype.getMethod();
                this.originalUri = prototype.getOriginalURI();
                this.address = prototype.getInetAddress();
                this.localAddress = prototype.getLocalAddress();
                this.headers = new FluentCaseInsensitiveStringsMap(prototype.getHeaders());
                this.cookies = new ArrayList(prototype.getCookies());
                this.byteData = prototype.getByteData();
                this.stringData = prototype.getStringData();
                this.streamData = prototype.getStreamData();
                this.entityWriter = prototype.getEntityWriter();
                this.bodyGenerator = prototype.getBodyGenerator();
                this.params = prototype.getParams() == null ? null : new FluentStringsMap(prototype.getParams());
                this.queryParams = prototype.getQueryParams() == null ? null : new FluentStringsMap(prototype.getQueryParams());
                this.parts = prototype.getParts() == null ? null : new ArrayList(prototype.getParts());
                this.virtualHost = prototype.getVirtualHost();
                this.length = prototype.getContentLength();
                this.proxyServer = prototype.getProxyServer();
                this.realm = prototype.getRealm();
                this.file = prototype.getFile();
                this.followRedirects = prototype.isRedirectOverrideSet() ? Boolean.valueOf(prototype.isRedirectEnabled()) : bool;
                this.perRequestConfig = prototype.getPerRequestConfig();
                this.rangeOffset = prototype.getRangeOffset();
                this.charset = prototype.getBodyEncoding();
                this.useRawUrl = prototype.isUseRawUrl();
                this.connectionPoolKeyStrategy = prototype.getConnectionPoolKeyStrategy();
            }
        }

        public String getReqType() {
            return getMethod();
        }

        public String getMethod() {
            return this.method;
        }

        public InetAddress getInetAddress() {
            return this.address;
        }

        public InetAddress getLocalAddress() {
            return this.localAddress;
        }

        private String removeTrailingSlash(URI uri2) {
            String uriString = uri2.toString();
            if (uriString.endsWith("/")) {
                return uriString.substring(0, uriString.length() - 1);
            }
            return uriString;
        }

        public String getUrl() {
            return removeTrailingSlash(getURI());
        }

        public String getRawUrl() {
            return removeTrailingSlash(getRawURI());
        }

        public URI getOriginalURI() {
            return this.originalUri;
        }

        public URI getURI() {
            if (this.uri == null) {
                this.uri = toURI(true);
            }
            return this.uri;
        }

        public URI getRawURI() {
            if (this.rawUri == null) {
                this.rawUri = toURI(false);
            }
            return this.rawUri;
        }

        private URI toURI(boolean encode) {
            if (this.originalUri == null) {
                RequestBuilderBase.logger.debug("setUrl hasn't been invoked. Using http://localhost");
                this.originalUri = RequestBuilderBase.DEFAULT_REQUEST_URL;
            }
            AsyncHttpProviderUtils.validateSupportedScheme(this.originalUri);
            StringBuilder builder = new StringBuilder();
            builder.append(this.originalUri.getScheme()).append("://").append(this.originalUri.getAuthority());
            if (MiscUtil.isNonEmpty(this.originalUri.getRawPath())) {
                builder.append(this.originalUri.getRawPath());
            } else {
                builder.append("/");
            }
            if (MiscUtil.isNonEmpty((Map<?, ?>) this.queryParams)) {
                builder.append("?");
                Iterator<Entry<String, List<String>>> i = this.queryParams.iterator();
                while (i.hasNext()) {
                    Entry<String, List<String>> param = i.next();
                    String name = param.getKey();
                    Iterator<String> j = param.getValue().iterator();
                    while (j.hasNext()) {
                        String value = j.next();
                        if (encode) {
                            UTF8UrlEncoder.appendEncoded(builder, name);
                        } else {
                            builder.append(name);
                        }
                        if (value != null) {
                            builder.append('=');
                            if (encode) {
                                UTF8UrlEncoder.appendEncoded(builder, value);
                            } else {
                                builder.append(value);
                            }
                        }
                        if (j.hasNext()) {
                            builder.append('&');
                        }
                    }
                    if (i.hasNext()) {
                        builder.append('&');
                    }
                }
            }
            return URI.create(builder.toString());
        }

        public FluentCaseInsensitiveStringsMap getHeaders() {
            return this.headers;
        }

        public Collection<Cookie> getCookies() {
            return Collections.unmodifiableCollection(this.cookies);
        }

        public byte[] getByteData() {
            return this.byteData;
        }

        public String getStringData() {
            return this.stringData;
        }

        public InputStream getStreamData() {
            return this.streamData;
        }

        public EntityWriter getEntityWriter() {
            return this.entityWriter;
        }

        public BodyGenerator getBodyGenerator() {
            return this.bodyGenerator;
        }

        public long getLength() {
            return this.length;
        }

        public long getContentLength() {
            return this.length;
        }

        public FluentStringsMap getParams() {
            return this.params;
        }

        public List<Part> getParts() {
            return this.parts;
        }

        public String getVirtualHost() {
            return this.virtualHost;
        }

        public FluentStringsMap getQueryParams() {
            return this.queryParams;
        }

        public ProxyServer getProxyServer() {
            return this.proxyServer;
        }

        public Realm getRealm() {
            return this.realm;
        }

        public File getFile() {
            return this.file;
        }

        public boolean isRedirectEnabled() {
            return this.followRedirects != null && this.followRedirects.booleanValue();
        }

        public boolean isRedirectOverrideSet() {
            return this.followRedirects != null;
        }

        public PerRequestConfig getPerRequestConfig() {
            return this.perRequestConfig;
        }

        public long getRangeOffset() {
            return this.rangeOffset;
        }

        public String getBodyEncoding() {
            return this.charset;
        }

        public ConnectionPoolKeyStrategy getConnectionPoolKeyStrategy() {
            return this.connectionPoolKeyStrategy;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder(getURI().toString());
            sb.append("\t");
            sb.append(this.method);
            sb.append("\theaders:");
            if (MiscUtil.isNonEmpty((Map<?, ?>) this.headers)) {
                for (String name : this.headers.keySet()) {
                    sb.append("\t");
                    sb.append(name);
                    sb.append(":");
                    sb.append(this.headers.getJoinedValue(name, ", "));
                }
            }
            if (MiscUtil.isNonEmpty((Map<?, ?>) this.params)) {
                sb.append("\tparams:");
                for (String name2 : this.params.keySet()) {
                    sb.append("\t");
                    sb.append(name2);
                    sb.append(":");
                    sb.append(this.params.getJoinedValue(name2, ", "));
                }
            }
            return sb.toString();
        }

        public boolean isUseRawUrl() {
            return this.useRawUrl;
        }
    }

    protected RequestBuilderBase(Class<T> derived2, String method, boolean rawUrls) {
        this.derived = derived2;
        this.request = new RequestImpl(rawUrls);
        this.request.method = method;
        this.useRawUrl = rawUrls;
    }

    protected RequestBuilderBase(Class<T> derived2, Request prototype) {
        this.derived = derived2;
        this.request = new RequestImpl(prototype);
        this.useRawUrl = prototype.isUseRawUrl();
    }

    public T setUrl(String url) {
        return setURI(URI.create(url));
    }

    public T setURI(URI uri) {
        if (uri.getPath() == null) {
            throw new IllegalArgumentException("Unsupported uri format: " + uri);
        }
        this.request.originalUri = uri;
        addQueryParameters(this.request.originalUri);
        this.request.uri = null;
        this.request.rawUri = null;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setInetAddress(InetAddress address) {
        this.request.address = address;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setLocalInetAddress(InetAddress address) {
        this.request.localAddress = address;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    private void addQueryParameters(URI uri) {
        String[] arr$;
        if (MiscUtil.isNonEmpty(uri.getRawQuery())) {
            for (String query : uri.getRawQuery().split("&")) {
                int pos = query.indexOf("=");
                if (pos <= 0) {
                    addQueryParameter(query, null);
                } else {
                    try {
                        if (this.useRawUrl) {
                            addQueryParameter(query.substring(0, pos), query.substring(pos + 1));
                        } else {
                            addQueryParameter(URLDecoder.decode(query.substring(0, pos), "UTF-8"), URLDecoder.decode(query.substring(pos + 1), "UTF-8"));
                        }
                    } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
    }

    public T setVirtualHost(String virtualHost) {
        this.request.virtualHost = virtualHost;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setHeader(String name, String value) {
        this.request.headers.replace(name, value);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T addHeader(String name, String value) {
        if (value == null) {
            logger.warn("Value was null, set to \"\"");
            value = "";
        }
        this.request.headers.add(name, value);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setHeaders(FluentCaseInsensitiveStringsMap headers) {
        this.request.headers = headers == null ? new FluentCaseInsensitiveStringsMap() : new FluentCaseInsensitiveStringsMap(headers);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setHeaders(Map<String, Collection<String>> headers) {
        this.request.headers = headers == null ? new FluentCaseInsensitiveStringsMap() : new FluentCaseInsensitiveStringsMap(headers);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setContentLength(int length) {
        this.request.length = (long) length;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T addCookie(Cookie cookie) {
        this.request.cookies.add(cookie);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    private void resetParameters() {
        this.request.params = null;
    }

    private void resetNonMultipartData() {
        this.request.byteData = null;
        this.request.stringData = null;
        this.request.streamData = null;
        this.request.entityWriter = null;
        this.request.length = -1;
    }

    private void resetMultipartData() {
        this.request.parts = null;
    }

    public T setBody(File file) {
        this.request.file = file;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setBody(byte[] data) throws IllegalArgumentException {
        resetParameters();
        resetNonMultipartData();
        resetMultipartData();
        this.request.byteData = data;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setBody(String data) throws IllegalArgumentException {
        resetParameters();
        resetNonMultipartData();
        resetMultipartData();
        this.request.stringData = data;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setBody(InputStream stream) throws IllegalArgumentException {
        resetParameters();
        resetNonMultipartData();
        resetMultipartData();
        this.request.streamData = stream;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setBody(EntityWriter dataWriter) {
        return setBody(dataWriter, -1);
    }

    public T setBody(EntityWriter dataWriter, long length) throws IllegalArgumentException {
        resetParameters();
        resetNonMultipartData();
        resetMultipartData();
        this.request.entityWriter = dataWriter;
        this.request.length = length;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setBody(BodyGenerator bodyGenerator) {
        this.request.bodyGenerator = bodyGenerator;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T addQueryParameter(String name, String value) {
        if (this.request.queryParams == null) {
            this.request.queryParams = new FluentStringsMap();
        }
        this.request.queryParams.add(name, value);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setQueryParameters(FluentStringsMap parameters) {
        if (parameters == null) {
            this.request.queryParams = null;
        } else {
            this.request.queryParams = new FluentStringsMap(parameters);
        }
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T addParameter(String key, String value) throws IllegalArgumentException {
        resetNonMultipartData();
        resetMultipartData();
        if (this.request.params == null) {
            this.request.params = new FluentStringsMap();
        }
        this.request.params.add(key, value);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setParameters(FluentStringsMap parameters) throws IllegalArgumentException {
        resetNonMultipartData();
        resetMultipartData();
        this.request.params = new FluentStringsMap(parameters);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setParameters(Map<String, Collection<String>> parameters) throws IllegalArgumentException {
        resetNonMultipartData();
        resetMultipartData();
        this.request.params = new FluentStringsMap(parameters);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T addBodyPart(Part part) throws IllegalArgumentException {
        resetParameters();
        resetNonMultipartData();
        if (this.request.parts == null) {
            this.request.parts = new ArrayList();
        }
        this.request.parts.add(part);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setProxyServer(ProxyServer proxyServer) {
        this.request.proxyServer = proxyServer;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setRealm(Realm realm) {
        this.request.realm = realm;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setFollowRedirects(boolean followRedirects) {
        this.request.followRedirects = Boolean.valueOf(followRedirects);
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setPerRequestConfig(PerRequestConfig perRequestConfig) {
        this.request.perRequestConfig = perRequestConfig;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setRangeOffset(long rangeOffset) {
        this.request.rangeOffset = rangeOffset;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setMethod(String method) {
        this.request.method = method;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setBodyEncoding(String charset) {
        this.request.charset = charset;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public T setConnectionPoolKeyStrategy(ConnectionPoolKeyStrategy connectionPoolKeyStrategy) {
        this.request.connectionPoolKeyStrategy = connectionPoolKeyStrategy;
        return (RequestBuilderBase) this.derived.cast(this);
    }

    public Request build() {
        if (this.request.length < 0 && this.request.streamData == null) {
            String contentLength = this.request.headers.getFirstValue("Content-Length");
            if (contentLength != null) {
                try {
                    this.request.length = Long.parseLong(contentLength);
                } catch (NumberFormatException e) {
                }
            }
        }
        return this.request;
    }

    public T addOrReplaceCookie(Cookie cookie) {
        String cookieKey = cookie.getName();
        boolean replace = false;
        int index = 0;
        Iterator i$ = this.request.cookies.iterator();
        while (true) {
            if (!i$.hasNext()) {
                break;
            } else if (((Cookie) i$.next()).getName().equals(cookieKey)) {
                replace = true;
                break;
            } else {
                index++;
            }
        }
        if (replace) {
            ((ArrayList) this.request.cookies).set(index, cookie);
        } else {
            this.request.cookies.add(cookie);
        }
        return (RequestBuilderBase) this.derived.cast(this);
    }
}