package com.ning.http.client;

import com.ning.http.client.cookie.Cookie;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.util.Collection;
import java.util.List;

public interface Request {

    public interface EntityWriter {
        void writeEntity(OutputStream outputStream) throws IOException;
    }

    String getBodyEncoding();

    BodyGenerator getBodyGenerator();

    byte[] getByteData();

    ConnectionPoolKeyStrategy getConnectionPoolKeyStrategy();

    long getContentLength();

    Collection<Cookie> getCookies();

    EntityWriter getEntityWriter();

    File getFile();

    FluentCaseInsensitiveStringsMap getHeaders();

    InetAddress getInetAddress();

    long getLength();

    InetAddress getLocalAddress();

    String getMethod();

    URI getOriginalURI();

    FluentStringsMap getParams();

    List<Part> getParts();

    PerRequestConfig getPerRequestConfig();

    ProxyServer getProxyServer();

    FluentStringsMap getQueryParams();

    long getRangeOffset();

    URI getRawURI();

    String getRawUrl();

    Realm getRealm();

    String getReqType();

    InputStream getStreamData();

    String getStringData();

    URI getURI();

    String getUrl();

    String getVirtualHost();

    boolean isRedirectEnabled();

    boolean isRedirectOverrideSet();

    boolean isUseRawUrl();
}