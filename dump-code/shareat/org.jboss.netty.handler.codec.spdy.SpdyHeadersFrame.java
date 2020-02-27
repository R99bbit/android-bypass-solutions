package org.jboss.netty.handler.codec.spdy;

import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

public interface SpdyHeadersFrame extends SpdyStreamFrame {
    @Deprecated
    void addHeader(String str, Object obj);

    @Deprecated
    void clearHeaders();

    @Deprecated
    boolean containsHeader(String str);

    @Deprecated
    String getHeader(String str);

    @Deprecated
    Set<String> getHeaderNames();

    @Deprecated
    List<Entry<String, String>> getHeaders();

    @Deprecated
    List<String> getHeaders(String str);

    SpdyHeaders headers();

    boolean isInvalid();

    boolean isTruncated();

    @Deprecated
    void removeHeader(String str);

    @Deprecated
    void setHeader(String str, Iterable<?> iterable);

    @Deprecated
    void setHeader(String str, Object obj);

    void setInvalid();

    void setTruncated();
}