package org.jboss.netty.handler.codec.http;

import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

public interface HttpChunkTrailer extends HttpChunk {
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

    boolean isLast();

    @Deprecated
    void removeHeader(String str);

    @Deprecated
    void setHeader(String str, Iterable<?> iterable);

    @Deprecated
    void setHeader(String str, Object obj);

    HttpHeaders trailingHeaders();
}