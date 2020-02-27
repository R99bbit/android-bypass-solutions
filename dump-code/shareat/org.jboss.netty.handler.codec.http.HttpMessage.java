package org.jboss.netty.handler.codec.http;

import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;

public interface HttpMessage {
    @Deprecated
    void addHeader(String str, Object obj);

    @Deprecated
    void clearHeaders();

    @Deprecated
    boolean containsHeader(String str);

    ChannelBuffer getContent();

    @Deprecated
    String getHeader(String str);

    @Deprecated
    Set<String> getHeaderNames();

    @Deprecated
    List<Entry<String, String>> getHeaders();

    @Deprecated
    List<String> getHeaders(String str);

    HttpVersion getProtocolVersion();

    HttpHeaders headers();

    boolean isChunked();

    @Deprecated
    void removeHeader(String str);

    void setChunked(boolean z);

    void setContent(ChannelBuffer channelBuffer);

    @Deprecated
    void setHeader(String str, Iterable<?> iterable);

    @Deprecated
    void setHeader(String str, Object obj);

    void setProtocolVersion(HttpVersion httpVersion);
}