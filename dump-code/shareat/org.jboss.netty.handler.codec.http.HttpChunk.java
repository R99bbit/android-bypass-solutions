package org.jboss.netty.handler.codec.http;

import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;

public interface HttpChunk {
    public static final HttpChunkTrailer LAST_CHUNK = new HttpChunkTrailer() {
        public ChannelBuffer getContent() {
            return ChannelBuffers.EMPTY_BUFFER;
        }

        public void setContent(ChannelBuffer content) {
            throw new IllegalStateException("read-only");
        }

        public boolean isLast() {
            return true;
        }

        @Deprecated
        public void addHeader(String name, Object value) {
            throw new IllegalStateException("read-only");
        }

        @Deprecated
        public void clearHeaders() {
        }

        @Deprecated
        public boolean containsHeader(String name) {
            return false;
        }

        @Deprecated
        public String getHeader(String name) {
            return null;
        }

        @Deprecated
        public Set<String> getHeaderNames() {
            return Collections.emptySet();
        }

        @Deprecated
        public List<String> getHeaders(String name) {
            return Collections.emptyList();
        }

        @Deprecated
        public List<Entry<String, String>> getHeaders() {
            return Collections.emptyList();
        }

        @Deprecated
        public void removeHeader(String name) {
        }

        @Deprecated
        public void setHeader(String name, Object value) {
            throw new IllegalStateException("read-only");
        }

        @Deprecated
        public void setHeader(String name, Iterable<?> iterable) {
            throw new IllegalStateException("read-only");
        }

        public HttpHeaders trailingHeaders() {
            return HttpHeaders.EMPTY_HEADERS;
        }
    };

    ChannelBuffer getContent();

    boolean isLast();

    void setContent(ChannelBuffer channelBuffer);
}