package org.jboss.netty.handler.codec.http;

import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.util.internal.StringUtil;

public class DefaultHttpChunkTrailer implements HttpChunkTrailer {
    private final HttpHeaders trailingHeaders = new TrailingHeaders(true);

    private static final class TrailingHeaders extends DefaultHttpHeaders {
        TrailingHeaders(boolean validateHeaders) {
            super(validateHeaders);
        }

        public HttpHeaders add(String name, Object value) {
            if (this.validate) {
                validateName(name);
            }
            return super.add(name, value);
        }

        public HttpHeaders add(String name, Iterable<?> values) {
            if (this.validate) {
                validateName(name);
            }
            return super.add(name, values);
        }

        public HttpHeaders set(String name, Iterable<?> values) {
            if (this.validate) {
                validateName(name);
            }
            return super.set(name, values);
        }

        public HttpHeaders set(String name, Object value) {
            if (this.validate) {
                validateName(name);
            }
            return super.set(name, value);
        }

        private static void validateName(String name) {
            if (name.equalsIgnoreCase("Content-Length") || name.equalsIgnoreCase(Names.TRANSFER_ENCODING) || name.equalsIgnoreCase(Names.TRAILER)) {
                throw new IllegalArgumentException("prohibited trailing header: " + name);
            }
        }
    }

    public boolean isLast() {
        return true;
    }

    @Deprecated
    public void addHeader(String name, Object value) {
        this.trailingHeaders.add(name, value);
    }

    @Deprecated
    public void setHeader(String name, Object value) {
        this.trailingHeaders.set(name, value);
    }

    @Deprecated
    public void setHeader(String name, Iterable<?> values) {
        this.trailingHeaders.set(name, values);
    }

    @Deprecated
    public void removeHeader(String name) {
        this.trailingHeaders.remove(name);
    }

    @Deprecated
    public void clearHeaders() {
        this.trailingHeaders.clear();
    }

    @Deprecated
    public String getHeader(String name) {
        return this.trailingHeaders.get(name);
    }

    @Deprecated
    public List<String> getHeaders(String name) {
        return this.trailingHeaders.getAll(name);
    }

    @Deprecated
    public List<Entry<String, String>> getHeaders() {
        return this.trailingHeaders.entries();
    }

    @Deprecated
    public boolean containsHeader(String name) {
        return this.trailingHeaders.contains(name);
    }

    @Deprecated
    public Set<String> getHeaderNames() {
        return this.trailingHeaders.names();
    }

    public ChannelBuffer getContent() {
        return ChannelBuffers.EMPTY_BUFFER;
    }

    public void setContent(ChannelBuffer content) {
        throw new IllegalStateException("read-only");
    }

    public HttpHeaders trailingHeaders() {
        return this.trailingHeaders;
    }

    public String toString() {
        StringBuilder buf = new StringBuilder(super.toString());
        buf.append(StringUtil.NEWLINE);
        appendHeaders(buf);
        buf.setLength(buf.length() - StringUtil.NEWLINE.length());
        return buf.toString();
    }

    private void appendHeaders(StringBuilder buf) {
        Iterator i$ = trailingHeaders().iterator();
        while (i$.hasNext()) {
            Entry<String, String> e = (Entry) i$.next();
            buf.append(e.getKey());
            buf.append(": ");
            buf.append(e.getValue());
            buf.append(StringUtil.NEWLINE);
        }
    }
}