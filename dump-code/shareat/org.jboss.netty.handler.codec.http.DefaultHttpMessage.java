package org.jboss.netty.handler.codec.http;

import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.util.internal.StringUtil;

public class DefaultHttpMessage implements HttpMessage {
    private boolean chunked;
    private ChannelBuffer content = ChannelBuffers.EMPTY_BUFFER;
    private final HttpHeaders headers = new DefaultHttpHeaders(true);
    private HttpVersion version;

    protected DefaultHttpMessage(HttpVersion version2) {
        setProtocolVersion(version2);
    }

    public HttpHeaders headers() {
        return this.headers;
    }

    @Deprecated
    public void addHeader(String name, Object value) {
        this.headers.add(name, value);
    }

    @Deprecated
    public void setHeader(String name, Object value) {
        this.headers.set(name, value);
    }

    @Deprecated
    public void setHeader(String name, Iterable<?> values) {
        this.headers.set(name, values);
    }

    @Deprecated
    public void removeHeader(String name) {
        this.headers.remove(name);
    }

    public boolean isChunked() {
        if (this.chunked) {
            return true;
        }
        return HttpCodecUtil.isTransferEncodingChunked(this);
    }

    public void setChunked(boolean chunked2) {
        this.chunked = chunked2;
        if (chunked2) {
            setContent(ChannelBuffers.EMPTY_BUFFER);
        }
    }

    @Deprecated
    public void clearHeaders() {
        this.headers.clear();
    }

    public void setContent(ChannelBuffer content2) {
        if (content2 == null) {
            content2 = ChannelBuffers.EMPTY_BUFFER;
        }
        if (!content2.readable() || !isChunked()) {
            this.content = content2;
            return;
        }
        throw new IllegalArgumentException("non-empty content disallowed if this.chunked == true");
    }

    @Deprecated
    public String getHeader(String name) {
        return this.headers.get(name);
    }

    @Deprecated
    public List<String> getHeaders(String name) {
        return this.headers.getAll(name);
    }

    @Deprecated
    public List<Entry<String, String>> getHeaders() {
        return this.headers.entries();
    }

    @Deprecated
    public boolean containsHeader(String name) {
        return this.headers.contains(name);
    }

    @Deprecated
    public Set<String> getHeaderNames() {
        return this.headers.names();
    }

    public HttpVersion getProtocolVersion() {
        return this.version;
    }

    public void setProtocolVersion(HttpVersion version2) {
        if (version2 == null) {
            throw new NullPointerException("version");
        }
        this.version = version2;
    }

    public ChannelBuffer getContent() {
        return this.content;
    }

    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append(getClass().getSimpleName());
        buf.append("(version: ");
        buf.append(getProtocolVersion().getText());
        buf.append(", keepAlive: ");
        buf.append(HttpHeaders.isKeepAlive(this));
        buf.append(", chunked: ");
        buf.append(isChunked());
        buf.append(')');
        buf.append(StringUtil.NEWLINE);
        appendHeaders(buf);
        buf.setLength(buf.length() - StringUtil.NEWLINE.length());
        return buf.toString();
    }

    /* access modifiers changed from: 0000 */
    public void appendHeaders(StringBuilder buf) {
        Iterator i$ = headers().iterator();
        while (i$.hasNext()) {
            Entry<String, String> e = (Entry) i$.next();
            buf.append(e.getKey());
            buf.append(": ");
            buf.append(e.getValue());
            buf.append(StringUtil.NEWLINE);
        }
    }
}