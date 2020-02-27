package org.jboss.netty.handler.codec.spdy;

import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import org.jboss.netty.util.internal.StringUtil;

public class DefaultSpdyHeadersFrame extends DefaultSpdyStreamFrame implements SpdyHeadersFrame {
    private final SpdyHeaders headers = new DefaultSpdyHeaders();
    private boolean invalid;
    private boolean truncated;

    public DefaultSpdyHeadersFrame(int streamId) {
        super(streamId);
    }

    public boolean isInvalid() {
        return this.invalid;
    }

    public void setInvalid() {
        this.invalid = true;
    }

    public boolean isTruncated() {
        return this.truncated;
    }

    public void setTruncated() {
        this.truncated = true;
    }

    public SpdyHeaders headers() {
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

    @Deprecated
    public void clearHeaders() {
        this.headers.clear();
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

    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append(getClass().getSimpleName());
        buf.append("(last: ");
        buf.append(isLast());
        buf.append(')');
        buf.append(StringUtil.NEWLINE);
        buf.append("--> Stream-ID = ");
        buf.append(getStreamId());
        buf.append(StringUtil.NEWLINE);
        buf.append("--> Headers:");
        buf.append(StringUtil.NEWLINE);
        appendHeaders(buf);
        buf.setLength(buf.length() - StringUtil.NEWLINE.length());
        return buf.toString();
    }

    /* access modifiers changed from: protected */
    public void appendHeaders(StringBuilder buf) {
        Iterator i$ = headers().iterator();
        while (i$.hasNext()) {
            Entry<String, String> e = i$.next();
            buf.append("    ");
            buf.append(e.getKey());
            buf.append(": ");
            buf.append(e.getValue());
            buf.append(StringUtil.NEWLINE);
        }
    }
}