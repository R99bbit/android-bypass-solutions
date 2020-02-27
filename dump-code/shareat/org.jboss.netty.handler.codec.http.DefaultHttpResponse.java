package org.jboss.netty.handler.codec.http;

import org.jboss.netty.util.internal.StringUtil;

public class DefaultHttpResponse extends DefaultHttpMessage implements HttpResponse {
    private HttpResponseStatus status;

    public DefaultHttpResponse(HttpVersion version, HttpResponseStatus status2) {
        super(version);
        setStatus(status2);
    }

    public HttpResponseStatus getStatus() {
        return this.status;
    }

    public void setStatus(HttpResponseStatus status2) {
        if (status2 == null) {
            throw new NullPointerException("status");
        }
        this.status = status2;
    }

    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append(getClass().getSimpleName());
        buf.append("(chunked: ");
        buf.append(isChunked());
        buf.append(')');
        buf.append(StringUtil.NEWLINE);
        buf.append(getProtocolVersion().getText());
        buf.append(' ');
        buf.append(getStatus().toString());
        buf.append(StringUtil.NEWLINE);
        appendHeaders(buf);
        buf.setLength(buf.length() - StringUtil.NEWLINE.length());
        return buf.toString();
    }
}