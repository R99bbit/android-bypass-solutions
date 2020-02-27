package org.jboss.netty.handler.codec.http;

import org.jboss.netty.buffer.ChannelBuffer;

public class HttpRequestEncoder extends HttpMessageEncoder {
    private static final char SLASH = '/';

    /* access modifiers changed from: protected */
    public void encodeInitialLine(ChannelBuffer buf, HttpMessage message) throws Exception {
        HttpRequest request = (HttpRequest) message;
        buf.writeBytes(request.getMethod().toString().getBytes("ASCII"));
        buf.writeByte(32);
        String uri = request.getUri();
        int start = uri.indexOf("://");
        if (start != -1 && uri.lastIndexOf(47) <= start + 3) {
            uri = uri + SLASH;
        }
        buf.writeBytes(uri.getBytes("UTF-8"));
        buf.writeByte(32);
        buf.writeBytes(request.getProtocolVersion().toString().getBytes("ASCII"));
        buf.writeByte(13);
        buf.writeByte(10);
    }
}