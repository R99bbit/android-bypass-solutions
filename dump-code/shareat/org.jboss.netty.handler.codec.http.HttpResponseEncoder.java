package org.jboss.netty.handler.codec.http;

import org.jboss.netty.buffer.ChannelBuffer;

public class HttpResponseEncoder extends HttpMessageEncoder {
    /* access modifiers changed from: protected */
    public void encodeInitialLine(ChannelBuffer buf, HttpMessage message) throws Exception {
        HttpResponse response = (HttpResponse) message;
        encodeAscii(response.getProtocolVersion().toString(), buf);
        buf.writeByte(32);
        encodeAscii(String.valueOf(response.getStatus().getCode()), buf);
        buf.writeByte(32);
        encodeAscii(String.valueOf(response.getStatus().getReasonPhrase()), buf);
        buf.writeByte(13);
        buf.writeByte(10);
    }
}