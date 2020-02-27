package org.jboss.netty.handler.codec.rtsp;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.handler.codec.http.HttpMessage;
import org.jboss.netty.handler.codec.http.HttpResponse;

public class RtspResponseEncoder extends RtspMessageEncoder {
    /* access modifiers changed from: protected */
    public void encodeInitialLine(ChannelBuffer buf, HttpMessage message) throws Exception {
        HttpResponse response = (HttpResponse) message;
        buf.writeBytes(response.getProtocolVersion().toString().getBytes("ASCII"));
        buf.writeByte(32);
        buf.writeBytes(String.valueOf(response.getStatus().getCode()).getBytes("ASCII"));
        buf.writeByte(32);
        buf.writeBytes(String.valueOf(response.getStatus().getReasonPhrase()).getBytes("ASCII"));
        buf.writeByte(13);
        buf.writeByte(10);
    }
}