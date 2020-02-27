package org.jboss.netty.handler.codec.rtsp;

import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpMessage;

public class RtspRequestDecoder extends RtspMessageDecoder {
    public RtspRequestDecoder() {
    }

    public RtspRequestDecoder(int maxInitialLineLength, int maxHeaderSize, int maxContentLength) {
        super(maxInitialLineLength, maxHeaderSize, maxContentLength);
    }

    /* access modifiers changed from: protected */
    public HttpMessage createMessage(String[] initialLine) throws Exception {
        return new DefaultHttpRequest(RtspVersions.valueOf(initialLine[2]), RtspMethods.valueOf(initialLine[0]), initialLine[1]);
    }

    /* access modifiers changed from: protected */
    public boolean isDecodingRequest() {
        return true;
    }
}