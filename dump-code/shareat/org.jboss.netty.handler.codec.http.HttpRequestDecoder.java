package org.jboss.netty.handler.codec.http;

public class HttpRequestDecoder extends HttpMessageDecoder {
    public HttpRequestDecoder() {
    }

    public HttpRequestDecoder(int maxInitialLineLength, int maxHeaderSize, int maxChunkSize) {
        super(maxInitialLineLength, maxHeaderSize, maxChunkSize);
    }

    /* access modifiers changed from: protected */
    public HttpMessage createMessage(String[] initialLine) throws Exception {
        return new DefaultHttpRequest(HttpVersion.valueOf(initialLine[2]), HttpMethod.valueOf(initialLine[0]), initialLine[1]);
    }

    /* access modifiers changed from: protected */
    public boolean isDecodingRequest() {
        return true;
    }
}