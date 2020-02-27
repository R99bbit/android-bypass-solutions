package org.jboss.netty.handler.codec.http;

public class HttpResponseDecoder extends HttpMessageDecoder {
    public HttpResponseDecoder() {
    }

    public HttpResponseDecoder(int maxInitialLineLength, int maxHeaderSize, int maxChunkSize) {
        super(maxInitialLineLength, maxHeaderSize, maxChunkSize);
    }

    /* access modifiers changed from: protected */
    public HttpMessage createMessage(String[] initialLine) {
        return new DefaultHttpResponse(HttpVersion.valueOf(initialLine[0]), new HttpResponseStatus(Integer.valueOf(initialLine[1]).intValue(), initialLine[2]));
    }

    /* access modifiers changed from: protected */
    public boolean isDecodingRequest() {
        return false;
    }
}