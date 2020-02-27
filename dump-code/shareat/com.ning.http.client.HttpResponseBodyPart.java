package com.ning.http.client;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;

public abstract class HttpResponseBodyPart extends HttpContent {
    public abstract boolean closeUnderlyingConnection();

    public abstract ByteBuffer getBodyByteBuffer();

    public abstract byte[] getBodyPartBytes();

    public abstract boolean isLast();

    public abstract int length();

    public abstract void markUnderlyingConnectionAsClosed();

    public abstract int writeTo(OutputStream outputStream) throws IOException;

    public HttpResponseBodyPart(URI uri, AsyncHttpProvider provider) {
        super(uri, provider);
    }
}