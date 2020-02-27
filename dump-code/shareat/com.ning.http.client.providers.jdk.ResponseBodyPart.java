package com.ning.http.client.providers.jdk;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.HttpResponseBodyPart;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;

public class ResponseBodyPart extends HttpResponseBodyPart {
    private final byte[] chunk;
    private boolean closeConnection;
    private final boolean isLast;

    public ResponseBodyPart(URI uri, byte[] chunk2, AsyncHttpProvider provider, boolean last) {
        super(uri, provider);
        this.chunk = chunk2;
        this.isLast = last;
    }

    public byte[] getBodyPartBytes() {
        return this.chunk;
    }

    public int writeTo(OutputStream outputStream) throws IOException {
        outputStream.write(this.chunk);
        return this.chunk.length;
    }

    public ByteBuffer getBodyByteBuffer() {
        return ByteBuffer.wrap(this.chunk);
    }

    public boolean isLast() {
        return this.isLast;
    }

    public void markUnderlyingConnectionAsClosed() {
        this.closeConnection = true;
    }

    public boolean closeUnderlyingConnection() {
        return this.closeConnection;
    }

    public int length() {
        if (this.chunk != null) {
            return this.chunk.length;
        }
        return 0;
    }
}