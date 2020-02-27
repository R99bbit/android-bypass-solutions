package com.ning.http.client.providers.grizzly;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.HttpResponseBodyPart;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.http.HttpContent;

public class GrizzlyResponseBodyPart extends HttpResponseBodyPart {
    private final Connection connection;
    private final HttpContent content;
    private final AtomicReference<byte[]> contentBytes = new AtomicReference<>();

    public GrizzlyResponseBodyPart(HttpContent content2, URI uri, Connection connection2, AsyncHttpProvider provider) {
        super(uri, provider);
        this.content = content2;
        this.connection = connection2;
    }

    public byte[] getBodyPartBytes() {
        byte[] bytes = this.contentBytes.get();
        if (bytes != null) {
            return bytes;
        }
        Buffer b = this.content.getContent();
        int origPos = b.position();
        byte[] bytes2 = new byte[b.remaining()];
        b.get(bytes2);
        b.flip();
        b.position(origPos);
        this.contentBytes.compareAndSet(null, bytes2);
        return bytes2;
    }

    public int writeTo(OutputStream outputStream) throws IOException {
        byte[] bytes = getBodyPartBytes();
        outputStream.write(getBodyPartBytes());
        return bytes.length;
    }

    public ByteBuffer getBodyByteBuffer() {
        return ByteBuffer.wrap(getBodyPartBytes());
    }

    public boolean isLast() {
        return this.content.isLast();
    }

    public void markUnderlyingConnectionAsClosed() {
        ConnectionManager.markConnectionAsDoNotCache(this.connection);
    }

    public boolean closeUnderlyingConnection() {
        return !ConnectionManager.isConnectionCacheable(this.connection);
    }

    /* access modifiers changed from: 0000 */
    public Buffer getBodyBuffer() {
        return this.content.getContent();
    }

    public int length() {
        return this.content.getContent().remaining();
    }
}