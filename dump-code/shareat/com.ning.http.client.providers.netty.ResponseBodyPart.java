package com.ning.http.client.providers.netty;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.HttpResponseBodyPart;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpResponse;

public class ResponseBodyPart extends HttpResponseBodyPart {
    private final AtomicReference<byte[]> bytes;
    private boolean closeConnection;
    private final ChannelBuffer content;
    private final boolean isLast;
    private final int length;

    public ResponseBodyPart(URI uri, HttpResponse response, AsyncHttpProvider provider, boolean last) {
        this(uri, response, provider, null, last);
    }

    public ResponseBodyPart(URI uri, HttpResponse response, AsyncHttpProvider provider, HttpChunk chunk, boolean last) {
        super(uri, provider);
        this.bytes = new AtomicReference<>(null);
        this.closeConnection = false;
        this.content = chunk != null ? chunk.getContent() : response.getContent();
        this.length = this.content.readableBytes();
        this.isLast = last;
    }

    public byte[] getBodyPartBytes() {
        if (this.bytes.get() != null) {
            return this.bytes.get();
        }
        byte[] b = ChannelBufferUtil.channelBuffer2bytes(this.content);
        this.bytes.set(b);
        return b;
    }

    public int writeTo(OutputStream outputStream) throws IOException {
        ChannelBuffer b = getChannelBuffer();
        int read = b.readableBytes();
        int index = b.readerIndex();
        if (read > 0) {
            b.readBytes(outputStream, read);
        }
        b.readerIndex(index);
        return read;
    }

    public ChannelBuffer getChannelBuffer() {
        return this.content;
    }

    public ByteBuffer getBodyByteBuffer() {
        return ByteBuffer.wrap(getBodyPartBytes());
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
        return this.length;
    }
}