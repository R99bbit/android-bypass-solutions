package com.ning.http.client.consumers;

import com.ning.http.client.BodyConsumer;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;

public class AppendableBodyConsumer implements BodyConsumer {
    private final Appendable appendable;
    private final String encoding;

    public AppendableBodyConsumer(Appendable appendable2, String encoding2) {
        this.appendable = appendable2;
        this.encoding = encoding2;
    }

    public AppendableBodyConsumer(Appendable appendable2) {
        this.appendable = appendable2;
        this.encoding = "UTF-8";
    }

    public void consume(ByteBuffer byteBuffer) throws IOException {
        this.appendable.append(new String(byteBuffer.array(), byteBuffer.arrayOffset() + byteBuffer.position(), byteBuffer.remaining(), this.encoding));
    }

    public void close() throws IOException {
        if (this.appendable instanceof Closeable) {
            Closeable.class.cast(this.appendable).close();
        }
    }
}