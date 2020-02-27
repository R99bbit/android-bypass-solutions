package org.jboss.netty.handler.codec.marshalling;

import java.io.IOException;
import org.jboss.marshalling.ByteOutput;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.buffer.ChannelBuffers;

class ChannelBufferByteOutput implements ByteOutput {
    private final ChannelBuffer buffer;

    public ChannelBufferByteOutput(ChannelBuffer buffer2) {
        this.buffer = buffer2;
    }

    public ChannelBufferByteOutput(ChannelBufferFactory factory, int estimatedLength) {
        this(ChannelBuffers.dynamicBuffer(estimatedLength, factory));
    }

    public void close() throws IOException {
    }

    public void flush() throws IOException {
    }

    public void write(int b) throws IOException {
        this.buffer.writeByte(b);
    }

    public void write(byte[] bytes) throws IOException {
        this.buffer.writeBytes(bytes);
    }

    public void write(byte[] bytes, int srcIndex, int length) throws IOException {
        this.buffer.writeBytes(bytes, srcIndex, length);
    }

    public ChannelBuffer getBuffer() {
        return this.buffer;
    }
}