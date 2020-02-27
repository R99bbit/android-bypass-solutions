package org.jboss.netty.handler.codec.serialization;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferOutputStream;
import org.jboss.netty.buffer.ChannelBuffers;

public class ObjectEncoderOutputStream extends OutputStream implements ObjectOutput {
    private final int estimatedLength;
    private final DataOutputStream out;

    public ObjectEncoderOutputStream(OutputStream out2) {
        this(out2, 512);
    }

    public ObjectEncoderOutputStream(OutputStream out2, int estimatedLength2) {
        if (out2 == null) {
            throw new NullPointerException("out");
        } else if (estimatedLength2 < 0) {
            throw new IllegalArgumentException("estimatedLength: " + estimatedLength2);
        } else {
            if (out2 instanceof DataOutputStream) {
                this.out = (DataOutputStream) out2;
            } else {
                this.out = new DataOutputStream(out2);
            }
            this.estimatedLength = estimatedLength2;
        }
    }

    public void writeObject(Object obj) throws IOException {
        ChannelBufferOutputStream bout = new ChannelBufferOutputStream(ChannelBuffers.dynamicBuffer(this.estimatedLength));
        ObjectOutputStream oout = new CompactObjectOutputStream(bout);
        oout.writeObject(obj);
        oout.flush();
        oout.close();
        ChannelBuffer buffer = bout.buffer();
        int objectSize = buffer.readableBytes();
        writeInt(objectSize);
        buffer.getBytes(0, (OutputStream) this, objectSize);
    }

    public void write(int b) throws IOException {
        this.out.write(b);
    }

    public void close() throws IOException {
        this.out.close();
    }

    public void flush() throws IOException {
        this.out.flush();
    }

    public final int size() {
        return this.out.size();
    }

    public void write(byte[] b, int off, int len) throws IOException {
        this.out.write(b, off, len);
    }

    public void write(byte[] b) throws IOException {
        this.out.write(b);
    }

    public final void writeBoolean(boolean v) throws IOException {
        this.out.writeBoolean(v);
    }

    public final void writeByte(int v) throws IOException {
        this.out.writeByte(v);
    }

    public final void writeBytes(String s) throws IOException {
        this.out.writeBytes(s);
    }

    public final void writeChar(int v) throws IOException {
        this.out.writeChar(v);
    }

    public final void writeChars(String s) throws IOException {
        this.out.writeChars(s);
    }

    public final void writeDouble(double v) throws IOException {
        this.out.writeDouble(v);
    }

    public final void writeFloat(float v) throws IOException {
        this.out.writeFloat(v);
    }

    public final void writeInt(int v) throws IOException {
        this.out.writeInt(v);
    }

    public final void writeLong(long v) throws IOException {
        this.out.writeLong(v);
    }

    public final void writeShort(int v) throws IOException {
        this.out.writeShort(v);
    }

    public final void writeUTF(String str) throws IOException {
        this.out.writeUTF(str);
    }
}