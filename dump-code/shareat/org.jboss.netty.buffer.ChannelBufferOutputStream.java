package org.jboss.netty.buffer;

import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class ChannelBufferOutputStream extends OutputStream implements DataOutput {
    private final ChannelBuffer buffer;
    private final int startIndex;
    private final DataOutputStream utf8out = new DataOutputStream(this);

    public ChannelBufferOutputStream(ChannelBuffer buffer2) {
        if (buffer2 == null) {
            throw new NullPointerException("buffer");
        }
        this.buffer = buffer2;
        this.startIndex = buffer2.writerIndex();
    }

    public int writtenBytes() {
        return this.buffer.writerIndex() - this.startIndex;
    }

    public void write(byte[] b, int off, int len) throws IOException {
        if (len != 0) {
            this.buffer.writeBytes(b, off, len);
        }
    }

    public void write(byte[] b) throws IOException {
        this.buffer.writeBytes(b);
    }

    public void write(int b) throws IOException {
        this.buffer.writeByte((byte) b);
    }

    public void writeBoolean(boolean v) throws IOException {
        write(v ? 1 : 0);
    }

    public void writeByte(int v) throws IOException {
        write(v);
    }

    public void writeBytes(String s) throws IOException {
        int len = s.length();
        for (int i = 0; i < len; i++) {
            write((int) (byte) s.charAt(i));
        }
    }

    public void writeChar(int v) throws IOException {
        writeShort((short) v);
    }

    public void writeChars(String s) throws IOException {
        int len = s.length();
        for (int i = 0; i < len; i++) {
            writeChar(s.charAt(i));
        }
    }

    public void writeDouble(double v) throws IOException {
        writeLong(Double.doubleToLongBits(v));
    }

    public void writeFloat(float v) throws IOException {
        writeInt(Float.floatToIntBits(v));
    }

    public void writeInt(int v) throws IOException {
        this.buffer.writeInt(v);
    }

    public void writeLong(long v) throws IOException {
        this.buffer.writeLong(v);
    }

    public void writeShort(int v) throws IOException {
        this.buffer.writeShort((short) v);
    }

    public void writeUTF(String s) throws IOException {
        this.utf8out.writeUTF(s);
    }

    public ChannelBuffer buffer() {
        return this.buffer;
    }
}