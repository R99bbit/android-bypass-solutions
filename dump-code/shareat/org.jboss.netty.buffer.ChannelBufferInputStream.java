package org.jboss.netty.buffer;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class ChannelBufferInputStream extends InputStream implements DataInput {
    private final ChannelBuffer buffer;
    private final int endIndex;
    private final StringBuilder lineBuf;
    private final int startIndex;

    public ChannelBufferInputStream(ChannelBuffer buffer2) {
        this(buffer2, buffer2.readableBytes());
    }

    public ChannelBufferInputStream(ChannelBuffer buffer2, int length) {
        this.lineBuf = new StringBuilder();
        if (buffer2 == null) {
            throw new NullPointerException("buffer");
        } else if (length < 0) {
            throw new IllegalArgumentException("length: " + length);
        } else if (length > buffer2.readableBytes()) {
            throw new IndexOutOfBoundsException("Too many bytes to be read - Needs " + length + ", maximum is " + buffer2.readableBytes());
        } else {
            this.buffer = buffer2;
            this.startIndex = buffer2.readerIndex();
            this.endIndex = this.startIndex + length;
            buffer2.markReaderIndex();
        }
    }

    public int readBytes() {
        return this.buffer.readerIndex() - this.startIndex;
    }

    public int available() throws IOException {
        return this.endIndex - this.buffer.readerIndex();
    }

    public void mark(int readlimit) {
        this.buffer.markReaderIndex();
    }

    public boolean markSupported() {
        return true;
    }

    public int read() throws IOException {
        if (!this.buffer.readable()) {
            return -1;
        }
        return this.buffer.readByte() & 255;
    }

    public int read(byte[] b, int off, int len) throws IOException {
        int available = available();
        if (available == 0) {
            return -1;
        }
        int len2 = Math.min(available, len);
        this.buffer.readBytes(b, off, len2);
        return len2;
    }

    public void reset() throws IOException {
        this.buffer.resetReaderIndex();
    }

    public long skip(long n) throws IOException {
        if (n > 2147483647L) {
            return (long) skipBytes(ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED);
        }
        return (long) skipBytes((int) n);
    }

    public boolean readBoolean() throws IOException {
        checkAvailable(1);
        if (read() != 0) {
            return true;
        }
        return false;
    }

    public byte readByte() throws IOException {
        if (this.buffer.readable()) {
            return this.buffer.readByte();
        }
        throw new EOFException();
    }

    public char readChar() throws IOException {
        return (char) readShort();
    }

    public double readDouble() throws IOException {
        return Double.longBitsToDouble(readLong());
    }

    public float readFloat() throws IOException {
        return Float.intBitsToFloat(readInt());
    }

    public void readFully(byte[] b) throws IOException {
        readFully(b, 0, b.length);
    }

    public void readFully(byte[] b, int off, int len) throws IOException {
        checkAvailable(len);
        this.buffer.readBytes(b, off, len);
    }

    public int readInt() throws IOException {
        checkAvailable(4);
        return this.buffer.readInt();
    }

    public String readLine() throws IOException {
        this.lineBuf.setLength(0);
        while (true) {
            int b = read();
            if (b >= 0 && b != 10) {
                this.lineBuf.append((char) b);
            }
        }
        if (this.lineBuf.length() > 0) {
            while (this.lineBuf.charAt(this.lineBuf.length() - 1) == 13) {
                this.lineBuf.setLength(this.lineBuf.length() - 1);
            }
        }
        return this.lineBuf.toString();
    }

    public long readLong() throws IOException {
        checkAvailable(8);
        return this.buffer.readLong();
    }

    public short readShort() throws IOException {
        checkAvailable(2);
        return this.buffer.readShort();
    }

    public String readUTF() throws IOException {
        return DataInputStream.readUTF(this);
    }

    public int readUnsignedByte() throws IOException {
        return readByte() & 255;
    }

    public int readUnsignedShort() throws IOException {
        return readShort() & 65535;
    }

    public int skipBytes(int n) throws IOException {
        int nBytes = Math.min(available(), n);
        this.buffer.skipBytes(nBytes);
        return nBytes;
    }

    private void checkAvailable(int fieldSize) throws IOException {
        if (fieldSize < 0) {
            throw new IndexOutOfBoundsException("fieldSize cannot be a negative number");
        } else if (fieldSize > available()) {
            throw new EOFException("fieldSize is too long! Length is " + fieldSize + ", but maximum is " + available());
        }
    }
}