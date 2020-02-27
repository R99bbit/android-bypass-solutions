package org.jboss.netty.handler.codec.serialization;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.StreamCorruptedException;

public class ObjectDecoderInputStream extends InputStream implements ObjectInput {
    private final ClassResolver classResolver;
    private final DataInputStream in;
    private final int maxObjectSize;

    public ObjectDecoderInputStream(InputStream in2) {
        this(in2, (ClassLoader) null);
    }

    public ObjectDecoderInputStream(InputStream in2, ClassLoader classLoader) {
        this(in2, classLoader, 1048576);
    }

    public ObjectDecoderInputStream(InputStream in2, int maxObjectSize2) {
        this(in2, null, maxObjectSize2);
    }

    public ObjectDecoderInputStream(InputStream in2, ClassLoader classLoader, int maxObjectSize2) {
        if (in2 == null) {
            throw new NullPointerException("in");
        } else if (maxObjectSize2 <= 0) {
            throw new IllegalArgumentException("maxObjectSize: " + maxObjectSize2);
        } else {
            if (in2 instanceof DataInputStream) {
                this.in = (DataInputStream) in2;
            } else {
                this.in = new DataInputStream(in2);
            }
            this.classResolver = ClassResolvers.weakCachingResolver(classLoader);
            this.maxObjectSize = maxObjectSize2;
        }
    }

    public Object readObject() throws ClassNotFoundException, IOException {
        int dataLen = readInt();
        if (dataLen <= 0) {
            throw new StreamCorruptedException("invalid data length: " + dataLen);
        } else if (dataLen <= this.maxObjectSize) {
            return new CompactObjectInputStream(this.in, this.classResolver).readObject();
        } else {
            throw new StreamCorruptedException("data length too big: " + dataLen + " (max: " + this.maxObjectSize + ')');
        }
    }

    public int available() throws IOException {
        return this.in.available();
    }

    public void close() throws IOException {
        this.in.close();
    }

    public void mark(int readlimit) {
        this.in.mark(readlimit);
    }

    public boolean markSupported() {
        return this.in.markSupported();
    }

    public int read() throws IOException {
        return this.in.read();
    }

    public final int read(byte[] b, int off, int len) throws IOException {
        return this.in.read(b, off, len);
    }

    public final int read(byte[] b) throws IOException {
        return this.in.read(b);
    }

    public final boolean readBoolean() throws IOException {
        return this.in.readBoolean();
    }

    public final byte readByte() throws IOException {
        return this.in.readByte();
    }

    public final char readChar() throws IOException {
        return this.in.readChar();
    }

    public final double readDouble() throws IOException {
        return this.in.readDouble();
    }

    public final float readFloat() throws IOException {
        return this.in.readFloat();
    }

    public final void readFully(byte[] b, int off, int len) throws IOException {
        this.in.readFully(b, off, len);
    }

    public final void readFully(byte[] b) throws IOException {
        this.in.readFully(b);
    }

    public final int readInt() throws IOException {
        return this.in.readInt();
    }

    @Deprecated
    public final String readLine() throws IOException {
        return this.in.readLine();
    }

    public final long readLong() throws IOException {
        return this.in.readLong();
    }

    public final short readShort() throws IOException {
        return this.in.readShort();
    }

    public final int readUnsignedByte() throws IOException {
        return this.in.readUnsignedByte();
    }

    public final int readUnsignedShort() throws IOException {
        return this.in.readUnsignedShort();
    }

    public final String readUTF() throws IOException {
        return this.in.readUTF();
    }

    public void reset() throws IOException {
        this.in.reset();
    }

    public long skip(long n) throws IOException {
        return this.in.skip(n);
    }

    public final int skipBytes(int n) throws IOException {
        return this.in.skipBytes(n);
    }
}