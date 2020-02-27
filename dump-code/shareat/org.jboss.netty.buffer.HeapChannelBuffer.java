package org.jboss.netty.buffer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.ScatteringByteChannel;

public abstract class HeapChannelBuffer extends AbstractChannelBuffer {
    protected final byte[] array;

    protected HeapChannelBuffer(int length) {
        this(new byte[length], 0, 0);
    }

    protected HeapChannelBuffer(byte[] array2) {
        this(array2, 0, array2.length);
    }

    protected HeapChannelBuffer(byte[] array2, int readerIndex, int writerIndex) {
        if (array2 == null) {
            throw new NullPointerException("array");
        }
        this.array = array2;
        setIndex(readerIndex, writerIndex);
    }

    public boolean isDirect() {
        return false;
    }

    public int capacity() {
        return this.array.length;
    }

    public boolean hasArray() {
        return true;
    }

    public byte[] array() {
        return this.array;
    }

    public int arrayOffset() {
        return 0;
    }

    public byte getByte(int index) {
        return this.array[index];
    }

    public void getBytes(int index, ChannelBuffer dst, int dstIndex, int length) {
        if (dst instanceof HeapChannelBuffer) {
            getBytes(index, ((HeapChannelBuffer) dst).array, dstIndex, length);
        } else {
            dst.setBytes(dstIndex, this.array, index, length);
        }
    }

    public void getBytes(int index, byte[] dst, int dstIndex, int length) {
        System.arraycopy(this.array, index, dst, dstIndex, length);
    }

    public void getBytes(int index, ByteBuffer dst) {
        dst.put(this.array, index, Math.min(capacity() - index, dst.remaining()));
    }

    public void getBytes(int index, OutputStream out, int length) throws IOException {
        out.write(this.array, index, length);
    }

    public int getBytes(int index, GatheringByteChannel out, int length) throws IOException {
        return out.write(ByteBuffer.wrap(this.array, index, length));
    }

    public void setByte(int index, int value) {
        this.array[index] = (byte) value;
    }

    public void setBytes(int index, ChannelBuffer src, int srcIndex, int length) {
        if (src instanceof HeapChannelBuffer) {
            setBytes(index, ((HeapChannelBuffer) src).array, srcIndex, length);
        } else {
            src.getBytes(srcIndex, this.array, index, length);
        }
    }

    public void setBytes(int index, byte[] src, int srcIndex, int length) {
        System.arraycopy(src, srcIndex, this.array, index, length);
    }

    public void setBytes(int index, ByteBuffer src) {
        src.get(this.array, index, src.remaining());
    }

    public int setBytes(int index, InputStream in, int length) throws IOException {
        int readBytes = 0;
        while (true) {
            int localReadBytes = in.read(this.array, index, length);
            if (localReadBytes >= 0) {
                readBytes += localReadBytes;
                index += localReadBytes;
                length -= localReadBytes;
                if (length <= 0) {
                    break;
                }
            } else if (readBytes == 0) {
                return -1;
            }
        }
        return readBytes;
    }

    public int setBytes(int index, ScatteringByteChannel in, int length) throws IOException {
        int localReadBytes;
        ByteBuffer buf = ByteBuffer.wrap(this.array, index, length);
        int readBytes = 0;
        while (true) {
            try {
                localReadBytes = in.read(buf);
            } catch (ClosedChannelException e) {
                localReadBytes = -1;
            }
            if (localReadBytes >= 0) {
                if (localReadBytes != 0) {
                    readBytes += localReadBytes;
                    if (readBytes >= length) {
                        break;
                    }
                } else {
                    break;
                }
            } else if (readBytes == 0) {
                return -1;
            }
        }
        return readBytes;
    }

    public ChannelBuffer slice(int index, int length) {
        if (index == 0) {
            if (length == 0) {
                return ChannelBuffers.EMPTY_BUFFER;
            }
            if (length != this.array.length) {
                return new TruncatedChannelBuffer(this, length);
            }
            ChannelBuffer slice = duplicate();
            slice.setIndex(0, length);
            return slice;
        } else if (length == 0) {
            return ChannelBuffers.EMPTY_BUFFER;
        } else {
            return new SlicedChannelBuffer(this, index, length);
        }
    }

    public ByteBuffer toByteBuffer(int index, int length) {
        return ByteBuffer.wrap(this.array, index, length).order(order());
    }
}