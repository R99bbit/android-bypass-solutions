package org.jboss.netty.buffer;

import android.support.v4.view.ViewCompat;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.ScatteringByteChannel;
import java.nio.charset.Charset;
import java.util.NoSuchElementException;

public abstract class AbstractChannelBuffer implements ChannelBuffer {
    private int markedReaderIndex;
    private int markedWriterIndex;
    private int readerIndex;
    private int writerIndex;

    public int readerIndex() {
        return this.readerIndex;
    }

    public void readerIndex(int readerIndex2) {
        if (readerIndex2 < 0 || readerIndex2 > this.writerIndex) {
            throw new IndexOutOfBoundsException();
        }
        this.readerIndex = readerIndex2;
    }

    public int writerIndex() {
        return this.writerIndex;
    }

    public void writerIndex(int writerIndex2) {
        if (writerIndex2 < this.readerIndex || writerIndex2 > capacity()) {
            throw new IndexOutOfBoundsException("Invalid readerIndex: " + this.readerIndex + " - Maximum is " + writerIndex2);
        }
        this.writerIndex = writerIndex2;
    }

    public void setIndex(int readerIndex2, int writerIndex2) {
        if (readerIndex2 < 0 || readerIndex2 > writerIndex2 || writerIndex2 > capacity()) {
            throw new IndexOutOfBoundsException("Invalid writerIndex: " + writerIndex2 + " - Maximum is " + readerIndex2 + " or " + capacity());
        }
        this.readerIndex = readerIndex2;
        this.writerIndex = writerIndex2;
    }

    public void clear() {
        this.writerIndex = 0;
        this.readerIndex = 0;
    }

    public boolean readable() {
        return readableBytes() > 0;
    }

    public boolean writable() {
        return writableBytes() > 0;
    }

    public int readableBytes() {
        return this.writerIndex - this.readerIndex;
    }

    public int writableBytes() {
        return capacity() - this.writerIndex;
    }

    public void markReaderIndex() {
        this.markedReaderIndex = this.readerIndex;
    }

    public void resetReaderIndex() {
        readerIndex(this.markedReaderIndex);
    }

    public void markWriterIndex() {
        this.markedWriterIndex = this.writerIndex;
    }

    public void resetWriterIndex() {
        this.writerIndex = this.markedWriterIndex;
    }

    public void discardReadBytes() {
        if (this.readerIndex != 0) {
            setBytes(0, (ChannelBuffer) this, this.readerIndex, this.writerIndex - this.readerIndex);
            this.writerIndex -= this.readerIndex;
            this.markedReaderIndex = Math.max(this.markedReaderIndex - this.readerIndex, 0);
            this.markedWriterIndex = Math.max(this.markedWriterIndex - this.readerIndex, 0);
            this.readerIndex = 0;
        }
    }

    public void ensureWritableBytes(int writableBytes) {
        if (writableBytes > writableBytes()) {
            throw new IndexOutOfBoundsException("Writable bytes exceeded: Got " + writableBytes + ", maximum is " + writableBytes());
        }
    }

    public short getUnsignedByte(int index) {
        return (short) (getByte(index) & 255);
    }

    public int getUnsignedShort(int index) {
        return getShort(index) & 65535;
    }

    public int getMedium(int index) {
        int value = getUnsignedMedium(index);
        if ((8388608 & value) != 0) {
            return value | ViewCompat.MEASURED_STATE_MASK;
        }
        return value;
    }

    public long getUnsignedInt(int index) {
        return ((long) getInt(index)) & 4294967295L;
    }

    public char getChar(int index) {
        return (char) getShort(index);
    }

    public float getFloat(int index) {
        return Float.intBitsToFloat(getInt(index));
    }

    public double getDouble(int index) {
        return Double.longBitsToDouble(getLong(index));
    }

    public void getBytes(int index, byte[] dst) {
        getBytes(index, dst, 0, dst.length);
    }

    public void getBytes(int index, ChannelBuffer dst) {
        getBytes(index, dst, dst.writableBytes());
    }

    public void getBytes(int index, ChannelBuffer dst, int length) {
        if (length > dst.writableBytes()) {
            throw new IndexOutOfBoundsException("Too many bytes to be read: Need " + length + ", maximum is " + dst.writableBytes());
        }
        getBytes(index, dst, dst.writerIndex(), length);
        dst.writerIndex(dst.writerIndex() + length);
    }

    public void setChar(int index, int value) {
        setShort(index, value);
    }

    public void setFloat(int index, float value) {
        setInt(index, Float.floatToRawIntBits(value));
    }

    public void setDouble(int index, double value) {
        setLong(index, Double.doubleToRawLongBits(value));
    }

    public void setBytes(int index, byte[] src) {
        setBytes(index, src, 0, src.length);
    }

    public void setBytes(int index, ChannelBuffer src) {
        setBytes(index, src, src.readableBytes());
    }

    public void setBytes(int index, ChannelBuffer src, int length) {
        if (length > src.readableBytes()) {
            throw new IndexOutOfBoundsException("Too many bytes to write: Need " + length + ", maximum is " + src.readableBytes());
        }
        setBytes(index, src, src.readerIndex(), length);
        src.readerIndex(src.readerIndex() + length);
    }

    public void setZero(int index, int length) {
        if (length != 0) {
            if (length < 0) {
                throw new IllegalArgumentException("length must be 0 or greater than 0.");
            }
            int nBytes = length & 7;
            for (int i = length >>> 3; i > 0; i--) {
                setLong(index, 0);
                index += 8;
            }
            if (nBytes == 4) {
                setInt(index, 0);
            } else if (nBytes < 4) {
                for (int i2 = nBytes; i2 > 0; i2--) {
                    setByte(index, 0);
                    index++;
                }
            } else {
                setInt(index, 0);
                int index2 = index + 4;
                for (int i3 = nBytes - 4; i3 > 0; i3--) {
                    setByte(index2, 0);
                    index2++;
                }
            }
        }
    }

    public byte readByte() {
        if (this.readerIndex == this.writerIndex) {
            throw new IndexOutOfBoundsException("Readable byte limit exceeded: " + this.readerIndex);
        }
        int i = this.readerIndex;
        this.readerIndex = i + 1;
        return getByte(i);
    }

    public short readUnsignedByte() {
        return (short) (readByte() & 255);
    }

    public short readShort() {
        checkReadableBytes(2);
        short v = getShort(this.readerIndex);
        this.readerIndex += 2;
        return v;
    }

    public int readUnsignedShort() {
        return readShort() & 65535;
    }

    public int readMedium() {
        int value = readUnsignedMedium();
        if ((8388608 & value) != 0) {
            return value | ViewCompat.MEASURED_STATE_MASK;
        }
        return value;
    }

    public int readUnsignedMedium() {
        checkReadableBytes(3);
        int v = getUnsignedMedium(this.readerIndex);
        this.readerIndex += 3;
        return v;
    }

    public int readInt() {
        checkReadableBytes(4);
        int v = getInt(this.readerIndex);
        this.readerIndex += 4;
        return v;
    }

    public long readUnsignedInt() {
        return ((long) readInt()) & 4294967295L;
    }

    public long readLong() {
        checkReadableBytes(8);
        long v = getLong(this.readerIndex);
        this.readerIndex += 8;
        return v;
    }

    public char readChar() {
        return (char) readShort();
    }

    public float readFloat() {
        return Float.intBitsToFloat(readInt());
    }

    public double readDouble() {
        return Double.longBitsToDouble(readLong());
    }

    public ChannelBuffer readBytes(int length) {
        checkReadableBytes(length);
        if (length == 0) {
            return ChannelBuffers.EMPTY_BUFFER;
        }
        ChannelBuffer buf = factory().getBuffer(order(), length);
        buf.writeBytes((ChannelBuffer) this, this.readerIndex, length);
        this.readerIndex += length;
        return buf;
    }

    @Deprecated
    public ChannelBuffer readBytes(ChannelBufferIndexFinder endIndexFinder) {
        int endIndex = indexOf(this.readerIndex, this.writerIndex, endIndexFinder);
        if (endIndex >= 0) {
            return readBytes(endIndex - this.readerIndex);
        }
        throw new NoSuchElementException();
    }

    public ChannelBuffer readSlice(int length) {
        ChannelBuffer slice = slice(this.readerIndex, length);
        this.readerIndex += length;
        return slice;
    }

    @Deprecated
    public ChannelBuffer readSlice(ChannelBufferIndexFinder endIndexFinder) {
        int endIndex = indexOf(this.readerIndex, this.writerIndex, endIndexFinder);
        if (endIndex >= 0) {
            return readSlice(endIndex - this.readerIndex);
        }
        throw new NoSuchElementException();
    }

    public void readBytes(byte[] dst, int dstIndex, int length) {
        checkReadableBytes(length);
        getBytes(this.readerIndex, dst, dstIndex, length);
        this.readerIndex += length;
    }

    public void readBytes(byte[] dst) {
        readBytes(dst, 0, dst.length);
    }

    public void readBytes(ChannelBuffer dst) {
        readBytes(dst, dst.writableBytes());
    }

    public void readBytes(ChannelBuffer dst, int length) {
        if (length > dst.writableBytes()) {
            throw new IndexOutOfBoundsException("Too many bytes to be read: Need " + length + ", maximum is " + dst.writableBytes());
        }
        readBytes(dst, dst.writerIndex(), length);
        dst.writerIndex(dst.writerIndex() + length);
    }

    public void readBytes(ChannelBuffer dst, int dstIndex, int length) {
        checkReadableBytes(length);
        getBytes(this.readerIndex, dst, dstIndex, length);
        this.readerIndex += length;
    }

    public void readBytes(ByteBuffer dst) {
        int length = dst.remaining();
        checkReadableBytes(length);
        getBytes(this.readerIndex, dst);
        this.readerIndex += length;
    }

    public int readBytes(GatheringByteChannel out, int length) throws IOException {
        checkReadableBytes(length);
        int readBytes = getBytes(this.readerIndex, out, length);
        this.readerIndex += readBytes;
        return readBytes;
    }

    public void readBytes(OutputStream out, int length) throws IOException {
        checkReadableBytes(length);
        getBytes(this.readerIndex, out, length);
        this.readerIndex += length;
    }

    public void skipBytes(int length) {
        int newReaderIndex = this.readerIndex + length;
        if (newReaderIndex > this.writerIndex) {
            throw new IndexOutOfBoundsException("Readable bytes exceeded - Need " + newReaderIndex + ", maximum is " + this.writerIndex);
        }
        this.readerIndex = newReaderIndex;
    }

    @Deprecated
    public int skipBytes(ChannelBufferIndexFinder firstIndexFinder) {
        int oldReaderIndex = this.readerIndex;
        int newReaderIndex = indexOf(oldReaderIndex, this.writerIndex, firstIndexFinder);
        if (newReaderIndex < 0) {
            throw new NoSuchElementException();
        }
        readerIndex(newReaderIndex);
        return newReaderIndex - oldReaderIndex;
    }

    public void writeByte(int value) {
        setByte(this.writerIndex, value);
        this.writerIndex++;
    }

    public void writeShort(int value) {
        setShort(this.writerIndex, value);
        this.writerIndex += 2;
    }

    public void writeMedium(int value) {
        setMedium(this.writerIndex, value);
        this.writerIndex += 3;
    }

    public void writeInt(int value) {
        setInt(this.writerIndex, value);
        this.writerIndex += 4;
    }

    public void writeLong(long value) {
        setLong(this.writerIndex, value);
        this.writerIndex += 8;
    }

    public void writeChar(int value) {
        writeShort(value);
    }

    public void writeFloat(float value) {
        writeInt(Float.floatToRawIntBits(value));
    }

    public void writeDouble(double value) {
        writeLong(Double.doubleToRawLongBits(value));
    }

    public void writeBytes(byte[] src, int srcIndex, int length) {
        setBytes(this.writerIndex, src, srcIndex, length);
        this.writerIndex += length;
    }

    public void writeBytes(byte[] src) {
        writeBytes(src, 0, src.length);
    }

    public void writeBytes(ChannelBuffer src) {
        writeBytes(src, src.readableBytes());
    }

    public void writeBytes(ChannelBuffer src, int length) {
        if (length > src.readableBytes()) {
            throw new IndexOutOfBoundsException("Too many bytes to write - Need " + length + ", maximum is " + src.readableBytes());
        }
        writeBytes(src, src.readerIndex(), length);
        src.readerIndex(src.readerIndex() + length);
    }

    public void writeBytes(ChannelBuffer src, int srcIndex, int length) {
        setBytes(this.writerIndex, src, srcIndex, length);
        this.writerIndex += length;
    }

    public void writeBytes(ByteBuffer src) {
        int length = src.remaining();
        setBytes(this.writerIndex, src);
        this.writerIndex += length;
    }

    public int writeBytes(InputStream in, int length) throws IOException {
        int writtenBytes = setBytes(this.writerIndex, in, length);
        if (writtenBytes > 0) {
            this.writerIndex += writtenBytes;
        }
        return writtenBytes;
    }

    public int writeBytes(ScatteringByteChannel in, int length) throws IOException {
        int writtenBytes = setBytes(this.writerIndex, in, length);
        if (writtenBytes > 0) {
            this.writerIndex += writtenBytes;
        }
        return writtenBytes;
    }

    public void writeZero(int length) {
        if (length != 0) {
            if (length < 0) {
                throw new IllegalArgumentException("length must be 0 or greater than 0.");
            }
            int nBytes = length & 7;
            for (int i = length >>> 3; i > 0; i--) {
                writeLong(0);
            }
            if (nBytes == 4) {
                writeInt(0);
            } else if (nBytes < 4) {
                for (int i2 = nBytes; i2 > 0; i2--) {
                    writeByte(0);
                }
            } else {
                writeInt(0);
                for (int i3 = nBytes - 4; i3 > 0; i3--) {
                    writeByte(0);
                }
            }
        }
    }

    public ChannelBuffer copy() {
        return copy(this.readerIndex, readableBytes());
    }

    public ChannelBuffer slice() {
        return slice(this.readerIndex, readableBytes());
    }

    public ByteBuffer toByteBuffer() {
        return toByteBuffer(this.readerIndex, readableBytes());
    }

    public ByteBuffer[] toByteBuffers() {
        return toByteBuffers(this.readerIndex, readableBytes());
    }

    public ByteBuffer[] toByteBuffers(int index, int length) {
        return new ByteBuffer[]{toByteBuffer(index, length)};
    }

    public String toString(Charset charset) {
        return toString(this.readerIndex, readableBytes(), charset);
    }

    public String toString(int index, int length, Charset charset) {
        if (length == 0) {
            return "";
        }
        return ChannelBuffers.decodeString(toByteBuffer(index, length), charset);
    }

    @Deprecated
    public String toString(int index, int length, String charsetName, ChannelBufferIndexFinder terminatorFinder) {
        if (terminatorFinder == null) {
            return toString(index, length, charsetName);
        }
        int terminatorIndex = indexOf(index, index + length, terminatorFinder);
        if (terminatorIndex < 0) {
            return toString(index, length, charsetName);
        }
        return toString(index, terminatorIndex - index, charsetName);
    }

    @Deprecated
    public String toString(int index, int length, String charsetName) {
        return toString(index, length, Charset.forName(charsetName));
    }

    @Deprecated
    public String toString(String charsetName, ChannelBufferIndexFinder terminatorFinder) {
        return toString(this.readerIndex, readableBytes(), charsetName, terminatorFinder);
    }

    @Deprecated
    public String toString(String charsetName) {
        return toString(Charset.forName(charsetName));
    }

    public int indexOf(int fromIndex, int toIndex, byte value) {
        return ChannelBuffers.indexOf((ChannelBuffer) this, fromIndex, toIndex, value);
    }

    public int indexOf(int fromIndex, int toIndex, ChannelBufferIndexFinder indexFinder) {
        return ChannelBuffers.indexOf((ChannelBuffer) this, fromIndex, toIndex, indexFinder);
    }

    public int bytesBefore(byte value) {
        return bytesBefore(readerIndex(), readableBytes(), value);
    }

    public int bytesBefore(ChannelBufferIndexFinder indexFinder) {
        return bytesBefore(readerIndex(), readableBytes(), indexFinder);
    }

    public int bytesBefore(int length, byte value) {
        checkReadableBytes(length);
        return bytesBefore(readerIndex(), length, value);
    }

    public int bytesBefore(int length, ChannelBufferIndexFinder indexFinder) {
        checkReadableBytes(length);
        return bytesBefore(readerIndex(), length, indexFinder);
    }

    public int bytesBefore(int index, int length, byte value) {
        if (index < 0 || length < 0 || index + length > capacity()) {
            throw new IndexOutOfBoundsException();
        }
        int endIndex = indexOf(index, index + length, value);
        if (endIndex < 0) {
            return -1;
        }
        return endIndex - index;
    }

    public int bytesBefore(int index, int length, ChannelBufferIndexFinder indexFinder) {
        if (index < 0 || length < 0 || index + length > capacity()) {
            throw new IndexOutOfBoundsException();
        }
        int endIndex = indexOf(index, index + length, indexFinder);
        if (endIndex < 0) {
            return -1;
        }
        return endIndex - index;
    }

    public int hashCode() {
        return ChannelBuffers.hashCode(this);
    }

    public boolean equals(Object o) {
        if (!(o instanceof ChannelBuffer)) {
            return false;
        }
        return ChannelBuffers.equals(this, (ChannelBuffer) o);
    }

    public int compareTo(ChannelBuffer that) {
        return ChannelBuffers.compare(this, that);
    }

    public String toString() {
        return getClass().getSimpleName() + '(' + "ridx=" + this.readerIndex + ", " + "widx=" + this.writerIndex + ", " + "cap=" + capacity() + ')';
    }

    /* access modifiers changed from: protected */
    public void checkReadableBytes(int minimumReadableBytes) {
        if (readableBytes() < minimumReadableBytes) {
            throw new IndexOutOfBoundsException("Not enough readable bytes - Need " + minimumReadableBytes + ", maximum is " + readableBytes());
        }
    }
}