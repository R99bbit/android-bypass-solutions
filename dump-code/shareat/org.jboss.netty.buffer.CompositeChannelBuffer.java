package org.jboss.netty.buffer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.ScatteringByteChannel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.jboss.netty.util.internal.DetectionUtil;

public class CompositeChannelBuffer extends AbstractChannelBuffer {
    static final /* synthetic */ boolean $assertionsDisabled = (!CompositeChannelBuffer.class.desiredAssertionStatus());
    private ChannelBuffer[] components;
    private final boolean gathering;
    private int[] indices;
    private int lastAccessedComponentId;
    private final ByteOrder order;

    public CompositeChannelBuffer(ByteOrder endianness, List<ChannelBuffer> buffers, boolean gathering2) {
        this.order = endianness;
        this.gathering = gathering2;
        setComponents(buffers);
    }

    public boolean useGathering() {
        return this.gathering && DetectionUtil.javaVersion() >= 7;
    }

    public List<ChannelBuffer> decompose(int index, int length) {
        if (length == 0) {
            return Collections.emptyList();
        }
        if (index + length > capacity()) {
            throw new IndexOutOfBoundsException("Too many bytes to decompose - Need " + (index + length) + ", capacity is " + capacity());
        }
        int componentId = componentId(index);
        List<ChannelBuffer> slice = new ArrayList<>(this.components.length);
        ChannelBuffer first = this.components[componentId].duplicate();
        first.readerIndex(index - this.indices[componentId]);
        ChannelBuffer buf = first;
        int bytesToSlice = length;
        while (true) {
            int readableBytes = buf.readableBytes();
            if (bytesToSlice > readableBytes) {
                slice.add(buf);
                bytesToSlice -= readableBytes;
                componentId++;
                buf = this.components[componentId].duplicate();
                if (bytesToSlice <= 0) {
                    break;
                }
            } else {
                buf.writerIndex(buf.readerIndex() + bytesToSlice);
                slice.add(buf);
                break;
            }
        }
        for (int i = 0; i < slice.size(); i++) {
            slice.set(i, slice.get(i).slice());
        }
        return slice;
    }

    private void setComponents(List<ChannelBuffer> newComponents) {
        if ($assertionsDisabled || !newComponents.isEmpty()) {
            this.lastAccessedComponentId = 0;
            this.components = new ChannelBuffer[newComponents.size()];
            int i = 0;
            while (i < this.components.length) {
                ChannelBuffer c = newComponents.get(i);
                if (c.order() != order()) {
                    throw new IllegalArgumentException("All buffers must have the same endianness.");
                } else if (!$assertionsDisabled && c.readerIndex() != 0) {
                    throw new AssertionError();
                } else if ($assertionsDisabled || c.writerIndex() == c.capacity()) {
                    this.components[i] = c;
                    i++;
                } else {
                    throw new AssertionError();
                }
            }
            this.indices = new int[(this.components.length + 1)];
            this.indices[0] = 0;
            for (int i2 = 1; i2 <= this.components.length; i2++) {
                this.indices[i2] = this.indices[i2 - 1] + this.components[i2 - 1].capacity();
            }
            setIndex(0, capacity());
            return;
        }
        throw new AssertionError();
    }

    private CompositeChannelBuffer(CompositeChannelBuffer buffer) {
        this.order = buffer.order;
        this.gathering = buffer.gathering;
        this.components = (ChannelBuffer[]) buffer.components.clone();
        this.indices = (int[]) buffer.indices.clone();
        setIndex(buffer.readerIndex(), buffer.writerIndex());
    }

    public ChannelBufferFactory factory() {
        return HeapChannelBufferFactory.getInstance(order());
    }

    public ByteOrder order() {
        return this.order;
    }

    public boolean isDirect() {
        return false;
    }

    public boolean hasArray() {
        return false;
    }

    public byte[] array() {
        throw new UnsupportedOperationException();
    }

    public int arrayOffset() {
        throw new UnsupportedOperationException();
    }

    public int capacity() {
        return this.indices[this.components.length];
    }

    public int numComponents() {
        return this.components.length;
    }

    public byte getByte(int index) {
        int componentId = componentId(index);
        return this.components[componentId].getByte(index - this.indices[componentId]);
    }

    public short getShort(int index) {
        int componentId = componentId(index);
        if (index + 2 <= this.indices[componentId + 1]) {
            return this.components[componentId].getShort(index - this.indices[componentId]);
        }
        if (order() == ByteOrder.BIG_ENDIAN) {
            return (short) (((getByte(index) & 255) << 8) | (getByte(index + 1) & 255));
        }
        return (short) ((getByte(index) & 255) | ((getByte(index + 1) & 255) << 8));
    }

    public int getUnsignedMedium(int index) {
        int componentId = componentId(index);
        if (index + 3 <= this.indices[componentId + 1]) {
            return this.components[componentId].getUnsignedMedium(index - this.indices[componentId]);
        }
        if (order() == ByteOrder.BIG_ENDIAN) {
            return ((getShort(index) & 65535) << 8) | (getByte(index + 2) & 255);
        }
        return (getShort(index) & 65535) | ((getByte(index + 2) & 255) << 16);
    }

    public int getInt(int index) {
        int componentId = componentId(index);
        if (index + 4 <= this.indices[componentId + 1]) {
            return this.components[componentId].getInt(index - this.indices[componentId]);
        }
        if (order() == ByteOrder.BIG_ENDIAN) {
            return ((getShort(index) & 65535) << 16) | (getShort(index + 2) & 65535);
        }
        return (getShort(index) & 65535) | ((getShort(index + 2) & 65535) << 16);
    }

    public long getLong(int index) {
        int componentId = componentId(index);
        if (index + 8 <= this.indices[componentId + 1]) {
            return this.components[componentId].getLong(index - this.indices[componentId]);
        }
        if (order() == ByteOrder.BIG_ENDIAN) {
            return ((((long) getInt(index)) & 4294967295L) << 32) | (((long) getInt(index + 4)) & 4294967295L);
        }
        return (((long) getInt(index)) & 4294967295L) | ((((long) getInt(index + 4)) & 4294967295L) << 32);
    }

    public void getBytes(int index, byte[] dst, int dstIndex, int length) {
        if (index > capacity() - length || dstIndex > dst.length - length) {
            throw new IndexOutOfBoundsException("Too many bytes to read - Needs " + (index + length) + ", maximum is " + capacity() + " or " + dst.length);
        } else if (index < 0) {
            throw new IndexOutOfBoundsException("Index must be >= 0");
        } else if (length != 0) {
            int i = componentId(index);
            while (length > 0) {
                ChannelBuffer s = this.components[i];
                int adjustment = this.indices[i];
                int localLength = Math.min(length, s.capacity() - (index - adjustment));
                s.getBytes(index - adjustment, dst, dstIndex, localLength);
                index += localLength;
                dstIndex += localLength;
                length -= localLength;
                i++;
            }
        }
    }

    public void getBytes(int index, ByteBuffer dst) {
        int componentId = componentId(index);
        int limit = dst.limit();
        int length = dst.remaining();
        if (index > capacity() - length) {
            throw new IndexOutOfBoundsException("Too many bytes to be read - Needs " + (index + length) + ", maximum is " + capacity());
        } else if (index < 0) {
            throw new IndexOutOfBoundsException("Index must be >= 0");
        } else {
            int i = componentId;
            while (length > 0) {
                try {
                    ChannelBuffer s = this.components[i];
                    int adjustment = this.indices[i];
                    int localLength = Math.min(length, s.capacity() - (index - adjustment));
                    dst.limit(dst.position() + localLength);
                    s.getBytes(index - adjustment, dst);
                    index += localLength;
                    length -= localLength;
                    i++;
                } catch (Throwable th) {
                    dst.limit(limit);
                    throw th;
                }
            }
            dst.limit(limit);
        }
    }

    public void getBytes(int index, ChannelBuffer dst, int dstIndex, int length) {
        if (index > capacity() - length || dstIndex > dst.capacity() - length) {
            throw new IndexOutOfBoundsException("Too many bytes to be read - Needs " + (index + length) + " or " + (dstIndex + length) + ", maximum is " + capacity() + " or " + dst.capacity());
        } else if (index < 0) {
            throw new IndexOutOfBoundsException("Index must be >= 0");
        } else if (length != 0) {
            int i = componentId(index);
            while (length > 0) {
                ChannelBuffer s = this.components[i];
                int adjustment = this.indices[i];
                int localLength = Math.min(length, s.capacity() - (index - adjustment));
                s.getBytes(index - adjustment, dst, dstIndex, localLength);
                index += localLength;
                dstIndex += localLength;
                length -= localLength;
                i++;
            }
        }
    }

    public int getBytes(int index, GatheringByteChannel out, int length) throws IOException {
        if (useGathering()) {
            return (int) out.write(toByteBuffers(index, length));
        }
        return out.write(toByteBuffer(index, length));
    }

    public void getBytes(int index, OutputStream out, int length) throws IOException {
        if (index > capacity() - length) {
            throw new IndexOutOfBoundsException("Too many bytes to be read - needs " + (index + length) + ", maximum of " + capacity());
        } else if (index < 0) {
            throw new IndexOutOfBoundsException("Index must be >= 0");
        } else if (length != 0) {
            int i = componentId(index);
            while (length > 0) {
                ChannelBuffer s = this.components[i];
                int adjustment = this.indices[i];
                int localLength = Math.min(length, s.capacity() - (index - adjustment));
                s.getBytes(index - adjustment, out, localLength);
                index += localLength;
                length -= localLength;
                i++;
            }
        }
    }

    public void setByte(int index, int value) {
        int componentId = componentId(index);
        this.components[componentId].setByte(index - this.indices[componentId], value);
    }

    public void setShort(int index, int value) {
        int componentId = componentId(index);
        if (index + 2 <= this.indices[componentId + 1]) {
            this.components[componentId].setShort(index - this.indices[componentId], value);
        } else if (order() == ByteOrder.BIG_ENDIAN) {
            setByte(index, (byte) (value >>> 8));
            setByte(index + 1, (byte) value);
        } else {
            setByte(index, (byte) value);
            setByte(index + 1, (byte) (value >>> 8));
        }
    }

    public void setMedium(int index, int value) {
        int componentId = componentId(index);
        if (index + 3 <= this.indices[componentId + 1]) {
            this.components[componentId].setMedium(index - this.indices[componentId], value);
        } else if (order() == ByteOrder.BIG_ENDIAN) {
            setShort(index, (short) (value >> 8));
            setByte(index + 2, (byte) value);
        } else {
            setShort(index, (short) value);
            setByte(index + 2, (byte) (value >>> 16));
        }
    }

    public void setInt(int index, int value) {
        int componentId = componentId(index);
        if (index + 4 <= this.indices[componentId + 1]) {
            this.components[componentId].setInt(index - this.indices[componentId], value);
        } else if (order() == ByteOrder.BIG_ENDIAN) {
            setShort(index, (short) (value >>> 16));
            setShort(index + 2, (short) value);
        } else {
            setShort(index, (short) value);
            setShort(index + 2, (short) (value >>> 16));
        }
    }

    public void setLong(int index, long value) {
        int componentId = componentId(index);
        if (index + 8 <= this.indices[componentId + 1]) {
            this.components[componentId].setLong(index - this.indices[componentId], value);
        } else if (order() == ByteOrder.BIG_ENDIAN) {
            setInt(index, (int) (value >>> 32));
            setInt(index + 4, (int) value);
        } else {
            setInt(index, (int) value);
            setInt(index + 4, (int) (value >>> 32));
        }
    }

    public void setBytes(int index, byte[] src, int srcIndex, int length) {
        int componentId = componentId(index);
        if (index > capacity() - length || srcIndex > src.length - length) {
            throw new IndexOutOfBoundsException("Too many bytes to read - needs " + (index + length) + " or " + (srcIndex + length) + ", maximum is " + capacity() + " or " + src.length);
        }
        int i = componentId;
        while (length > 0) {
            ChannelBuffer s = this.components[i];
            int adjustment = this.indices[i];
            int localLength = Math.min(length, s.capacity() - (index - adjustment));
            s.setBytes(index - adjustment, src, srcIndex, localLength);
            index += localLength;
            srcIndex += localLength;
            length -= localLength;
            i++;
        }
    }

    public void setBytes(int index, ByteBuffer src) {
        int componentId = componentId(index);
        int limit = src.limit();
        int length = src.remaining();
        if (index > capacity() - length) {
            throw new IndexOutOfBoundsException("Too many bytes to be written - Needs " + (index + length) + ", maximum is " + capacity());
        }
        int i = componentId;
        while (length > 0) {
            try {
                ChannelBuffer s = this.components[i];
                int adjustment = this.indices[i];
                int localLength = Math.min(length, s.capacity() - (index - adjustment));
                src.limit(src.position() + localLength);
                s.setBytes(index - adjustment, src);
                index += localLength;
                length -= localLength;
                i++;
            } catch (Throwable th) {
                src.limit(limit);
                throw th;
            }
        }
        src.limit(limit);
    }

    public void setBytes(int index, ChannelBuffer src, int srcIndex, int length) {
        int componentId = componentId(index);
        if (index > capacity() - length || srcIndex > src.capacity() - length) {
            throw new IndexOutOfBoundsException("Too many bytes to be written - Needs " + (index + length) + " or " + (srcIndex + length) + ", maximum is " + capacity() + " or " + src.capacity());
        }
        int i = componentId;
        while (length > 0) {
            ChannelBuffer s = this.components[i];
            int adjustment = this.indices[i];
            int localLength = Math.min(length, s.capacity() - (index - adjustment));
            s.setBytes(index - adjustment, src, srcIndex, localLength);
            index += localLength;
            srcIndex += localLength;
            length -= localLength;
            i++;
        }
    }

    public int setBytes(int index, InputStream in, int length) throws IOException {
        int componentId = componentId(index);
        if (index > capacity() - length) {
            throw new IndexOutOfBoundsException("Too many bytes to write - Needs " + (index + length) + ", maximum is " + capacity());
        }
        int i = componentId;
        int readBytes = 0;
        while (true) {
            ChannelBuffer s = this.components[i];
            int adjustment = this.indices[i];
            int localLength = Math.min(length, s.capacity() - (index - adjustment));
            int localReadBytes = s.setBytes(index - adjustment, in, localLength);
            if (localReadBytes >= 0) {
                if (localReadBytes == localLength) {
                    index += localLength;
                    length -= localLength;
                    readBytes += localLength;
                    i++;
                    continue;
                } else {
                    index += localReadBytes;
                    length -= localReadBytes;
                    readBytes += localReadBytes;
                    continue;
                }
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
        int componentId = componentId(index);
        if (index > capacity() - length) {
            throw new IndexOutOfBoundsException("Too many bytes to write - Needs " + (index + length) + ", maximum is " + capacity());
        }
        int i = componentId;
        int readBytes = 0;
        while (true) {
            ChannelBuffer s = this.components[i];
            int adjustment = this.indices[i];
            int localLength = Math.min(length, s.capacity() - (index - adjustment));
            int localReadBytes = s.setBytes(index - adjustment, in, localLength);
            if (localReadBytes != 0) {
                if (localReadBytes >= 0) {
                    if (localReadBytes == localLength) {
                        index += localLength;
                        length -= localLength;
                        readBytes += localLength;
                        i++;
                        continue;
                    } else {
                        index += localReadBytes;
                        length -= localReadBytes;
                        readBytes += localReadBytes;
                        continue;
                    }
                    if (length <= 0) {
                        break;
                    }
                } else if (readBytes == 0) {
                    return -1;
                }
            } else {
                break;
            }
        }
        return readBytes;
    }

    public ChannelBuffer duplicate() {
        ChannelBuffer duplicate = new CompositeChannelBuffer(this);
        duplicate.setIndex(readerIndex(), writerIndex());
        return duplicate;
    }

    public ChannelBuffer copy(int index, int length) {
        int componentId = componentId(index);
        if (index > capacity() - length) {
            throw new IndexOutOfBoundsException("Too many bytes to copy - Needs " + (index + length) + ", maximum is " + capacity());
        }
        ChannelBuffer dst = factory().getBuffer(order(), length);
        copyTo(index, length, componentId, dst);
        return dst;
    }

    private void copyTo(int index, int length, int componentId, ChannelBuffer dst) {
        int dstIndex = 0;
        int i = componentId;
        while (length > 0) {
            ChannelBuffer s = this.components[i];
            int adjustment = this.indices[i];
            int localLength = Math.min(length, s.capacity() - (index - adjustment));
            s.getBytes(index - adjustment, dst, dstIndex, localLength);
            index += localLength;
            dstIndex += localLength;
            length -= localLength;
            i++;
        }
        dst.writerIndex(dst.capacity());
    }

    public ChannelBuffer getBuffer(int index) {
        if (index >= 0 && index < capacity()) {
            return this.components[componentId(index)];
        }
        throw new IndexOutOfBoundsException("Invalid index: " + index + " - Bytes needed: " + index + ", maximum is " + capacity());
    }

    public ChannelBuffer slice(int index, int length) {
        if (index == 0) {
            if (length == 0) {
                return ChannelBuffers.EMPTY_BUFFER;
            }
        } else if (index < 0 || index > capacity() - length) {
            throw new IndexOutOfBoundsException("Invalid index: " + index + " - Bytes needed: " + (index + length) + ", maximum is " + capacity());
        } else if (length == 0) {
            return ChannelBuffers.EMPTY_BUFFER;
        }
        List<ChannelBuffer> components2 = decompose(index, length);
        switch (components2.size()) {
            case 0:
                return ChannelBuffers.EMPTY_BUFFER;
            case 1:
                return components2.get(0);
            default:
                return new CompositeChannelBuffer(order(), components2, this.gathering);
        }
    }

    public ByteBuffer toByteBuffer(int index, int length) {
        if (this.components.length == 1) {
            return this.components[0].toByteBuffer(index, length);
        }
        ByteBuffer[] buffers = toByteBuffers(index, length);
        ByteBuffer merged = ByteBuffer.allocate(length).order(order());
        for (ByteBuffer b : buffers) {
            merged.put(b);
        }
        merged.flip();
        return merged;
    }

    public ByteBuffer[] toByteBuffers(int index, int length) {
        if (index + length > capacity()) {
            throw new IndexOutOfBoundsException("Too many bytes to convert - Needs" + (index + length) + ", maximum is " + capacity());
        } else if (index < 0) {
            throw new IndexOutOfBoundsException("Index must be >= 0");
        } else if (length == 0) {
            return new ByteBuffer[0];
        } else {
            List<ByteBuffer> buffers = new ArrayList<>(this.components.length);
            int i = componentId(index);
            while (length > 0) {
                ChannelBuffer s = this.components[i];
                int adjustment = this.indices[i];
                int localLength = Math.min(length, s.capacity() - (index - adjustment));
                buffers.add(s.toByteBuffer(index - adjustment, localLength));
                index += localLength;
                length -= localLength;
                i++;
            }
            return (ByteBuffer[]) buffers.toArray(new ByteBuffer[buffers.size()]);
        }
    }

    private int componentId(int index) {
        int lastComponentId = this.lastAccessedComponentId;
        if (index < this.indices[lastComponentId]) {
            for (int i = lastComponentId - 1; i >= 0; i--) {
                if (index >= this.indices[i]) {
                    this.lastAccessedComponentId = i;
                    return i;
                }
            }
        } else if (index < this.indices[lastComponentId + 1]) {
            return lastComponentId;
        } else {
            for (int i2 = lastComponentId + 1; i2 < this.components.length; i2++) {
                if (index < this.indices[i2 + 1]) {
                    this.lastAccessedComponentId = i2;
                    return i2;
                }
            }
        }
        throw new IndexOutOfBoundsException("Invalid index: " + index + ", maximum: " + this.indices.length);
    }

    public void discardReadBytes() {
        int localReaderIndex = readerIndex();
        if (localReaderIndex != 0) {
            int localWriterIndex = writerIndex();
            List<ChannelBuffer> list = decompose(localReaderIndex, capacity() - localReaderIndex);
            if (list.isEmpty()) {
                list = new ArrayList<>(1);
            }
            ChannelBuffer padding = ChannelBuffers.buffer(order(), localReaderIndex);
            padding.writerIndex(localReaderIndex);
            list.add(padding);
            int localMarkedReaderIndex = localReaderIndex;
            try {
                resetReaderIndex();
                localMarkedReaderIndex = readerIndex();
            } catch (IndexOutOfBoundsException e) {
            }
            int localMarkedWriterIndex = localWriterIndex;
            try {
                resetWriterIndex();
                localMarkedWriterIndex = writerIndex();
            } catch (IndexOutOfBoundsException e2) {
            }
            setComponents(list);
            setIndex(Math.max(localMarkedReaderIndex - localReaderIndex, 0), Math.max(localMarkedWriterIndex - localReaderIndex, 0));
            markReaderIndex();
            markWriterIndex();
            setIndex(0, Math.max(localWriterIndex - localReaderIndex, 0));
        }
    }

    public String toString() {
        String result = super.toString();
        return result.substring(0, result.length() - 1) + ", components=" + this.components.length + ')';
    }
}