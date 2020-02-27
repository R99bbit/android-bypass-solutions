package org.jboss.netty.buffer;

import java.nio.ByteOrder;

public class BigEndianHeapChannelBuffer extends HeapChannelBuffer {
    public BigEndianHeapChannelBuffer(int length) {
        super(length);
    }

    public BigEndianHeapChannelBuffer(byte[] array) {
        super(array);
    }

    private BigEndianHeapChannelBuffer(byte[] array, int readerIndex, int writerIndex) {
        super(array, readerIndex, writerIndex);
    }

    public ChannelBufferFactory factory() {
        return HeapChannelBufferFactory.getInstance(ByteOrder.BIG_ENDIAN);
    }

    public ByteOrder order() {
        return ByteOrder.BIG_ENDIAN;
    }

    public short getShort(int index) {
        return (short) ((this.array[index] << 8) | (this.array[index + 1] & 255));
    }

    public int getUnsignedMedium(int index) {
        return ((this.array[index] & 255) << 16) | ((this.array[index + 1] & 255) << 8) | (this.array[index + 2] & 255);
    }

    public int getInt(int index) {
        return ((this.array[index] & 255) << 24) | ((this.array[index + 1] & 255) << 16) | ((this.array[index + 2] & 255) << 8) | (this.array[index + 3] & 255);
    }

    public long getLong(int index) {
        return ((((long) this.array[index]) & 255) << 56) | ((((long) this.array[index + 1]) & 255) << 48) | ((((long) this.array[index + 2]) & 255) << 40) | ((((long) this.array[index + 3]) & 255) << 32) | ((((long) this.array[index + 4]) & 255) << 24) | ((((long) this.array[index + 5]) & 255) << 16) | ((((long) this.array[index + 6]) & 255) << 8) | (((long) this.array[index + 7]) & 255);
    }

    public void setShort(int index, int value) {
        this.array[index] = (byte) (value >>> 8);
        this.array[index + 1] = (byte) value;
    }

    public void setMedium(int index, int value) {
        this.array[index] = (byte) (value >>> 16);
        this.array[index + 1] = (byte) (value >>> 8);
        this.array[index + 2] = (byte) value;
    }

    public void setInt(int index, int value) {
        this.array[index] = (byte) (value >>> 24);
        this.array[index + 1] = (byte) (value >>> 16);
        this.array[index + 2] = (byte) (value >>> 8);
        this.array[index + 3] = (byte) value;
    }

    public void setLong(int index, long value) {
        this.array[index] = (byte) ((int) (value >>> 56));
        this.array[index + 1] = (byte) ((int) (value >>> 48));
        this.array[index + 2] = (byte) ((int) (value >>> 40));
        this.array[index + 3] = (byte) ((int) (value >>> 32));
        this.array[index + 4] = (byte) ((int) (value >>> 24));
        this.array[index + 5] = (byte) ((int) (value >>> 16));
        this.array[index + 6] = (byte) ((int) (value >>> 8));
        this.array[index + 7] = (byte) ((int) value);
    }

    public ChannelBuffer duplicate() {
        return new BigEndianHeapChannelBuffer(this.array, readerIndex(), writerIndex());
    }

    public ChannelBuffer copy(int index, int length) {
        if (index < 0 || length < 0 || index + length > this.array.length) {
            throw new IndexOutOfBoundsException("Too many bytes to copy - Need " + (index + length) + ", maximum is " + this.array.length);
        }
        byte[] copiedArray = new byte[length];
        System.arraycopy(this.array, index, copiedArray, 0, length);
        return new BigEndianHeapChannelBuffer(copiedArray);
    }
}