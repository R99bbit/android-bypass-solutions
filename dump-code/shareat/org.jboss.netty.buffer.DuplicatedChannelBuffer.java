package org.jboss.netty.buffer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.ScatteringByteChannel;

public class DuplicatedChannelBuffer extends AbstractChannelBuffer implements WrappedChannelBuffer {
    private final ChannelBuffer buffer;

    public DuplicatedChannelBuffer(ChannelBuffer buffer2) {
        if (buffer2 == null) {
            throw new NullPointerException("buffer");
        }
        this.buffer = buffer2;
        setIndex(buffer2.readerIndex(), buffer2.writerIndex());
    }

    private DuplicatedChannelBuffer(DuplicatedChannelBuffer buffer2) {
        this.buffer = buffer2.buffer;
        setIndex(buffer2.readerIndex(), buffer2.writerIndex());
    }

    public ChannelBuffer unwrap() {
        return this.buffer;
    }

    public ChannelBufferFactory factory() {
        return this.buffer.factory();
    }

    public ByteOrder order() {
        return this.buffer.order();
    }

    public boolean isDirect() {
        return this.buffer.isDirect();
    }

    public int capacity() {
        return this.buffer.capacity();
    }

    public boolean hasArray() {
        return this.buffer.hasArray();
    }

    public byte[] array() {
        return this.buffer.array();
    }

    public int arrayOffset() {
        return this.buffer.arrayOffset();
    }

    public byte getByte(int index) {
        return this.buffer.getByte(index);
    }

    public short getShort(int index) {
        return this.buffer.getShort(index);
    }

    public int getUnsignedMedium(int index) {
        return this.buffer.getUnsignedMedium(index);
    }

    public int getInt(int index) {
        return this.buffer.getInt(index);
    }

    public long getLong(int index) {
        return this.buffer.getLong(index);
    }

    public ChannelBuffer duplicate() {
        return new DuplicatedChannelBuffer(this);
    }

    public ChannelBuffer copy(int index, int length) {
        return this.buffer.copy(index, length);
    }

    public ChannelBuffer slice(int index, int length) {
        return this.buffer.slice(index, length);
    }

    public void getBytes(int index, ChannelBuffer dst, int dstIndex, int length) {
        this.buffer.getBytes(index, dst, dstIndex, length);
    }

    public void getBytes(int index, byte[] dst, int dstIndex, int length) {
        this.buffer.getBytes(index, dst, dstIndex, length);
    }

    public void getBytes(int index, ByteBuffer dst) {
        this.buffer.getBytes(index, dst);
    }

    public void setByte(int index, int value) {
        this.buffer.setByte(index, value);
    }

    public void setShort(int index, int value) {
        this.buffer.setShort(index, value);
    }

    public void setMedium(int index, int value) {
        this.buffer.setMedium(index, value);
    }

    public void setInt(int index, int value) {
        this.buffer.setInt(index, value);
    }

    public void setLong(int index, long value) {
        this.buffer.setLong(index, value);
    }

    public void setBytes(int index, byte[] src, int srcIndex, int length) {
        this.buffer.setBytes(index, src, srcIndex, length);
    }

    public void setBytes(int index, ChannelBuffer src, int srcIndex, int length) {
        this.buffer.setBytes(index, src, srcIndex, length);
    }

    public void setBytes(int index, ByteBuffer src) {
        this.buffer.setBytes(index, src);
    }

    public void getBytes(int index, OutputStream out, int length) throws IOException {
        this.buffer.getBytes(index, out, length);
    }

    public int getBytes(int index, GatheringByteChannel out, int length) throws IOException {
        return this.buffer.getBytes(index, out, length);
    }

    public int setBytes(int index, InputStream in, int length) throws IOException {
        return this.buffer.setBytes(index, in, length);
    }

    public int setBytes(int index, ScatteringByteChannel in, int length) throws IOException {
        return this.buffer.setBytes(index, in, length);
    }

    public ByteBuffer toByteBuffer(int index, int length) {
        return this.buffer.toByteBuffer(index, length);
    }
}