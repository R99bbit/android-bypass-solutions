package org.jboss.netty.buffer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.ReadOnlyBufferException;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.ScatteringByteChannel;

public class ReadOnlyChannelBuffer extends AbstractChannelBuffer implements WrappedChannelBuffer {
    private final ChannelBuffer buffer;

    public ReadOnlyChannelBuffer(ChannelBuffer buffer2) {
        if (buffer2 == null) {
            throw new NullPointerException("buffer");
        }
        this.buffer = buffer2;
        setIndex(buffer2.readerIndex(), buffer2.writerIndex());
    }

    private ReadOnlyChannelBuffer(ReadOnlyChannelBuffer buffer2) {
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

    public boolean hasArray() {
        return false;
    }

    public byte[] array() {
        throw new ReadOnlyBufferException();
    }

    public int arrayOffset() {
        throw new ReadOnlyBufferException();
    }

    public void discardReadBytes() {
        throw new ReadOnlyBufferException();
    }

    public void setByte(int index, int value) {
        throw new ReadOnlyBufferException();
    }

    public void setBytes(int index, ChannelBuffer src, int srcIndex, int length) {
        throw new ReadOnlyBufferException();
    }

    public void setBytes(int index, byte[] src, int srcIndex, int length) {
        throw new ReadOnlyBufferException();
    }

    public void setBytes(int index, ByteBuffer src) {
        throw new ReadOnlyBufferException();
    }

    public void setShort(int index, int value) {
        throw new ReadOnlyBufferException();
    }

    public void setMedium(int index, int value) {
        throw new ReadOnlyBufferException();
    }

    public void setInt(int index, int value) {
        throw new ReadOnlyBufferException();
    }

    public void setLong(int index, long value) {
        throw new ReadOnlyBufferException();
    }

    public int setBytes(int index, InputStream in, int length) throws IOException {
        throw new ReadOnlyBufferException();
    }

    public int setBytes(int index, ScatteringByteChannel in, int length) throws IOException {
        throw new ReadOnlyBufferException();
    }

    public int getBytes(int index, GatheringByteChannel out, int length) throws IOException {
        return this.buffer.getBytes(index, out, length);
    }

    public void getBytes(int index, OutputStream out, int length) throws IOException {
        this.buffer.getBytes(index, out, length);
    }

    public void getBytes(int index, byte[] dst, int dstIndex, int length) {
        this.buffer.getBytes(index, dst, dstIndex, length);
    }

    public void getBytes(int index, ChannelBuffer dst, int dstIndex, int length) {
        this.buffer.getBytes(index, dst, dstIndex, length);
    }

    public void getBytes(int index, ByteBuffer dst) {
        this.buffer.getBytes(index, dst);
    }

    public ChannelBuffer duplicate() {
        return new ReadOnlyChannelBuffer(this);
    }

    public ChannelBuffer copy(int index, int length) {
        return this.buffer.copy(index, length);
    }

    public ChannelBuffer slice(int index, int length) {
        return new ReadOnlyChannelBuffer(this.buffer.slice(index, length));
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

    public ByteBuffer toByteBuffer(int index, int length) {
        return this.buffer.toByteBuffer(index, length).asReadOnlyBuffer();
    }

    public ByteBuffer[] toByteBuffers(int index, int length) {
        ByteBuffer[] bufs = this.buffer.toByteBuffers(index, length);
        for (int i = 0; i < bufs.length; i++) {
            bufs[i] = bufs[i].asReadOnlyBuffer();
        }
        return bufs;
    }

    public int capacity() {
        return this.buffer.capacity();
    }
}