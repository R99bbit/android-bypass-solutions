package org.jboss.netty.handler.codec.http.multipart;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.HttpConstants;

public abstract class AbstractMemoryHttpData extends AbstractHttpData {
    private ChannelBuffer channelBuffer;
    private int chunkPosition;
    protected boolean isRenamed;

    protected AbstractMemoryHttpData(String name, Charset charset, long size) {
        super(name, charset, size);
    }

    public void setContent(ChannelBuffer buffer) throws IOException {
        if (buffer == null) {
            throw new NullPointerException("buffer");
        }
        long localsize = (long) buffer.readableBytes();
        checkSize(localsize);
        if (this.definedSize <= 0 || this.definedSize >= localsize) {
            this.channelBuffer = buffer;
            this.size = localsize;
            this.completed = true;
            return;
        }
        throw new IOException("Out of size: " + localsize + " > " + this.definedSize);
    }

    public void setContent(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            throw new NullPointerException("inputStream");
        }
        ChannelBuffer buffer = ChannelBuffers.dynamicBuffer();
        byte[] bytes = new byte[16384];
        int read = inputStream.read(bytes);
        int written = 0;
        while (read > 0) {
            buffer.writeBytes(bytes, 0, read);
            written += read;
            checkSize((long) written);
            read = inputStream.read(bytes);
        }
        this.size = (long) written;
        if (this.definedSize <= 0 || this.definedSize >= this.size) {
            this.channelBuffer = buffer;
            this.completed = true;
            return;
        }
        throw new IOException("Out of size: " + this.size + " > " + this.definedSize);
    }

    public void addContent(ChannelBuffer buffer, boolean last) throws IOException {
        if (buffer != null) {
            long localsize = (long) buffer.readableBytes();
            checkSize(this.size + localsize);
            if (this.definedSize <= 0 || this.definedSize >= this.size + localsize) {
                this.size += localsize;
                if (this.channelBuffer == null) {
                    this.channelBuffer = buffer;
                } else {
                    this.channelBuffer = ChannelBuffers.wrappedBuffer(this.channelBuffer, buffer);
                }
            } else {
                throw new IOException("Out of size: " + (this.size + localsize) + " > " + this.definedSize);
            }
        }
        if (last) {
            this.completed = true;
        } else if (buffer == null) {
            throw new NullPointerException("buffer");
        }
    }

    public void setContent(File file) throws IOException {
        if (file == null) {
            throw new NullPointerException("file");
        }
        long newsize = file.length();
        if (newsize > 2147483647L) {
            throw new IllegalArgumentException("File too big to be loaded in memory");
        }
        checkSize(newsize);
        FileInputStream inputStream = new FileInputStream(file);
        FileChannel fileChannel = inputStream.getChannel();
        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[((int) newsize)]);
        for (int read = 0; ((long) read) < newsize; read += fileChannel.read(byteBuffer)) {
        }
        fileChannel.close();
        inputStream.close();
        byteBuffer.flip();
        this.channelBuffer = ChannelBuffers.wrappedBuffer(byteBuffer);
        this.size = newsize;
        this.completed = true;
    }

    public void delete() {
    }

    public byte[] get() {
        if (this.channelBuffer == null) {
            return new byte[0];
        }
        byte[] array = new byte[this.channelBuffer.readableBytes()];
        this.channelBuffer.getBytes(this.channelBuffer.readerIndex(), array);
        return array;
    }

    public String getString() {
        return getString(HttpConstants.DEFAULT_CHARSET);
    }

    public String getString(Charset encoding) {
        if (this.channelBuffer == null) {
            return "";
        }
        if (encoding == null) {
            encoding = HttpConstants.DEFAULT_CHARSET;
        }
        return this.channelBuffer.toString(encoding);
    }

    public ChannelBuffer getChannelBuffer() {
        return this.channelBuffer;
    }

    public ChannelBuffer getChunk(int length) throws IOException {
        if (this.channelBuffer == null || length == 0 || this.channelBuffer.readableBytes() == 0) {
            this.chunkPosition = 0;
            return ChannelBuffers.EMPTY_BUFFER;
        }
        int sizeLeft = this.channelBuffer.readableBytes() - this.chunkPosition;
        if (sizeLeft == 0) {
            this.chunkPosition = 0;
            return ChannelBuffers.EMPTY_BUFFER;
        }
        int sliceLength = length;
        if (sizeLeft < length) {
            sliceLength = sizeLeft;
        }
        ChannelBuffer slice = this.channelBuffer.slice(this.chunkPosition, sliceLength);
        this.chunkPosition += sliceLength;
        return slice;
    }

    public boolean isInMemory() {
        return true;
    }

    public boolean renameTo(File dest) throws IOException {
        if (dest == null) {
            throw new NullPointerException("dest");
        } else if (this.channelBuffer == null) {
            dest.createNewFile();
            this.isRenamed = true;
            return true;
        } else {
            int length = this.channelBuffer.readableBytes();
            FileOutputStream outputStream = new FileOutputStream(dest);
            FileChannel fileChannel = outputStream.getChannel();
            ByteBuffer byteBuffer = this.channelBuffer.toByteBuffer();
            int written = 0;
            while (written < length) {
                written += fileChannel.write(byteBuffer);
            }
            fileChannel.force(false);
            fileChannel.close();
            outputStream.close();
            this.isRenamed = true;
            if (written != length) {
                return false;
            }
            return true;
        }
    }

    public File getFile() throws IOException {
        throw new IOException("Not represented by a file");
    }
}