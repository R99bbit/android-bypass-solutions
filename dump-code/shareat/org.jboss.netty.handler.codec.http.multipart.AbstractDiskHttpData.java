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

public abstract class AbstractDiskHttpData extends AbstractHttpData {
    protected File file;
    private FileChannel fileChannel;
    private boolean isRenamed;

    /* access modifiers changed from: protected */
    public abstract boolean deleteOnExit();

    /* access modifiers changed from: protected */
    public abstract String getBaseDirectory();

    /* access modifiers changed from: protected */
    public abstract String getDiskFilename();

    /* access modifiers changed from: protected */
    public abstract String getPostfix();

    /* access modifiers changed from: protected */
    public abstract String getPrefix();

    protected AbstractDiskHttpData(String name, Charset charset, long size) {
        super(name, charset, size);
    }

    private File tempFile() throws IOException {
        String newpostfix;
        File tmpFile;
        String diskFilename = getDiskFilename();
        if (diskFilename != null) {
            newpostfix = '_' + diskFilename;
        } else {
            newpostfix = getPostfix();
        }
        if (getBaseDirectory() == null) {
            tmpFile = File.createTempFile(getPrefix(), newpostfix);
        } else {
            tmpFile = File.createTempFile(getPrefix(), newpostfix, new File(getBaseDirectory()));
        }
        if (deleteOnExit()) {
            tmpFile.deleteOnExit();
        }
        return tmpFile;
    }

    public void setContent(ChannelBuffer buffer) throws IOException {
        if (buffer == null) {
            throw new NullPointerException("buffer");
        }
        this.size = (long) buffer.readableBytes();
        checkSize(this.size);
        if (this.definedSize <= 0 || this.definedSize >= this.size) {
            if (this.file == null) {
                this.file = tempFile();
            }
            if (buffer.readableBytes() == 0) {
                this.file.createNewFile();
                return;
            }
            FileOutputStream outputStream = new FileOutputStream(this.file);
            FileChannel localfileChannel = outputStream.getChannel();
            ByteBuffer byteBuffer = buffer.toByteBuffer();
            int written = 0;
            while (((long) written) < this.size) {
                written += localfileChannel.write(byteBuffer);
            }
            buffer.readerIndex(buffer.readerIndex() + written);
            localfileChannel.force(false);
            localfileChannel.close();
            outputStream.close();
            this.completed = true;
            return;
        }
        throw new IOException("Out of size: " + this.size + " > " + this.definedSize);
    }

    public void addContent(ChannelBuffer buffer, boolean last) throws IOException {
        if (buffer != null) {
            int localsize = buffer.readableBytes();
            checkSize(this.size + ((long) localsize));
            if (this.definedSize <= 0 || this.definedSize >= this.size + ((long) localsize)) {
                ByteBuffer byteBuffer = buffer.toByteBuffer();
                int written = 0;
                if (this.file == null) {
                    this.file = tempFile();
                }
                if (this.fileChannel == null) {
                    this.fileChannel = new FileOutputStream(this.file).getChannel();
                }
                while (written < localsize) {
                    written += this.fileChannel.write(byteBuffer);
                }
                this.size += (long) localsize;
                buffer.readerIndex(buffer.readerIndex() + written);
            } else {
                throw new IOException("Out of size: " + (this.size + ((long) localsize)) + " > " + this.definedSize);
            }
        }
        if (last) {
            if (this.file == null) {
                this.file = tempFile();
            }
            if (this.fileChannel == null) {
                this.fileChannel = new FileOutputStream(this.file).getChannel();
            }
            this.fileChannel.force(false);
            this.fileChannel.close();
            this.fileChannel = null;
            this.completed = true;
        } else if (buffer == null) {
            throw new NullPointerException("buffer");
        }
    }

    public void setContent(File file2) throws IOException {
        if (this.file != null) {
            delete();
        }
        this.file = file2;
        this.size = file2.length();
        checkSize(this.size);
        this.isRenamed = true;
        this.completed = true;
    }

    public void setContent(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            throw new NullPointerException("inputStream");
        }
        if (this.file != null) {
            delete();
        }
        this.file = tempFile();
        FileChannel localfileChannel = new FileOutputStream(this.file).getChannel();
        byte[] bytes = new byte[16384];
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        int read = inputStream.read(bytes);
        int written = 0;
        while (read > 0) {
            byteBuffer.position(read).flip();
            written += localfileChannel.write(byteBuffer);
            checkSize((long) written);
            read = inputStream.read(bytes);
        }
        localfileChannel.force(false);
        localfileChannel.close();
        this.size = (long) written;
        if (this.definedSize <= 0 || this.definedSize >= this.size) {
            this.isRenamed = true;
            this.completed = true;
            return;
        }
        this.file.delete();
        this.file = null;
        throw new IOException("Out of size: " + this.size + " > " + this.definedSize);
    }

    public void delete() {
        if (!this.isRenamed && this.file != null) {
            this.file.delete();
        }
    }

    public byte[] get() throws IOException {
        if (this.file == null) {
            return new byte[0];
        }
        return readFrom(this.file);
    }

    public ChannelBuffer getChannelBuffer() throws IOException {
        if (this.file == null) {
            return ChannelBuffers.EMPTY_BUFFER;
        }
        return ChannelBuffers.wrappedBuffer(readFrom(this.file));
    }

    public ChannelBuffer getChunk(int length) throws IOException {
        if (this.file == null || length == 0) {
            return ChannelBuffers.EMPTY_BUFFER;
        }
        if (this.fileChannel == null) {
            this.fileChannel = new FileInputStream(this.file).getChannel();
        }
        int read = 0;
        ByteBuffer byteBuffer = ByteBuffer.allocate(length);
        while (true) {
            if (read >= length) {
                break;
            }
            int readnow = this.fileChannel.read(byteBuffer);
            if (readnow == -1) {
                this.fileChannel.close();
                this.fileChannel = null;
                break;
            }
            read += readnow;
        }
        if (read == 0) {
            return ChannelBuffers.EMPTY_BUFFER;
        }
        byteBuffer.flip();
        ChannelBuffer buffer = ChannelBuffers.wrappedBuffer(byteBuffer);
        buffer.readerIndex(0);
        buffer.writerIndex(read);
        return buffer;
    }

    public String getString() throws IOException {
        return getString(HttpConstants.DEFAULT_CHARSET);
    }

    public String getString(Charset encoding) throws IOException {
        if (this.file == null) {
            return "";
        }
        if (encoding == null) {
            return new String(readFrom(this.file), HttpConstants.DEFAULT_CHARSET.name());
        }
        return new String(readFrom(this.file), encoding.name());
    }

    public boolean isInMemory() {
        return false;
    }

    public boolean renameTo(File dest) throws IOException {
        if (dest == null) {
            throw new NullPointerException("dest");
        } else if (!this.file.renameTo(dest)) {
            FileInputStream inputStream = new FileInputStream(this.file);
            FileOutputStream outputStream = new FileOutputStream(dest);
            FileChannel in = inputStream.getChannel();
            FileChannel out = outputStream.getChannel();
            int chunkSize = 8196;
            long position = 0;
            while (position < this.size) {
                if (((long) chunkSize) < this.size - position) {
                    chunkSize = (int) (this.size - position);
                }
                position += in.transferTo(position, (long) chunkSize, out);
            }
            in.close();
            out.close();
            if (position == this.size) {
                this.file.delete();
                this.file = dest;
                this.isRenamed = true;
                return true;
            }
            dest.delete();
            return false;
        } else {
            this.file = dest;
            this.isRenamed = true;
            return true;
        }
    }

    private static byte[] readFrom(File src) throws IOException {
        long srcsize = src.length();
        if (srcsize > 2147483647L) {
            throw new IllegalArgumentException("File too big to be loaded in memory");
        }
        FileChannel fileChannel2 = new FileInputStream(src).getChannel();
        byte[] array = new byte[((int) srcsize)];
        ByteBuffer byteBuffer = ByteBuffer.wrap(array);
        for (int read = 0; ((long) read) < srcsize; read += fileChannel2.read(byteBuffer)) {
        }
        fileChannel2.close();
        return array;
    }

    public File getFile() throws IOException {
        return this.file;
    }
}