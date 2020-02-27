package org.jboss.netty.handler.codec.http.multipart;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData.HttpDataType;

public class MixedAttribute implements Attribute {
    private Attribute attribute;
    private final long limitSize;
    protected long maxSize = -1;

    public MixedAttribute(String name, long limitSize2) {
        this.limitSize = limitSize2;
        this.attribute = new MemoryAttribute(name);
    }

    public MixedAttribute(String name, String value, long limitSize2) {
        this.limitSize = limitSize2;
        if (((long) value.length()) > this.limitSize) {
            try {
                this.attribute = new DiskAttribute(name, value);
            } catch (IOException e) {
                try {
                    this.attribute = new MemoryAttribute(name, value);
                } catch (IOException e2) {
                    throw new IllegalArgumentException(e);
                }
            }
        } else {
            try {
                this.attribute = new MemoryAttribute(name, value);
            } catch (IOException e3) {
                throw new IllegalArgumentException(e3);
            }
        }
    }

    public void setMaxSize(long maxSize2) {
        this.maxSize = maxSize2;
        this.attribute.setMaxSize(maxSize2);
    }

    public void checkSize(long newSize) throws IOException {
        if (this.maxSize >= 0 && newSize > this.maxSize) {
            throw new IOException("Size exceed allowed maximum capacity");
        }
    }

    public void addContent(ChannelBuffer buffer, boolean last) throws IOException {
        if (this.attribute instanceof MemoryAttribute) {
            checkSize(this.attribute.length() + ((long) buffer.readableBytes()));
            if (this.attribute.length() + ((long) buffer.readableBytes()) > this.limitSize) {
                DiskAttribute diskAttribute = new DiskAttribute(this.attribute.getName());
                diskAttribute.setMaxSize(this.maxSize);
                if (((MemoryAttribute) this.attribute).getChannelBuffer() != null) {
                    diskAttribute.addContent(((MemoryAttribute) this.attribute).getChannelBuffer(), false);
                }
                this.attribute = diskAttribute;
            }
        }
        this.attribute.addContent(buffer, last);
    }

    public void delete() {
        this.attribute.delete();
    }

    public byte[] get() throws IOException {
        return this.attribute.get();
    }

    public ChannelBuffer getChannelBuffer() throws IOException {
        return this.attribute.getChannelBuffer();
    }

    public Charset getCharset() {
        return this.attribute.getCharset();
    }

    public String getString() throws IOException {
        return this.attribute.getString();
    }

    public String getString(Charset encoding) throws IOException {
        return this.attribute.getString(encoding);
    }

    public boolean isCompleted() {
        return this.attribute.isCompleted();
    }

    public boolean isInMemory() {
        return this.attribute.isInMemory();
    }

    public long length() {
        return this.attribute.length();
    }

    public boolean renameTo(File dest) throws IOException {
        return this.attribute.renameTo(dest);
    }

    public void setCharset(Charset charset) {
        this.attribute.setCharset(charset);
    }

    public void setContent(ChannelBuffer buffer) throws IOException {
        checkSize((long) buffer.readableBytes());
        if (((long) buffer.readableBytes()) > this.limitSize && (this.attribute instanceof MemoryAttribute)) {
            this.attribute = new DiskAttribute(this.attribute.getName());
            this.attribute.setMaxSize(this.maxSize);
        }
        this.attribute.setContent(buffer);
    }

    public void setContent(File file) throws IOException {
        checkSize(file.length());
        if (file.length() > this.limitSize && (this.attribute instanceof MemoryAttribute)) {
            this.attribute = new DiskAttribute(this.attribute.getName());
            this.attribute.setMaxSize(this.maxSize);
        }
        this.attribute.setContent(file);
    }

    public void setContent(InputStream inputStream) throws IOException {
        if (this.attribute instanceof MemoryAttribute) {
            this.attribute = new DiskAttribute(this.attribute.getName());
            this.attribute.setMaxSize(this.maxSize);
        }
        this.attribute.setContent(inputStream);
    }

    public HttpDataType getHttpDataType() {
        return this.attribute.getHttpDataType();
    }

    public String getName() {
        return this.attribute.getName();
    }

    public int compareTo(InterfaceHttpData o) {
        return this.attribute.compareTo(o);
    }

    public String toString() {
        return "Mixed: " + this.attribute.toString();
    }

    public String getValue() throws IOException {
        return this.attribute.getValue();
    }

    public void setValue(String value) throws IOException {
        if (value != null) {
            checkSize((long) value.getBytes().length);
        }
        this.attribute.setValue(value);
    }

    public ChannelBuffer getChunk(int length) throws IOException {
        return this.attribute.getChunk(length);
    }

    public File getFile() throws IOException {
        return this.attribute.getFile();
    }
}