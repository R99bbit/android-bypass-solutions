package com.ning.http.multipart;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ByteArrayPartSource implements PartSource {
    private final byte[] bytes;
    private final String fileName;

    public ByteArrayPartSource(String fileName2, byte[] bytes2) {
        this.fileName = fileName2;
        this.bytes = bytes2;
    }

    public long getLength() {
        return (long) this.bytes.length;
    }

    public String getFileName() {
        return this.fileName;
    }

    public InputStream createInputStream() throws IOException {
        return new ByteArrayInputStream(this.bytes);
    }
}