package com.ning.http.multipart;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class FilePart extends PartBase {
    public static final String DEFAULT_CHARSET = "ISO-8859-1";
    public static final String DEFAULT_CONTENT_TYPE = "application/octet-stream";
    public static final String DEFAULT_TRANSFER_ENCODING = "binary";
    protected static final String FILE_NAME = "; filename=";
    private static final byte[] FILE_NAME_BYTES = MultipartEncodingUtil.getAsciiBytes(FILE_NAME);
    private long _stalledTime;
    private final PartSource source;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public FilePart(String name, PartSource partSource, String contentType, String charset, String contentId) {
        String str;
        String str2;
        // if (contentType == null) {
            // str = "application/octet-stream";
        // } else {
            // str = contentType;
        // }
        // if (charset == null) {
            // str2 = "ISO-8859-1";
        // } else {
            // str2 = charset;
        // }
        super(name, str, str2, "binary", contentId);
        this._stalledTime = -1;
        if (partSource == null) {
            throw new IllegalArgumentException("Source may not be null");
        }
        this.source = partSource;
    }

    public FilePart(String name, PartSource partSource, String contentType, String charset) {
        this(name, partSource, contentType, charset, (String) null);
    }

    public FilePart(String name, PartSource partSource) {
        this(name, partSource, (String) null, (String) null);
    }

    public FilePart(String name, File file) throws FileNotFoundException {
        this(name, (PartSource) new FilePartSource(file), (String) null, (String) null);
    }

    public FilePart(String name, File file, String contentType, String charset) throws FileNotFoundException {
        this(name, (PartSource) new FilePartSource(file), contentType, charset);
    }

    public FilePart(String name, String fileName, File file) throws FileNotFoundException {
        this(name, (PartSource) new FilePartSource(fileName, file), (String) null, (String) null);
    }

    public FilePart(String name, String fileName, File file, String contentType, String charset) throws FileNotFoundException {
        this(name, (PartSource) new FilePartSource(fileName, file), contentType, charset);
    }

    /* access modifiers changed from: protected */
    public void sendDispositionHeader(OutputStream out) throws IOException {
        String filename = this.source.getFileName();
        super.sendDispositionHeader(out);
        if (filename != null) {
            out.write(FILE_NAME_BYTES);
            out.write(QUOTE_BYTES);
            out.write(MultipartEncodingUtil.getAsciiBytes(filename));
            out.write(QUOTE_BYTES);
        }
    }

    /* access modifiers changed from: protected */
    public long dispositionHeaderLength() {
        String filename = this.source.getFileName();
        long length = super.dispositionHeaderLength();
        if (filename != null) {
            return length + ((long) FILE_NAME_BYTES.length) + ((long) QUOTE_BYTES.length) + ((long) MultipartEncodingUtil.getAsciiBytes(filename).length) + ((long) QUOTE_BYTES.length);
        }
        return length;
    }

    /* access modifiers changed from: protected */
    public void sendData(OutputStream out) throws IOException {
        if (lengthOfData() != 0) {
            byte[] tmp = new byte[4096];
            InputStream instream = this.source.createInputStream();
            while (true) {
                try {
                    int len = instream.read(tmp);
                    if (len >= 0) {
                        out.write(tmp, 0, len);
                    } else {
                        return;
                    }
                } finally {
                    instream.close();
                }
            }
        }
    }

    public void setStalledTime(long ms) {
        this._stalledTime = ms;
    }

    public long getStalledTime() {
        return this._stalledTime;
    }

    /* access modifiers changed from: protected */
    public PartSource getSource() {
        return this.source;
    }

    /* access modifiers changed from: protected */
    public long lengthOfData() {
        return this.source.getLength();
    }
}