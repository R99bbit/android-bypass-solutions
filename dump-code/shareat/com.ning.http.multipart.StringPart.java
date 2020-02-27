package com.ning.http.multipart;

import java.io.IOException;
import java.io.OutputStream;

public class StringPart extends PartBase {
    public static final String DEFAULT_CHARSET = "US-ASCII";
    public static final String DEFAULT_CONTENT_TYPE = "text/plain";
    public static final String DEFAULT_TRANSFER_ENCODING = "8bit";
    private byte[] content;
    private final String value;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public StringPart(String name, String value2, String charset, String contentId) {
        String str;
        // if (charset == null) {
            // str = DEFAULT_CHARSET;
        // } else {
            // str = charset;
        // }
        super(name, "text/plain", str, DEFAULT_TRANSFER_ENCODING, contentId);
        if (value2 == null) {
            throw new IllegalArgumentException("Value may not be null");
        } else if (value2.indexOf(0) != -1) {
            throw new IllegalArgumentException("NULs may not be present in string parts");
        } else {
            this.value = value2;
        }
    }

    public StringPart(String name, String value2, String charset) {
        this(name, value2, charset, null);
    }

    public StringPart(String name, String value2) {
        this(name, value2, null);
    }

    private byte[] getContent() {
        if (this.content == null) {
            this.content = MultipartEncodingUtil.getBytes(this.value, getCharSet());
        }
        return this.content;
    }

    /* access modifiers changed from: protected */
    public void sendData(OutputStream out) throws IOException {
        out.write(getContent());
    }

    /* access modifiers changed from: protected */
    public long lengthOfData() {
        return (long) getContent().length;
    }

    public void setCharSet(String charSet) {
        super.setCharSet(charSet);
        this.content = null;
    }
}