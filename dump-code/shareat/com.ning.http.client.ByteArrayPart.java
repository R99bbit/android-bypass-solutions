package com.ning.http.client;

public class ByteArrayPart implements Part {
    private final String charSet;
    private final byte[] data;
    private final String fileName;
    private final String mimeType;
    private final String name;

    public ByteArrayPart(String name2, String fileName2, byte[] data2, String mimeType2, String charSet2) {
        this.name = name2;
        this.fileName = fileName2;
        this.data = data2;
        this.mimeType = mimeType2;
        this.charSet = charSet2;
    }

    public String getName() {
        return this.name;
    }

    public String getFileName() {
        return this.fileName;
    }

    public byte[] getData() {
        return this.data;
    }

    public String getMimeType() {
        return this.mimeType;
    }

    public String getCharSet() {
        return this.charSet;
    }
}