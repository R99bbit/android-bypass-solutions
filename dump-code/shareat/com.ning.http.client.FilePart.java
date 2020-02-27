package com.ning.http.client;

import java.io.File;

public class FilePart implements Part {
    private final String charSet;
    private final File file;
    private final String mimeType;
    private final String name;

    public FilePart(String name2, File file2, String mimeType2, String charSet2) {
        this.name = name2;
        this.file = file2;
        this.mimeType = mimeType2;
        this.charSet = charSet2;
    }

    public String getName() {
        return this.name;
    }

    public File getFile() {
        return this.file;
    }

    public String getMimeType() {
        return this.mimeType;
    }

    public String getCharSet() {
        return this.charSet;
    }
}