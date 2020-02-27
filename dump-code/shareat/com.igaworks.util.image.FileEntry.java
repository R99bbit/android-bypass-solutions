package com.igaworks.util.image;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class FileEntry {
    private File file;
    private String key;

    public FileEntry(String key2, File file2) {
        this.key = key2;
        this.file = file2;
    }

    public InputStream getInputStream() throws IOException {
        return new BufferedInputStream(new FileInputStream(this.file));
    }

    public String getKey() {
        return this.key;
    }

    public File getFile() {
        return this.file;
    }
}