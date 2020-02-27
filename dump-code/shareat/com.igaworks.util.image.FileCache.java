package com.igaworks.util.image;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public interface FileCache {
    void clear();

    FileEntry get(String str);

    void put(String str, ByteProvider byteProvider) throws IOException;

    void put(String str, File file, boolean z) throws IOException;

    void put(String str, InputStream inputStream) throws IOException;

    void remove(String str);
}