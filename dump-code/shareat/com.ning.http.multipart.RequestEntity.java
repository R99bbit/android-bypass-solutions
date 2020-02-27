package com.ning.http.multipart;

import java.io.IOException;
import java.io.OutputStream;

public interface RequestEntity {
    long getContentLength();

    String getContentType();

    boolean isRepeatable();

    void writeRequest(OutputStream outputStream) throws IOException;
}