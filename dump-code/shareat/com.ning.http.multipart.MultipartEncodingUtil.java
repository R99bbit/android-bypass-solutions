package com.ning.http.multipart;

import java.io.UnsupportedEncodingException;

public class MultipartEncodingUtil {
    public static byte[] getAsciiBytes(String data) {
        try {
            return data.getBytes(StringPart.DEFAULT_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getAsciiString(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Parameter may not be null");
        }
        try {
            return new String(data, StringPart.DEFAULT_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getBytes(String data, String charset) {
        if (data == null) {
            throw new IllegalArgumentException("data may not be null");
        } else if (charset == null || charset.length() == 0) {
            throw new IllegalArgumentException("charset may not be null or empty");
        } else {
            try {
                return data.getBytes(charset);
            } catch (UnsupportedEncodingException e) {
                throw new IllegalArgumentException(String.format("Unsupported encoding: %s", new Object[]{charset}));
            }
        }
    }
}