package com.ning.http.util;

import java.io.UnsupportedEncodingException;

public class UTF8Codec {
    private static final String ENCODING_UTF8 = "UTF-8";

    public static byte[] toUTF8(String input) {
        try {
            return input.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException();
        }
    }

    public static String fromUTF8(byte[] input) {
        return fromUTF8(input, 0, input.length);
    }

    public static String fromUTF8(byte[] input, int offset, int len) {
        try {
            return new String(input, offset, len, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException();
        }
    }
}