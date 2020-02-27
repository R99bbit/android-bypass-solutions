package com.ning.http.client.providers.netty;

import com.ning.http.multipart.StringPart;
import com.ning.http.util.Base64;
import io.fabric.sdk.android.services.common.CommonUtils;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class WebSocketUtil {
    public static final String MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    public static String getKey() {
        return base64Encode(createRandomBytes(16));
    }

    public static String getAcceptKey(String key) throws UnsupportedEncodingException {
        return base64Encode(sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StringPart.DEFAULT_CHARSET)));
    }

    public static byte[] md5(byte[] bytes) {
        try {
            return MessageDigest.getInstance(CommonUtils.MD5_INSTANCE).digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("MD5 not supported on this platform");
        }
    }

    public static byte[] sha1(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA1").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("SHA-1 not supported on this platform");
        }
    }

    public static String base64Encode(byte[] bytes) {
        return Base64.encode(bytes);
    }

    public static byte[] createRandomBytes(int size) {
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            bytes[i] = (byte) createRandomNumber(0, 255);
        }
        return bytes;
    }

    public static int createRandomNumber(int min, int max) {
        return (int) ((Math.random() * ((double) max)) + ((double) min));
    }
}