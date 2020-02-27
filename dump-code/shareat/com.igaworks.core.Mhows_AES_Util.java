package com.igaworks.core;

import com.igaworks.util.IgawBase64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Mhows_AES_Util {
    public static String key = "";

    public static String encrypt(String message) throws Exception {
        key = IgawBase64.decodeString(SDKConfig.ENCODE_MHOWS_UTIL_KEY);
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(1, skeySpec);
        return new String(IgawBase64.encode(cipher.doFinal(message.getBytes())));
    }

    public static String decrypt(String encrypted) throws Exception {
        key = IgawBase64.decodeString(SDKConfig.ENCODE_MHOWS_UTIL_KEY);
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(2, skeySpec);
        return new String(cipher.doFinal(IgawBase64.decode(encrypted)));
    }
}