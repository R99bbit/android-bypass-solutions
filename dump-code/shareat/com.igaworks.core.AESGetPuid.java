package com.igaworks.core;

import com.facebook.appevents.AppEventsConstants;
import com.igaworks.util.IgawBase64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESGetPuid {
    public static String encrypt(String message) throws Exception {
        String IGAW_AES_SUPER_KEY = IgawBase64.decodeString(SDKConfig.ENCODE_SUPER_KEY);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IGAW_AES_SUPER_KEY.substring(0, 16).getBytes());
        SecretKeySpec skeySpec = new SecretKeySpec(IGAW_AES_SUPER_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(1, skeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        if (encrypted == null || encrypted.length == 0) {
            return null;
        }
        StringBuffer sb = new StringBuffer(encrypted.length * 2);
        for (byte b : encrypted) {
            String hexNumber = new StringBuilder(AppEventsConstants.EVENT_PARAM_VALUE_NO).append(Integer.toHexString(b & 255)).toString();
            sb.append(hexNumber.substring(hexNumber.length() - 2));
        }
        return sb.toString();
    }

    public static String decrypt(String encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(IgawBase64.decodeString(SDKConfig.ENCODE_SUPER_KEY).getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(2, skeySpec);
        return new String(cipher.doFinal(IgawBase64.decode(encrypted)));
    }
}