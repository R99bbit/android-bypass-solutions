package com.nuvent.shareat.util;

import com.facebook.appevents.AppEventsConstants;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AES {
    private static final String ASP_KeyString = "NuVent1!qa@ws3ed";
    private static final String algorithm = "AES";
    private static final Key key = new SecretKeySpec(ASP_KeyString.getBytes(), algorithm);
    private static final String transformation = "AES/ECB/PKCS5Padding";

    public static String encrypt(String src) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(1, key);
            return byteArrayToHex(cipher.doFinal(src.getBytes()));
        } catch (Exception e) {
            return "EncryptError";
        }
    }

    public static String decrypt(String src) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(ASP_KeyString.getBytes(), algorithm);
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(2, skeySpec);
            return new String(cipher.doFinal(hexToByteArray(src)));
        } catch (Exception e) {
            return "DecryptError : " + e.getMessage();
        }
    }

    public static String decrypt(String src, String sKey) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(sKey.getBytes(), algorithm);
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(2, skeySpec);
            return new String(cipher.doFinal(hexToByteArray(src)));
        } catch (Exception e) {
            return "DecryptError : " + e.getMessage();
        }
    }

    private static byte[] hexToByteArray(String s) {
        byte[] retValue = null;
        if (!(s == null || s.length() == 0)) {
            retValue = new byte[(s.length() / 2)];
            for (int i = 0; i < retValue.length; i++) {
                retValue[i] = (byte) Integer.parseInt(s.substring(i * 2, (i * 2) + 2), 16);
            }
        }
        return retValue;
    }

    private static String byteArrayToHex(byte[] buf) {
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        for (int i = 0; i < buf.length; i++) {
            if ((buf[i] & 255) < 16) {
                strbuf.append(AppEventsConstants.EVENT_PARAM_VALUE_NO);
            }
            strbuf.append(Long.toString((long) (buf[i] & 255), 16));
        }
        return strbuf.toString();
    }
}