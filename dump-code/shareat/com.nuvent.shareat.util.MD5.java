package com.nuvent.shareat.util;

import java.security.MessageDigest;

public class MD5 {
    public static String makeMD5(String str) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] msg1 = str.getBytes();
        int nread = msg1.length;
        byte[] dataBytes = new byte[1024];
        for (int i = 0; i < nread; i++) {
            dataBytes[i] = msg1[i];
        }
        md.update(dataBytes, 0, nread);
        byte[] mdbytes = md.digest();
        StringBuffer sb = new StringBuffer();
        for (byte b : mdbytes) {
            sb.append(Integer.toString((b & 255) + 256, 16).substring(1));
        }
        return sb.toString();
    }
}