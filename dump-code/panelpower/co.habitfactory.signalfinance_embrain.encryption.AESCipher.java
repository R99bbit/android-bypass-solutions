package co.habitfactory.signalfinance_embrain.encryption;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher {
    public static String Decrypt(String str, String str2) throws Exception {
        Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] bArr = new byte[16];
        byte[] bytes = str2.getBytes("UTF-8");
        int length = bytes.length;
        if (length > bArr.length) {
            length = bArr.length;
        }
        System.arraycopy(bytes, 0, bArr, 0, length);
        instance.init(2, new SecretKeySpec(bArr, "AES"), new IvParameterSpec(bArr));
        return new String(instance.doFinal(Base64.decode(str, 0)), "UTF-8");
    }

    public static String Encrypt(String str, String str2) throws Exception {
        Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] bArr = new byte[16];
        byte[] bytes = str2.getBytes("UTF-8");
        int length = bytes.length;
        if (length > bArr.length) {
            length = bArr.length;
        }
        System.arraycopy(bytes, 0, bArr, 0, length);
        instance.init(1, new SecretKeySpec(bArr, "AES"), new IvParameterSpec(bArr));
        return Base64.encodeToString(instance.doFinal(str.getBytes("UTF-8")), 0);
    }
}