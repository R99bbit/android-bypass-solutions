package com.ning.http.client.oauth;

import com.ning.http.util.UTF8Codec;
import com.ning.http.util.UTF8UrlEncoder;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class ThreadSafeHMAC {
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private final Mac mac;

    public ThreadSafeHMAC(ConsumerKey consumerAuth, RequestToken userAuth) {
        SecretKeySpec signingKey = new SecretKeySpec(UTF8Codec.toUTF8(UTF8UrlEncoder.encode(consumerAuth.getSecret()) + "&" + UTF8UrlEncoder.encode(userAuth.getSecret())), HMAC_SHA1_ALGORITHM);
        try {
            this.mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            this.mac.init(signingKey);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public synchronized byte[] digest(byte[] message) {
        try {
            this.mac.reset();
        }
        return this.mac.doFinal(message);
    }
}