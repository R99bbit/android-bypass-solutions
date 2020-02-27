package com.ning.http.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SslUtils {
    private static SSLContext context = null;

    static class LooseTrustManager implements X509TrustManager {
        public static final LooseTrustManager INSTANCE = new LooseTrustManager();

        LooseTrustManager() {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
    }

    private static final class SSLConfig {
        public String keyManagerAlgorithm;
        public String keyManagerPassword;
        public String keyStoreLocation;
        public String keyStorePassword;
        public String keyStoreType;
        public String trustManagerAlgorithm;
        public String trustStoreLocation;
        public String trustStorePassword;
        public String trustStoreType;

        public SSLConfig() {
            this.keyStoreType = "JKS";
            this.keyStorePassword = "changeit";
            this.keyManagerAlgorithm = "SunX509";
            this.keyManagerPassword = "changeit";
            this.trustStoreType = "JKS";
            this.trustStorePassword = "changeit";
            this.trustManagerAlgorithm = "SunX509";
            this.keyStoreLocation = System.getProperty("javax.net.ssl.keyStore");
            this.keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword", "changeit");
            this.keyStoreType = System.getProperty("javax.net.ssl.keyStoreType", KeyStore.getDefaultType());
            this.keyManagerAlgorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
            if (this.keyManagerAlgorithm == null) {
                this.keyManagerAlgorithm = "SunX509";
            }
            this.keyManagerPassword = System.getProperty("javax.net.ssl.keyStorePassword", "changeit");
            this.trustStoreLocation = System.getProperty("javax.net.ssl.trustStore");
            if (this.trustStoreLocation == null) {
                this.trustStoreLocation = this.keyStoreLocation;
                this.trustStorePassword = this.keyStorePassword;
                this.trustStoreType = this.keyStoreType;
            } else {
                this.trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword", "changeit");
                this.trustStoreType = System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType());
            }
            this.trustManagerAlgorithm = Security.getProperty("ssl.TrustManagerFactory.algorithm");
            if (this.trustManagerAlgorithm == null) {
                this.trustManagerAlgorithm = "SunX509";
            }
        }
    }

    public static SSLEngine getSSLEngine() throws GeneralSecurityException, IOException {
        SSLContext context2 = getSSLContext();
        if (context2 == null) {
            return null;
        }
        SSLEngine engine = context2.createSSLEngine();
        engine.setUseClientMode(true);
        return engine;
    }

    public static SSLContext getSSLContext() throws GeneralSecurityException, IOException {
        if (context == null) {
            SSLConfig config = new SSLConfig();
            if (config.keyStoreLocation == null || config.trustStoreLocation == null) {
                context = getLooseSSLContext();
            } else {
                context = getStrictSSLContext(config);
            }
        }
        return context;
    }

    /* JADX INFO: finally extract failed */
    static SSLContext getStrictSSLContext(SSLConfig config) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(config.keyStoreType);
        InputStream keystoreInputStream = new FileInputStream(config.keyStoreLocation);
        try {
            keyStore.load(keystoreInputStream, config.keyStorePassword == null ? null : config.keyStorePassword.toCharArray());
            keystoreInputStream.close();
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(config.keyManagerAlgorithm);
            keyManagerFactory.init(keyStore, config.keyManagerPassword == null ? null : config.keyManagerPassword.toCharArray());
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
            KeyStore trustStore = KeyStore.getInstance(config.trustStoreType);
            InputStream truststoreInputStream = new FileInputStream(config.trustStoreLocation);
            try {
                trustStore.load(truststoreInputStream, config.trustStorePassword == null ? null : config.trustStorePassword.toCharArray());
                truststoreInputStream.close();
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(config.trustManagerAlgorithm);
                trustManagerFactory.init(trustStore);
                TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
                SSLContext context2 = SSLContext.getInstance("TLS");
                context2.init(keyManagers, trustManagers, null);
                return context2;
            } catch (Throwable th) {
                truststoreInputStream.close();
                throw th;
            }
        } catch (Throwable th2) {
            keystoreInputStream.close();
            throw th2;
        }
    }

    static SSLContext getLooseSSLContext() throws GeneralSecurityException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{LooseTrustManager.INSTANCE}, new SecureRandom());
        return sslContext;
    }
}