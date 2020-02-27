package com.ning.http.client;

import java.security.GeneralSecurityException;
import javax.net.ssl.SSLEngine;

public interface SSLEngineFactory {
    SSLEngine newSSLEngine() throws GeneralSecurityException;
}