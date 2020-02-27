package com.squareup.okhttp;

import com.squareup.okhttp.internal.Util;
import java.net.Proxy;
import java.net.ProxySelector;
import java.util.List;
import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;

public final class Address {
    final Authenticator authenticator;
    final CertificatePinner certificatePinner;
    final List<ConnectionSpec> connectionSpecs;
    final HostnameVerifier hostnameVerifier;
    final List<Protocol> protocols;
    final Proxy proxy;
    final ProxySelector proxySelector;
    final SocketFactory socketFactory;
    final SSLSocketFactory sslSocketFactory;
    final String uriHost;
    final int uriPort;

    public Address(String uriHost2, int uriPort2, SocketFactory socketFactory2, SSLSocketFactory sslSocketFactory2, HostnameVerifier hostnameVerifier2, CertificatePinner certificatePinner2, Authenticator authenticator2, Proxy proxy2, List<Protocol> protocols2, List<ConnectionSpec> connectionSpecs2, ProxySelector proxySelector2) {
        if (uriHost2 == null) {
            throw new NullPointerException("uriHost == null");
        } else if (uriPort2 <= 0) {
            throw new IllegalArgumentException("uriPort <= 0: " + uriPort2);
        } else if (authenticator2 == null) {
            throw new IllegalArgumentException("authenticator == null");
        } else if (protocols2 == null) {
            throw new IllegalArgumentException("protocols == null");
        } else if (proxySelector2 == null) {
            throw new IllegalArgumentException("proxySelector == null");
        } else {
            this.proxy = proxy2;
            this.uriHost = uriHost2;
            this.uriPort = uriPort2;
            this.socketFactory = socketFactory2;
            this.sslSocketFactory = sslSocketFactory2;
            this.hostnameVerifier = hostnameVerifier2;
            this.certificatePinner = certificatePinner2;
            this.authenticator = authenticator2;
            this.protocols = Util.immutableList(protocols2);
            this.connectionSpecs = Util.immutableList(connectionSpecs2);
            this.proxySelector = proxySelector2;
        }
    }

    public String getUriHost() {
        return this.uriHost;
    }

    public int getUriPort() {
        return this.uriPort;
    }

    public SocketFactory getSocketFactory() {
        return this.socketFactory;
    }

    public SSLSocketFactory getSslSocketFactory() {
        return this.sslSocketFactory;
    }

    public HostnameVerifier getHostnameVerifier() {
        return this.hostnameVerifier;
    }

    public Authenticator getAuthenticator() {
        return this.authenticator;
    }

    public List<Protocol> getProtocols() {
        return this.protocols;
    }

    public List<ConnectionSpec> getConnectionSpecs() {
        return this.connectionSpecs;
    }

    public Proxy getProxy() {
        return this.proxy;
    }

    public ProxySelector getProxySelector() {
        return this.proxySelector;
    }

    public CertificatePinner getCertificatePinner() {
        return this.certificatePinner;
    }

    public boolean equals(Object other) {
        if (!(other instanceof Address)) {
            return false;
        }
        Address that = (Address) other;
        if (!Util.equal(this.proxy, that.proxy) || !this.uriHost.equals(that.uriHost) || this.uriPort != that.uriPort || !Util.equal(this.sslSocketFactory, that.sslSocketFactory) || !Util.equal(this.hostnameVerifier, that.hostnameVerifier) || !Util.equal(this.certificatePinner, that.certificatePinner) || !Util.equal(this.authenticator, that.authenticator) || !Util.equal(this.protocols, that.protocols) || !Util.equal(this.connectionSpecs, that.connectionSpecs) || !Util.equal(this.proxySelector, that.proxySelector)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        int i;
        int i2;
        int i3 = 0;
        int hashCode = ((((((this.proxy != null ? this.proxy.hashCode() : 0) + 527) * 31) + this.uriHost.hashCode()) * 31) + this.uriPort) * 31;
        if (this.sslSocketFactory != null) {
            i = this.sslSocketFactory.hashCode();
        } else {
            i = 0;
        }
        int i4 = (hashCode + i) * 31;
        if (this.hostnameVerifier != null) {
            i2 = this.hostnameVerifier.hashCode();
        } else {
            i2 = 0;
        }
        int i5 = (i4 + i2) * 31;
        if (this.certificatePinner != null) {
            i3 = this.certificatePinner.hashCode();
        }
        return ((((((((i5 + i3) * 31) + this.authenticator.hashCode()) * 31) + this.protocols.hashCode()) * 31) + this.connectionSpecs.hashCode()) * 31) + this.proxySelector.hashCode();
    }
}