package com.squareup.okhttp;

import com.squareup.okhttp.internal.Util;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

public final class Handshake {
    private final String cipherSuite;
    private final List<Certificate> localCertificates;
    private final List<Certificate> peerCertificates;

    private Handshake(String cipherSuite2, List<Certificate> peerCertificates2, List<Certificate> localCertificates2) {
        this.cipherSuite = cipherSuite2;
        this.peerCertificates = peerCertificates2;
        this.localCertificates = localCertificates2;
    }

    public static Handshake get(SSLSession session) {
        Certificate[] peerCertificates2;
        List<Certificate> peerCertificatesList;
        List<Certificate> localCertificatesList;
        String cipherSuite2 = session.getCipherSuite();
        if (cipherSuite2 == null) {
            throw new IllegalStateException("cipherSuite == null");
        }
        try {
            peerCertificates2 = session.getPeerCertificates();
        } catch (SSLPeerUnverifiedException e) {
            peerCertificates2 = null;
        }
        if (peerCertificates2 != null) {
            peerCertificatesList = Util.immutableList((T[]) peerCertificates2);
        } else {
            peerCertificatesList = Collections.emptyList();
        }
        Certificate[] localCertificates2 = session.getLocalCertificates();
        if (localCertificates2 != null) {
            localCertificatesList = Util.immutableList((T[]) localCertificates2);
        } else {
            localCertificatesList = Collections.emptyList();
        }
        return new Handshake(cipherSuite2, peerCertificatesList, localCertificatesList);
    }

    public static Handshake get(String cipherSuite2, List<Certificate> peerCertificates2, List<Certificate> localCertificates2) {
        if (cipherSuite2 != null) {
            return new Handshake(cipherSuite2, Util.immutableList(peerCertificates2), Util.immutableList(localCertificates2));
        }
        throw new IllegalArgumentException("cipherSuite == null");
    }

    public String cipherSuite() {
        return this.cipherSuite;
    }

    public List<Certificate> peerCertificates() {
        return this.peerCertificates;
    }

    public Principal peerPrincipal() {
        if (!this.peerCertificates.isEmpty()) {
            return ((X509Certificate) this.peerCertificates.get(0)).getSubjectX500Principal();
        }
        return null;
    }

    public List<Certificate> localCertificates() {
        return this.localCertificates;
    }

    public Principal localPrincipal() {
        if (!this.localCertificates.isEmpty()) {
            return ((X509Certificate) this.localCertificates.get(0)).getSubjectX500Principal();
        }
        return null;
    }

    public boolean equals(Object other) {
        if (!(other instanceof Handshake)) {
            return false;
        }
        Handshake that = (Handshake) other;
        if (!this.cipherSuite.equals(that.cipherSuite) || !this.peerCertificates.equals(that.peerCertificates) || !this.localCertificates.equals(that.localCertificates)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return ((((this.cipherSuite.hashCode() + 527) * 31) + this.peerCertificates.hashCode()) * 31) + this.localCertificates.hashCode();
    }
}