package com.ning.http.client;

import com.ning.http.util.MiscUtil;
import io.fabric.sdk.android.services.common.CommonUtils;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Realm {
    private static final String NC = "00000001";
    private final String algorithm;
    private final String cnonce;
    private final String domain;
    private final String enc;
    private final String host;
    private final boolean messageType2Received;
    private final String methodName;
    private final String nc;
    private final String nonce;
    private final String opaque;
    private final String password;
    private final String principal;
    private final String qop;
    private final String realmName;
    private final String response;
    private final AuthScheme scheme;
    private final String uri;
    private final boolean usePreemptiveAuth;

    public static class RealmBuilder {
        private static final Logger logger = LoggerFactory.getLogger(RealmBuilder.class);
        private String algorithm = CommonUtils.MD5_INSTANCE;
        private String cnonce = "";
        private String domain = System.getProperty("http.auth.ntlm.domain", "");
        private String enc = "UTF-8";
        private String host = "localhost";
        private boolean messageType2Received = false;
        private String methodName = HttpRequest.METHOD_GET;
        private String nc = Realm.NC;
        private String nonce = "";
        private String opaque = "";
        private String password = "";
        private String principal = "";
        private String qop = "auth";
        private String realmName = "";
        private String response = "";
        private AuthScheme scheme = AuthScheme.NONE;
        private String uri = "";
        private boolean usePreemptive = false;

        @Deprecated
        public String getDomain() {
            return this.domain;
        }

        @Deprecated
        public RealmBuilder setDomain(String domain2) {
            this.domain = domain2;
            return this;
        }

        public String getNtlmDomain() {
            return this.domain;
        }

        public RealmBuilder setNtlmDomain(String domain2) {
            this.domain = domain2;
            return this;
        }

        public String getNtlmHost() {
            return this.host;
        }

        public RealmBuilder setNtlmHost(String host2) {
            this.host = host2;
            return this;
        }

        public String getPrincipal() {
            return this.principal;
        }

        public RealmBuilder setPrincipal(String principal2) {
            this.principal = principal2;
            return this;
        }

        public String getPassword() {
            return this.password;
        }

        public RealmBuilder setPassword(String password2) {
            this.password = password2;
            return this;
        }

        public AuthScheme getScheme() {
            return this.scheme;
        }

        public RealmBuilder setScheme(AuthScheme scheme2) {
            this.scheme = scheme2;
            return this;
        }

        public String getRealmName() {
            return this.realmName;
        }

        public RealmBuilder setRealmName(String realmName2) {
            this.realmName = realmName2;
            return this;
        }

        public String getNonce() {
            return this.nonce;
        }

        public RealmBuilder setNonce(String nonce2) {
            this.nonce = nonce2;
            return this;
        }

        public String getAlgorithm() {
            return this.algorithm;
        }

        public RealmBuilder setAlgorithm(String algorithm2) {
            this.algorithm = algorithm2;
            return this;
        }

        public String getResponse() {
            return this.response;
        }

        public RealmBuilder setResponse(String response2) {
            this.response = response2;
            return this;
        }

        public String getOpaque() {
            return this.opaque;
        }

        public RealmBuilder setOpaque(String opaque2) {
            this.opaque = opaque2;
            return this;
        }

        public String getQop() {
            return this.qop;
        }

        public RealmBuilder setQop(String qop2) {
            this.qop = qop2;
            return this;
        }

        public String getNc() {
            return this.nc;
        }

        public RealmBuilder setNc(String nc2) {
            this.nc = nc2;
            return this;
        }

        public String getUri() {
            return this.uri;
        }

        public RealmBuilder setUri(String uri2) {
            this.uri = uri2;
            return this;
        }

        public String getMethodName() {
            return this.methodName;
        }

        public RealmBuilder setMethodName(String methodName2) {
            this.methodName = methodName2;
            return this;
        }

        public boolean getUsePreemptiveAuth() {
            return this.usePreemptive;
        }

        public RealmBuilder setUsePreemptiveAuth(boolean usePreemptiveAuth) {
            this.usePreemptive = usePreemptiveAuth;
            return this;
        }

        public RealmBuilder parseWWWAuthenticateHeader(String headerLine) {
            setRealmName(match(headerLine, "realm"));
            setNonce(match(headerLine, "nonce"));
            setAlgorithm(match(headerLine, "algorithm"));
            setOpaque(match(headerLine, "opaque"));
            setQop(match(headerLine, "qop"));
            if (getNonce() == null || getNonce().equalsIgnoreCase("")) {
                setScheme(AuthScheme.BASIC);
            } else {
                setScheme(AuthScheme.DIGEST);
            }
            return this;
        }

        public RealmBuilder setNtlmMessageType2Received(boolean messageType2Received2) {
            this.messageType2Received = messageType2Received2;
            return this;
        }

        public RealmBuilder clone(Realm clone) {
            setRealmName(clone.getRealmName());
            setAlgorithm(clone.getAlgorithm());
            setMethodName(clone.getMethodName());
            setNc(clone.getNc());
            setNonce(clone.getNonce());
            setPassword(clone.getPassword());
            setPrincipal(clone.getPrincipal());
            setEnconding(clone.getEncoding());
            setOpaque(clone.getOpaque());
            setQop(clone.getQop());
            setScheme(clone.getScheme());
            setUri(clone.getUri());
            setUsePreemptiveAuth(clone.getUsePreemptiveAuth());
            setNtlmDomain(clone.getNtlmDomain());
            setNtlmHost(clone.getNtlmHost());
            setNtlmMessageType2Received(clone.isNtlmMessageType2Received());
            return this;
        }

        private void newCnonce() {
            try {
                this.cnonce = toHexString(MessageDigest.getInstance(CommonUtils.MD5_INSTANCE).digest(String.valueOf(System.currentTimeMillis()).getBytes("ISO-8859-1")));
            } catch (Exception e) {
                throw new SecurityException(e);
            }
        }

        private String match(String headerLine, String token) {
            if (headerLine == null) {
                return "";
            }
            int match = headerLine.indexOf(token);
            if (match <= 0) {
                return "";
            }
            int match2 = match + token.length() + 1;
            int traillingComa = headerLine.indexOf(",", match2);
            if (traillingComa <= 0) {
                traillingComa = headerLine.length();
            }
            String value = headerLine.substring(match2, traillingComa);
            if (value.endsWith("\"")) {
                value = value.substring(0, value.length() - 1);
            }
            return value.startsWith("\"") ? value.substring(1) : value;
        }

        public String getEncoding() {
            return this.enc;
        }

        public RealmBuilder setEnconding(String enc2) {
            this.enc = enc2;
            return this;
        }

        private void newResponse() throws UnsupportedEncodingException {
            try {
                MessageDigest md = MessageDigest.getInstance(CommonUtils.MD5_INSTANCE);
                md.update(new StringBuilder(this.principal).append(":").append(this.realmName).append(":").append(this.password).toString().getBytes("ISO-8859-1"));
                byte[] ha1 = md.digest();
                md.reset();
                md.update(new StringBuilder(this.methodName).append(':').append(this.uri).toString().getBytes("ISO-8859-1"));
                byte[] ha2 = md.digest();
                if (this.qop == null || this.qop.equals("")) {
                    md.update(new StringBuilder(toBase16(ha1)).append(':').append(this.nonce).append(':').append(toBase16(ha2)).toString().getBytes("ISO-8859-1"));
                } else {
                    md.update(new StringBuilder(toBase16(ha1)).append(':').append(this.nonce).append(':').append(Realm.NC).append(':').append(this.cnonce).append(':').append(this.qop).append(':').append(toBase16(ha2)).toString().getBytes("ISO-8859-1"));
                }
                this.response = toHexString(md.digest());
            } catch (NoSuchAlgorithmException e) {
                throw new SecurityException(e);
            }
        }

        private static String toHexString(byte[] data) {
            StringBuilder buffer = new StringBuilder();
            for (int i = 0; i < data.length; i++) {
                buffer.append(Integer.toHexString((data[i] & 240) >>> 4));
                buffer.append(Integer.toHexString(data[i] & 15));
            }
            return buffer.toString();
        }

        private static String toBase16(byte[] bytes) {
            StringBuilder buf = new StringBuilder();
            for (byte b : bytes) {
                int bi = b & 255;
                int c = ((bi / 16) % 16) + 48;
                if (c > 57) {
                    c = ((c - 48) - 10) + 97;
                }
                buf.append((char) c);
                int c2 = (bi % 16) + 48;
                if (c2 > 57) {
                    c2 = ((c2 - 48) - 10) + 97;
                }
                buf.append((char) c2);
            }
            return buf.toString();
        }

        public Realm build() {
            if (MiscUtil.isNonEmpty(this.nonce)) {
                newCnonce();
                try {
                    newResponse();
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
            }
            return new Realm(this.scheme, this.principal, this.password, this.realmName, this.nonce, this.algorithm, this.response, this.qop, this.nc, this.cnonce, this.uri, this.methodName, this.usePreemptive, this.domain, this.enc, this.host, this.messageType2Received, this.opaque);
        }
    }

    public enum AuthScheme {
        DIGEST,
        BASIC,
        NTLM,
        SPNEGO,
        KERBEROS,
        NONE
    }

    private Realm(AuthScheme scheme2, String principal2, String password2, String realmName2, String nonce2, String algorithm2, String response2, String qop2, String nc2, String cnonce2, String uri2, String method, boolean usePreemptiveAuth2, String domain2, String enc2, String host2, boolean messageType2Received2, String opaque2) {
        this.principal = principal2;
        this.password = password2;
        this.scheme = scheme2;
        this.realmName = realmName2;
        this.nonce = nonce2;
        this.algorithm = algorithm2;
        this.response = response2;
        this.opaque = opaque2;
        this.qop = qop2;
        this.nc = nc2;
        this.cnonce = cnonce2;
        this.uri = uri2;
        this.methodName = method;
        this.usePreemptiveAuth = usePreemptiveAuth2;
        this.domain = domain2;
        this.enc = enc2;
        this.host = host2;
        this.messageType2Received = messageType2Received2;
    }

    public String getPrincipal() {
        return this.principal;
    }

    public String getPassword() {
        return this.password;
    }

    public AuthScheme getAuthScheme() {
        return this.scheme;
    }

    public AuthScheme getScheme() {
        return this.scheme;
    }

    public String getRealmName() {
        return this.realmName;
    }

    public String getNonce() {
        return this.nonce;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getResponse() {
        return this.response;
    }

    public String getOpaque() {
        return this.opaque;
    }

    public String getQop() {
        return this.qop;
    }

    public String getNc() {
        return this.nc;
    }

    public String getCnonce() {
        return this.cnonce;
    }

    public String getUri() {
        return this.uri;
    }

    public String getEncoding() {
        return this.enc;
    }

    public String getMethodName() {
        return this.methodName;
    }

    public boolean getUsePreemptiveAuth() {
        return this.usePreemptiveAuth;
    }

    public String getDomain() {
        return this.domain;
    }

    public String getNtlmDomain() {
        return this.domain;
    }

    public String getNtlmHost() {
        return this.host;
    }

    public boolean isNtlmMessageType2Received() {
        return this.messageType2Received;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Realm realm = (Realm) o;
        if (this.algorithm == null ? realm.algorithm != null : !this.algorithm.equals(realm.algorithm)) {
            return false;
        }
        if (this.cnonce == null ? realm.cnonce != null : !this.cnonce.equals(realm.cnonce)) {
            return false;
        }
        if (this.nc == null ? realm.nc != null : !this.nc.equals(realm.nc)) {
            return false;
        }
        if (this.nonce == null ? realm.nonce != null : !this.nonce.equals(realm.nonce)) {
            return false;
        }
        if (this.password == null ? realm.password != null : !this.password.equals(realm.password)) {
            return false;
        }
        if (this.principal == null ? realm.principal != null : !this.principal.equals(realm.principal)) {
            return false;
        }
        if (this.qop == null ? realm.qop != null : !this.qop.equals(realm.qop)) {
            return false;
        }
        if (this.realmName == null ? realm.realmName != null : !this.realmName.equals(realm.realmName)) {
            return false;
        }
        if (this.response == null ? realm.response != null : !this.response.equals(realm.response)) {
            return false;
        }
        if (this.scheme != realm.scheme) {
            return false;
        }
        if (this.uri != null) {
            if (this.uri.equals(realm.uri)) {
                return true;
            }
        } else if (realm.uri == null) {
            return true;
        }
        return false;
    }

    public String toString() {
        return "Realm{principal='" + this.principal + '\'' + ", password='" + this.password + '\'' + ", scheme=" + this.scheme + ", realmName='" + this.realmName + '\'' + ", nonce='" + this.nonce + '\'' + ", algorithm='" + this.algorithm + '\'' + ", response='" + this.response + '\'' + ", qop='" + this.qop + '\'' + ", nc='" + this.nc + '\'' + ", cnonce='" + this.cnonce + '\'' + ", uri='" + this.uri + '\'' + ", methodName='" + this.methodName + '\'' + '}';
    }

    public int hashCode() {
        int result;
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10 = 0;
        if (this.principal != null) {
            result = this.principal.hashCode();
        } else {
            result = 0;
        }
        int i11 = result * 31;
        if (this.password != null) {
            i = this.password.hashCode();
        } else {
            i = 0;
        }
        int i12 = (i11 + i) * 31;
        if (this.scheme != null) {
            i2 = this.scheme.hashCode();
        } else {
            i2 = 0;
        }
        int i13 = (i12 + i2) * 31;
        if (this.realmName != null) {
            i3 = this.realmName.hashCode();
        } else {
            i3 = 0;
        }
        int i14 = (i13 + i3) * 31;
        if (this.nonce != null) {
            i4 = this.nonce.hashCode();
        } else {
            i4 = 0;
        }
        int i15 = (i14 + i4) * 31;
        if (this.algorithm != null) {
            i5 = this.algorithm.hashCode();
        } else {
            i5 = 0;
        }
        int i16 = (i15 + i5) * 31;
        if (this.response != null) {
            i6 = this.response.hashCode();
        } else {
            i6 = 0;
        }
        int i17 = (i16 + i6) * 31;
        if (this.qop != null) {
            i7 = this.qop.hashCode();
        } else {
            i7 = 0;
        }
        int i18 = (i17 + i7) * 31;
        if (this.nc != null) {
            i8 = this.nc.hashCode();
        } else {
            i8 = 0;
        }
        int i19 = (i18 + i8) * 31;
        if (this.cnonce != null) {
            i9 = this.cnonce.hashCode();
        } else {
            i9 = 0;
        }
        int i20 = (i19 + i9) * 31;
        if (this.uri != null) {
            i10 = this.uri.hashCode();
        }
        return i20 + i10;
    }
}