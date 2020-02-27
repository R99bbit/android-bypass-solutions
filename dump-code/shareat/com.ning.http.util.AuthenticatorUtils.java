package com.ning.http.util;

import com.ning.http.client.ProxyServer;
import com.ning.http.client.Realm;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public final class AuthenticatorUtils {
    public static String computeBasicAuthentication(Realm realm) throws UnsupportedEncodingException {
        return "Basic " + Base64.encode((realm.getPrincipal() + ":" + realm.getPassword()).getBytes(realm.getEncoding()));
    }

    public static String computeBasicAuthentication(ProxyServer proxyServer) throws UnsupportedEncodingException {
        return "Basic " + Base64.encode((proxyServer.getPrincipal() + ":" + proxyServer.getPassword()).getBytes(proxyServer.getEncoding()));
    }

    public static String computeDigestAuthentication(Realm realm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        StringBuilder builder = new StringBuilder().append("Digest ");
        construct(builder, "username", realm.getPrincipal());
        construct(builder, "realm", realm.getRealmName());
        construct(builder, "nonce", realm.getNonce());
        construct(builder, "uri", realm.getUri());
        builder.append("algorithm").append('=').append(realm.getAlgorithm()).append(", ");
        construct(builder, "response", realm.getResponse());
        if (MiscUtil.isNonEmpty(realm.getOpaque())) {
            construct(builder, "opaque", realm.getOpaque());
        }
        builder.append("qop").append('=').append(realm.getQop()).append(", ");
        builder.append("nc").append('=').append(realm.getNc()).append(", ");
        construct(builder, "cnonce", realm.getCnonce(), true);
        return new String(builder.toString().getBytes("ISO_8859_1"));
    }

    private static StringBuilder construct(StringBuilder builder, String name, String value) {
        return construct(builder, name, value, false);
    }

    private static StringBuilder construct(StringBuilder builder, String name, String value, boolean tail) {
        return builder.append(name).append('=').append('\"').append(value).append(tail ? "\"" : "\", ");
    }
}