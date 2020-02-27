package com.ning.http.client.cookie;

import java.util.Collection;

public final class CookieEncoder {
    private CookieEncoder() {
    }

    public static String encode(Collection<Cookie> cookies) {
        StringBuilder sb = new StringBuilder();
        for (Cookie cookie : cookies) {
            add(sb, cookie.getName(), cookie.getRawValue());
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 2);
        }
        return sb.toString();
    }

    private static void add(StringBuilder sb, String name, String val) {
        if (val == null) {
            val = "";
        }
        sb.append(name);
        sb.append('=');
        sb.append(val);
        sb.append(';');
        sb.append(' ');
    }
}