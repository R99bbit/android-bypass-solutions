package com.ning.http.client.cookie;

import com.google.firebase.analytics.FirebaseAnalytics.Param;

public class Cookie {
    private final String domain;
    private long expires;
    private final boolean httpOnly;
    private final int maxAge;
    private final String name;
    private final String path;
    private final String rawValue;
    private final boolean secure;
    private final String value;

    public static Cookie newValidCookie(String name2, String value2, String domain2, String rawValue2, String path2, long expires2, int maxAge2, boolean secure2, boolean httpOnly2) {
        if (name2 == null) {
            throw new NullPointerException("name");
        }
        String name3 = name2.trim();
        if (name3.length() == 0) {
            throw new IllegalArgumentException("empty name");
        }
        int i = 0;
        while (i < name3.length()) {
            char c = name3.charAt(i);
            if (c > 127) {
                throw new IllegalArgumentException("name contains non-ascii character: " + name3);
            }
            switch (c) {
                case 9:
                case 10:
                case 11:
                case 12:
                case 13:
                case ' ':
                case ',':
                case ';':
                case '=':
                    throw new IllegalArgumentException("name contains one of the following prohibited characters: =,; \\t\\r\\n\\v\\f: " + name3);
                default:
                    i++;
            }
        }
        if (name3.charAt(0) == '$') {
            throw new IllegalArgumentException("name starting with '$' not allowed: " + name3);
        } else if (value2 == null) {
            throw new NullPointerException(Param.VALUE);
        } else {
            return new Cookie(name3, value2, rawValue2, validateValue("domain", domain2), validateValue("path", path2), expires2, maxAge2, secure2, httpOnly2);
        }
    }

    private static String validateValue(String name2, String value2) {
        if (value2 == null) {
            return null;
        }
        String value3 = value2.trim();
        if (value3.length() == 0) {
            return null;
        }
        int i = 0;
        while (i < value3.length()) {
            switch (value3.charAt(i)) {
                case 10:
                case 11:
                case 12:
                case 13:
                case ';':
                    throw new IllegalArgumentException(name2 + " contains one of the following prohibited characters: " + ";\\r\\n\\f\\v (" + value3 + ')');
                default:
                    i++;
            }
        }
        return value3;
    }

    public Cookie(String name2, String value2, String rawValue2, String domain2, String path2, long expires2, int maxAge2, boolean secure2, boolean httpOnly2) {
        this.name = name2;
        this.value = value2;
        this.rawValue = rawValue2;
        this.domain = domain2;
        this.path = path2;
        this.expires = expires2;
        this.maxAge = maxAge2;
        this.secure = secure2;
        this.httpOnly = httpOnly2;
    }

    public String getDomain() {
        return this.domain;
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    public String getRawValue() {
        return this.rawValue;
    }

    public String getPath() {
        return this.path;
    }

    public long getExpires() {
        return this.expires;
    }

    public int getMaxAge() {
        return this.maxAge;
    }

    public boolean isSecure() {
        return this.secure;
    }

    public boolean isHttpOnly() {
        return this.httpOnly;
    }

    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append(this.name);
        buf.append("=");
        buf.append(this.rawValue);
        if (this.domain != null) {
            buf.append("; domain=");
            buf.append(this.domain);
        }
        if (this.path != null) {
            buf.append("; path=");
            buf.append(this.path);
        }
        if (this.expires >= 0) {
            buf.append("; expires=");
            buf.append(this.expires);
        }
        if (this.maxAge >= 0) {
            buf.append("; maxAge=");
            buf.append(this.maxAge);
            buf.append("s");
        }
        if (this.secure) {
            buf.append("; secure");
        }
        if (this.httpOnly) {
            buf.append("; HTTPOnly");
        }
        return buf.toString();
    }
}