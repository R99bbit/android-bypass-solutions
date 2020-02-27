package com.ning.http.client.cookie;

import com.ning.http.client.date.RFC2616Date;
import com.ning.http.client.date.RFC2616DateParser;
import com.ning.http.client.date.TimeConverter;

class KeyValuePairsParser {
    private String domain;
    private long expires = -1;
    private boolean httpOnly;
    private int maxAge = -1;
    private String name;
    private String path;
    private String rawValue;
    private boolean secure;
    private final TimeConverter timeBuilder;
    private String value;

    public KeyValuePairsParser(TimeConverter timeBuilder2) {
        this.timeBuilder = timeBuilder2;
    }

    public Cookie cookie() {
        if (this.name != null) {
            return new Cookie(this.name, this.value, this.rawValue, this.domain, this.path, this.expires, this.maxAge, this.secure, this.httpOnly);
        }
        return null;
    }

    public void parseKeyValuePair(String header, int keyStart, int keyEnd, String value2, String rawValue2) {
        if (this.name == null) {
            setCookieNameValue(header, keyStart, keyEnd, value2, rawValue2);
        } else {
            setCookieAttribute(header, keyStart, keyEnd, value2);
        }
    }

    private void setCookieNameValue(String header, int keyStart, int keyEnd, String value2, String rawValue2) {
        this.name = header.substring(keyStart, keyEnd);
        this.value = value2;
        this.rawValue = rawValue2;
    }

    private void setCookieAttribute(String header, int keyStart, int keyEnd, String value2) {
        int length = keyEnd - keyStart;
        if (length == 4) {
            parse4(header, keyStart, value2);
        } else if (length == 6) {
            parse6(header, keyStart, value2);
        } else if (length == 7) {
            parse7(header, keyStart, value2);
        } else if (length == 8) {
            parse8(header, keyStart, value2);
        }
    }

    private boolean isPath(char c0, char c1, char c2, char c3) {
        return (c0 == 'P' || c0 == 'p') && (c1 == 'a' || c1 == 'A') && ((c2 == 't' || c2 == 'T') && (c3 == 'h' || c3 == 'H'));
    }

    private void parse4(String header, int nameStart, String value2) {
        if (isPath(header.charAt(nameStart), header.charAt(nameStart + 1), header.charAt(nameStart + 2), header.charAt(nameStart + 3))) {
            this.path = value2;
        }
    }

    private boolean isDomain(char c0, char c1, char c2, char c3, char c4, char c5) {
        return (c0 == 'D' || c0 == 'd') && (c1 == 'o' || c1 == 'O') && ((c2 == 'm' || c2 == 'M') && ((c3 == 'a' || c3 == 'A') && ((c4 == 'i' || c4 == 'I') && (c5 == 'n' || c5 == 'N'))));
    }

    private boolean isSecure(char c0, char c1, char c2, char c3, char c4, char c5) {
        return (c0 == 'S' || c0 == 's') && (c1 == 'e' || c1 == 'E') && ((c2 == 'c' || c2 == 'C') && ((c3 == 'u' || c3 == 'U') && ((c4 == 'r' || c4 == 'R') && (c5 == 'e' || c5 == 'E'))));
    }

    private void parse6(String header, int nameStart, String value2) {
        char c0 = header.charAt(nameStart);
        char c1 = header.charAt(nameStart + 1);
        char c2 = header.charAt(nameStart + 2);
        char c3 = header.charAt(nameStart + 3);
        char c4 = header.charAt(nameStart + 4);
        char c5 = header.charAt(nameStart + 5);
        if (isDomain(c0, c1, c2, c3, c4, c5)) {
            this.domain = value2;
        } else if (isSecure(c0, c1, c2, c3, c4, c5)) {
            this.secure = true;
        }
    }

    private boolean isExpires(char c0, char c1, char c2, char c3, char c4, char c5, char c6) {
        return (c0 == 'E' || c0 == 'e') && (c1 == 'x' || c1 == 'X') && ((c2 == 'p' || c2 == 'P') && ((c3 == 'i' || c3 == 'I') && ((c4 == 'r' || c4 == 'R') && ((c5 == 'e' || c5 == 'E') && (c6 == 's' || c6 == 'S')))));
    }

    private boolean isMaxAge(char c0, char c1, char c2, char c3, char c4, char c5, char c6) {
        return (c0 == 'M' || c0 == 'm') && (c1 == 'a' || c1 == 'A') && ((c2 == 'x' || c2 == 'X') && c3 == '-' && ((c4 == 'A' || c4 == 'a') && ((c5 == 'g' || c5 == 'G') && (c6 == 'e' || c6 == 'E'))));
    }

    private void setExpire(String value2) {
        RFC2616Date dateElements = new RFC2616DateParser(value2).parse();
        if (dateElements != null) {
            try {
                this.expires = this.timeBuilder.toTime(dateElements);
            } catch (Exception e) {
            }
        }
    }

    private void setMaxAge(String value2) {
        try {
            this.maxAge = Math.max(Integer.valueOf(value2).intValue(), 0);
        } catch (NumberFormatException e) {
        }
    }

    private void parse7(String header, int nameStart, String value2) {
        char c0 = header.charAt(nameStart);
        char c1 = header.charAt(nameStart + 1);
        char c2 = header.charAt(nameStart + 2);
        char c3 = header.charAt(nameStart + 3);
        char c4 = header.charAt(nameStart + 4);
        char c5 = header.charAt(nameStart + 5);
        char c6 = header.charAt(nameStart + 6);
        if (isExpires(c0, c1, c2, c3, c4, c5, c6)) {
            setExpire(value2);
        } else if (isMaxAge(c0, c1, c2, c3, c4, c5, c6)) {
            setMaxAge(value2);
        }
    }

    private boolean isHttpOnly(char c0, char c1, char c2, char c3, char c4, char c5, char c6, char c7) {
        return (c0 == 'H' || c0 == 'h') && (c1 == 't' || c1 == 'T') && ((c2 == 't' || c2 == 'T') && ((c3 == 'p' || c3 == 'P') && ((c4 == 'O' || c4 == 'o') && ((c5 == 'n' || c5 == 'N') && ((c6 == 'l' || c6 == 'L') && (c7 == 'y' || c7 == 'Y'))))));
    }

    private void parse8(String header, int nameStart, String value2) {
        if (isHttpOnly(header.charAt(nameStart), header.charAt(nameStart + 1), header.charAt(nameStart + 2), header.charAt(nameStart + 3), header.charAt(nameStart + 4), header.charAt(nameStart + 5), header.charAt(nameStart + 6), header.charAt(nameStart + 7))) {
            this.httpOnly = true;
        }
    }
}