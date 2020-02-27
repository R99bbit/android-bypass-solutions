package org.jboss.netty.handler.codec.http;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpVersion implements Comparable<HttpVersion> {
    public static final HttpVersion HTTP_1_0 = new HttpVersion("HTTP", 1, 0, false);
    public static final HttpVersion HTTP_1_1 = new HttpVersion("HTTP", 1, 1, true);
    private static final Pattern VERSION_PATTERN = Pattern.compile("(\\S+)/(\\d+)\\.(\\d+)");
    private final boolean keepAliveDefault;
    private final int majorVersion;
    private final int minorVersion;
    private final String protocolName;
    private final String text;

    public static HttpVersion valueOf(String text2) {
        if (text2 == null) {
            throw new NullPointerException("text");
        }
        String text3 = text2.trim().toUpperCase();
        if ("HTTP/1.1".equals(text3)) {
            return HTTP_1_1;
        }
        if ("HTTP/1.0".equals(text3)) {
            return HTTP_1_0;
        }
        return new HttpVersion(text3, true);
    }

    @Deprecated
    public HttpVersion(String text2) {
        this(text2, true);
    }

    public HttpVersion(String text2, boolean keepAliveDefault2) {
        if (text2 == null) {
            throw new NullPointerException("text");
        }
        String text3 = text2.trim().toUpperCase();
        if (text3.length() == 0) {
            throw new IllegalArgumentException("empty text");
        }
        Matcher m = VERSION_PATTERN.matcher(text3);
        if (!m.matches()) {
            throw new IllegalArgumentException("invalid version format: " + text3);
        }
        this.protocolName = m.group(1);
        this.majorVersion = Integer.parseInt(m.group(2));
        this.minorVersion = Integer.parseInt(m.group(3));
        this.text = this.protocolName + '/' + this.majorVersion + '.' + this.minorVersion;
        this.keepAliveDefault = keepAliveDefault2;
    }

    @Deprecated
    public HttpVersion(String protocolName2, int majorVersion2, int minorVersion2) {
        this(protocolName2, majorVersion2, minorVersion2, true);
    }

    public HttpVersion(String protocolName2, int majorVersion2, int minorVersion2, boolean keepAliveDefault2) {
        if (protocolName2 == null) {
            throw new NullPointerException("protocolName");
        }
        String protocolName3 = protocolName2.trim().toUpperCase();
        if (protocolName3.length() == 0) {
            throw new IllegalArgumentException("empty protocolName");
        }
        for (int i = 0; i < protocolName3.length(); i++) {
            if (Character.isISOControl(protocolName3.charAt(i)) || Character.isWhitespace(protocolName3.charAt(i))) {
                throw new IllegalArgumentException("invalid character in protocolName");
            }
        }
        if (majorVersion2 < 0) {
            throw new IllegalArgumentException("negative majorVersion");
        } else if (minorVersion2 < 0) {
            throw new IllegalArgumentException("negative minorVersion");
        } else {
            this.protocolName = protocolName3;
            this.majorVersion = majorVersion2;
            this.minorVersion = minorVersion2;
            this.text = protocolName3 + '/' + majorVersion2 + '.' + minorVersion2;
            this.keepAliveDefault = keepAliveDefault2;
        }
    }

    public String getProtocolName() {
        return this.protocolName;
    }

    public int getMajorVersion() {
        return this.majorVersion;
    }

    public int getMinorVersion() {
        return this.minorVersion;
    }

    public String getText() {
        return this.text;
    }

    public boolean isKeepAliveDefault() {
        return this.keepAliveDefault;
    }

    public String toString() {
        return getText();
    }

    public int hashCode() {
        return (((getProtocolName().hashCode() * 31) + getMajorVersion()) * 31) + getMinorVersion();
    }

    public boolean equals(Object o) {
        if (!(o instanceof HttpVersion)) {
            return false;
        }
        HttpVersion that = (HttpVersion) o;
        if (getMinorVersion() == that.getMinorVersion() && getMajorVersion() == that.getMajorVersion() && getProtocolName().equals(that.getProtocolName())) {
            return true;
        }
        return false;
    }

    public int compareTo(HttpVersion o) {
        int v = getProtocolName().compareTo(o.getProtocolName());
        if (v != 0) {
            return v;
        }
        int v2 = getMajorVersion() - o.getMajorVersion();
        if (v2 != 0) {
            return v2;
        }
        return getMinorVersion() - o.getMinorVersion();
    }
}