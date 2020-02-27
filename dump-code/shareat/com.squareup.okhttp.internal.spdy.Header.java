package com.squareup.okhttp.internal.spdy;

import okio.ByteString;
import org.jboss.netty.handler.codec.spdy.SpdyHeaders.HttpNames;

public final class Header {
    public static final ByteString RESPONSE_STATUS = ByteString.encodeUtf8(HttpNames.STATUS);
    public static final ByteString TARGET_AUTHORITY = ByteString.encodeUtf8(":authority");
    public static final ByteString TARGET_HOST = ByteString.encodeUtf8(HttpNames.HOST);
    public static final ByteString TARGET_METHOD = ByteString.encodeUtf8(HttpNames.METHOD);
    public static final ByteString TARGET_PATH = ByteString.encodeUtf8(HttpNames.PATH);
    public static final ByteString TARGET_SCHEME = ByteString.encodeUtf8(HttpNames.SCHEME);
    public static final ByteString VERSION = ByteString.encodeUtf8(HttpNames.VERSION);
    final int hpackSize;
    public final ByteString name;
    public final ByteString value;

    public Header(String name2, String value2) {
        this(ByteString.encodeUtf8(name2), ByteString.encodeUtf8(value2));
    }

    public Header(ByteString name2, String value2) {
        this(name2, ByteString.encodeUtf8(value2));
    }

    public Header(ByteString name2, ByteString value2) {
        this.name = name2;
        this.value = value2;
        this.hpackSize = name2.size() + 32 + value2.size();
    }

    public boolean equals(Object other) {
        if (!(other instanceof Header)) {
            return false;
        }
        Header that = (Header) other;
        if (!this.name.equals(that.name) || !this.value.equals(that.value)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return ((this.name.hashCode() + 527) * 31) + this.value.hashCode();
    }

    public String toString() {
        return String.format("%s: %s", new Object[]{this.name.utf8(), this.value.utf8()});
    }
}