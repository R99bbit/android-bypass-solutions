package org.jboss.netty.util;

import com.ning.http.multipart.StringPart;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.util.IdentityHashMap;
import java.util.Map;

public final class CharsetUtil {
    public static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");
    public static final Charset US_ASCII = Charset.forName(StringPart.DEFAULT_CHARSET);
    public static final Charset UTF_16 = Charset.forName("UTF-16");
    public static final Charset UTF_16BE = Charset.forName("UTF-16BE");
    public static final Charset UTF_16LE = Charset.forName("UTF-16LE");
    public static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final ThreadLocal<Map<Charset, CharsetDecoder>> decoders = new ThreadLocal<Map<Charset, CharsetDecoder>>() {
        /* access modifiers changed from: protected */
        public Map<Charset, CharsetDecoder> initialValue() {
            return new IdentityHashMap();
        }
    };
    private static final ThreadLocal<Map<Charset, CharsetEncoder>> encoders = new ThreadLocal<Map<Charset, CharsetEncoder>>() {
        /* access modifiers changed from: protected */
        public Map<Charset, CharsetEncoder> initialValue() {
            return new IdentityHashMap();
        }
    };

    public static CharsetEncoder getEncoder(Charset charset) {
        if (charset == null) {
            throw new NullPointerException("charset");
        }
        Map<Charset, CharsetEncoder> map = encoders.get();
        CharsetEncoder e = map.get(charset);
        if (e != null) {
            e.reset();
            e.onMalformedInput(CodingErrorAction.REPLACE);
            e.onUnmappableCharacter(CodingErrorAction.REPLACE);
            return e;
        }
        CharsetEncoder e2 = charset.newEncoder();
        e2.onMalformedInput(CodingErrorAction.REPLACE);
        e2.onUnmappableCharacter(CodingErrorAction.REPLACE);
        map.put(charset, e2);
        return e2;
    }

    public static CharsetDecoder getDecoder(Charset charset) {
        if (charset == null) {
            throw new NullPointerException("charset");
        }
        Map<Charset, CharsetDecoder> map = decoders.get();
        CharsetDecoder d = map.get(charset);
        if (d != null) {
            d.reset();
            d.onMalformedInput(CodingErrorAction.REPLACE);
            d.onUnmappableCharacter(CodingErrorAction.REPLACE);
            return d;
        }
        CharsetDecoder d2 = charset.newDecoder();
        d2.onMalformedInput(CodingErrorAction.REPLACE);
        d2.onUnmappableCharacter(CodingErrorAction.REPLACE);
        map.put(charset, d2);
        return d2;
    }

    private CharsetUtil() {
    }
}