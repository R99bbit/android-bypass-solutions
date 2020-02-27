package org.jboss.netty.handler.codec.http;

import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.util.Iterator;
import java.util.List;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;

final class HttpCodecUtil {
    static void validateHeaderName(String name) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        int i = 0;
        while (i < name.length()) {
            char c = name.charAt(i);
            if (c > 127) {
                throw new IllegalArgumentException("name contains non-ascii character: " + name);
            }
            switch (c) {
                case 9:
                case 10:
                case 11:
                case 12:
                case 13:
                case ' ':
                case ',':
                case ':':
                case ';':
                case '=':
                    throw new IllegalArgumentException("name contains one of the following prohibited characters: =,;: \\t\\r\\n\\v\\f: " + name);
                default:
                    i++;
            }
        }
    }

    static void validateHeaderValue(String value) {
        if (value == null) {
            throw new NullPointerException(Param.VALUE);
        }
        int state = 0;
        int i = 0;
        while (i < value.length()) {
            char c = value.charAt(i);
            switch (c) {
                case 11:
                    throw new IllegalArgumentException("value contains a prohibited character '\\v': " + value);
                case 12:
                    throw new IllegalArgumentException("value contains a prohibited character '\\f': " + value);
                default:
                    switch (state) {
                        case 0:
                            switch (c) {
                                case 10:
                                    state = 2;
                                    break;
                                case 13:
                                    state = 1;
                                    break;
                            }
                        case 1:
                            switch (c) {
                                case 10:
                                    state = 2;
                                    break;
                                default:
                                    throw new IllegalArgumentException("Only '\\n' is allowed after '\\r': " + value);
                            }
                        case 2:
                            switch (c) {
                                case 9:
                                case ' ':
                                    state = 0;
                                    break;
                                default:
                                    throw new IllegalArgumentException("Only ' ' and '\\t' are allowed after '\\n': " + value);
                            }
                    }
                    i++;
                    break;
            }
        }
        if (state != 0) {
            throw new IllegalArgumentException("value must not end with '\\r' or '\\n':" + value);
        }
    }

    static boolean isTransferEncodingChunked(HttpMessage m) {
        List<String> chunked = m.headers().getAll(Names.TRANSFER_ENCODING);
        if (chunked.isEmpty()) {
            return false;
        }
        for (String v : chunked) {
            if (v.equalsIgnoreCase(Values.CHUNKED)) {
                return true;
            }
        }
        return false;
    }

    static void removeTransferEncodingChunked(HttpMessage m) {
        List<String> values = m.headers().getAll(Names.TRANSFER_ENCODING);
        if (!values.isEmpty()) {
            Iterator<String> it = values.iterator();
            while (it.hasNext()) {
                if (it.next().equalsIgnoreCase(Values.CHUNKED)) {
                    it.remove();
                }
            }
            if (values.isEmpty()) {
                m.headers().remove(Names.TRANSFER_ENCODING);
            } else {
                m.headers().set((String) Names.TRANSFER_ENCODING, (Iterable<?>) values);
            }
        }
    }

    static boolean isContentLengthSet(HttpMessage m) {
        return !m.headers().getAll("Content-Length").isEmpty();
    }

    private HttpCodecUtil() {
    }
}