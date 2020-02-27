package org.jboss.netty.handler.codec.http;

import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

public abstract class HttpHeaders implements Iterable<Entry<String, String>> {
    public static final HttpHeaders EMPTY_HEADERS = new HttpHeaders() {
        public String get(String name) {
            return null;
        }

        public List<String> getAll(String name) {
            return Collections.emptyList();
        }

        public List<Entry<String, String>> entries() {
            return Collections.emptyList();
        }

        public boolean contains(String name) {
            return false;
        }

        public boolean isEmpty() {
            return true;
        }

        public Set<String> names() {
            return Collections.emptySet();
        }

        public HttpHeaders add(String name, Object value) {
            throw new UnsupportedOperationException("read only");
        }

        public HttpHeaders add(String name, Iterable<?> iterable) {
            throw new UnsupportedOperationException("read only");
        }

        public HttpHeaders set(String name, Object value) {
            throw new UnsupportedOperationException("read only");
        }

        public HttpHeaders set(String name, Iterable<?> iterable) {
            throw new UnsupportedOperationException("read only");
        }

        public HttpHeaders remove(String name) {
            throw new UnsupportedOperationException("read only");
        }

        public HttpHeaders clear() {
            throw new UnsupportedOperationException("read only");
        }

        public Iterator<Entry<String, String>> iterator() {
            return entries().iterator();
        }
    };

    public static final class Names {
        public static final String ACCEPT = "Accept";
        public static final String ACCEPT_CHARSET = "Accept-Charset";
        public static final String ACCEPT_ENCODING = "Accept-Encoding";
        public static final String ACCEPT_LANGUAGE = "Accept-Language";
        public static final String ACCEPT_PATCH = "Accept-Patch";
        public static final String ACCEPT_RANGES = "Accept-Ranges";
        public static final String ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
        public static final String ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
        public static final String ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
        public static final String ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
        public static final String ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers";
        public static final String ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";
        public static final String ACCESS_CONTROL_REQUEST_HEADERS = "Access-Control-Request-Headers";
        public static final String ACCESS_CONTROL_REQUEST_METHOD = "Access-Control-Request-Method";
        public static final String AGE = "Age";
        public static final String ALLOW = "Allow";
        public static final String AUTHORIZATION = "Authorization";
        public static final String CACHE_CONTROL = "Cache-Control";
        public static final String CONNECTION = "Connection";
        public static final String CONTENT_BASE = "Content-Base";
        public static final String CONTENT_ENCODING = "Content-Encoding";
        public static final String CONTENT_LANGUAGE = "Content-Language";
        public static final String CONTENT_LENGTH = "Content-Length";
        public static final String CONTENT_LOCATION = "Content-Location";
        public static final String CONTENT_MD5 = "Content-MD5";
        public static final String CONTENT_RANGE = "Content-Range";
        public static final String CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";
        public static final String CONTENT_TYPE = "Content-Type";
        public static final String COOKIE = "Cookie";
        public static final String DATE = "Date";
        public static final String ETAG = "ETag";
        public static final String EXPECT = "Expect";
        public static final String EXPIRES = "Expires";
        public static final String FROM = "From";
        public static final String HOST = "Host";
        public static final String IF_MATCH = "If-Match";
        public static final String IF_MODIFIED_SINCE = "If-Modified-Since";
        public static final String IF_NONE_MATCH = "If-None-Match";
        public static final String IF_RANGE = "If-Range";
        public static final String IF_UNMODIFIED_SINCE = "If-Unmodified-Since";
        public static final String LAST_MODIFIED = "Last-Modified";
        public static final String LOCATION = "Location";
        public static final String MAX_FORWARDS = "Max-Forwards";
        public static final String ORIGIN = "Origin";
        public static final String PRAGMA = "Pragma";
        public static final String PROXY_AUTHENTICATE = "Proxy-Authenticate";
        public static final String PROXY_AUTHORIZATION = "Proxy-Authorization";
        public static final String RANGE = "Range";
        public static final String REFERER = "Referer";
        public static final String RETRY_AFTER = "Retry-After";
        public static final String SEC_WEBSOCKET_ACCEPT = "Sec-WebSocket-Accept";
        public static final String SEC_WEBSOCKET_KEY = "Sec-WebSocket-Key";
        public static final String SEC_WEBSOCKET_KEY1 = "Sec-WebSocket-Key1";
        public static final String SEC_WEBSOCKET_KEY2 = "Sec-WebSocket-Key2";
        public static final String SEC_WEBSOCKET_LOCATION = "Sec-WebSocket-Location";
        public static final String SEC_WEBSOCKET_ORIGIN = "Sec-WebSocket-Origin";
        public static final String SEC_WEBSOCKET_PROTOCOL = "Sec-WebSocket-Protocol";
        public static final String SEC_WEBSOCKET_VERSION = "Sec-WebSocket-Version";
        public static final String SERVER = "Server";
        public static final String SET_COOKIE = "Set-Cookie";
        public static final String SET_COOKIE2 = "Set-Cookie2";
        public static final String TE = "TE";
        public static final String TRAILER = "Trailer";
        public static final String TRANSFER_ENCODING = "Transfer-Encoding";
        public static final String UPGRADE = "Upgrade";
        public static final String USER_AGENT = "User-Agent";
        public static final String VARY = "Vary";
        public static final String VIA = "Via";
        public static final String WARNING = "Warning";
        public static final String WEBSOCKET_LOCATION = "WebSocket-Location";
        public static final String WEBSOCKET_ORIGIN = "WebSocket-Origin";
        public static final String WEBSOCKET_PROTOCOL = "WebSocket-Protocol";
        public static final String WWW_AUTHENTICATE = "WWW-Authenticate";

        private Names() {
        }
    }

    public static final class Values {
        public static final String APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";
        public static final String BASE64 = "base64";
        public static final String BINARY = "binary";
        public static final String BOUNDARY = "boundary";
        public static final String BYTES = "bytes";
        public static final String CHARSET = "charset";
        public static final String CHUNKED = "chunked";
        public static final String CLOSE = "close";
        public static final String COMPRESS = "compress";
        public static final String CONTINUE = "100-continue";
        public static final String DEFLATE = "deflate";
        public static final String GZIP = "gzip";
        public static final String IDENTITY = "identity";
        public static final String KEEP_ALIVE = "keep-alive";
        public static final String MAX_AGE = "max-age";
        public static final String MAX_STALE = "max-stale";
        public static final String MIN_FRESH = "min-fresh";
        public static final String MULTIPART_FORM_DATA = "multipart/form-data";
        public static final String MUST_REVALIDATE = "must-revalidate";
        public static final String NONE = "none";
        public static final String NO_CACHE = "no-cache";
        public static final String NO_STORE = "no-store";
        public static final String NO_TRANSFORM = "no-transform";
        public static final String ONLY_IF_CACHED = "only-if-cached";
        public static final String PRIVATE = "private";
        public static final String PROXY_REVALIDATE = "proxy-revalidate";
        public static final String PUBLIC = "public";
        public static final String QUOTED_PRINTABLE = "quoted-printable";
        public static final String S_MAXAGE = "s-maxage";
        public static final String TRAILERS = "trailers";
        public static final String UPGRADE = "Upgrade";
        public static final String WEBSOCKET = "WebSocket";

        private Values() {
        }
    }

    public abstract HttpHeaders add(String str, Iterable<?> iterable);

    public abstract HttpHeaders add(String str, Object obj);

    public abstract HttpHeaders clear();

    public abstract boolean contains(String str);

    public abstract List<Entry<String, String>> entries();

    public abstract String get(String str);

    public abstract List<String> getAll(String str);

    public abstract boolean isEmpty();

    public abstract Set<String> names();

    public abstract HttpHeaders remove(String str);

    public abstract HttpHeaders set(String str, Iterable<?> iterable);

    public abstract HttpHeaders set(String str, Object obj);

    public static boolean isKeepAlive(HttpMessage message) {
        String connection = message.headers().get("Connection");
        boolean close = "close".equalsIgnoreCase(connection);
        if (close) {
            return false;
        }
        if (!message.getProtocolVersion().isKeepAliveDefault()) {
            return "keep-alive".equalsIgnoreCase(connection);
        }
        if (!close) {
            return true;
        }
        return false;
    }

    public static void setKeepAlive(HttpMessage message, boolean keepAlive) {
        HttpHeaders h = message.headers();
        if (message.getProtocolVersion().isKeepAliveDefault()) {
            if (keepAlive) {
                h.remove("Connection");
            } else {
                h.set((String) "Connection", (Object) "close");
            }
        } else if (keepAlive) {
            h.set((String) "Connection", (Object) "keep-alive");
        } else {
            h.remove("Connection");
        }
    }

    public static String getHeader(HttpMessage message, String name) {
        return message.headers().get(name);
    }

    public static String getHeader(HttpMessage message, String name, String defaultValue) {
        String value = message.headers().get(name);
        return value == null ? defaultValue : value;
    }

    public static void setHeader(HttpMessage message, String name, Object value) {
        message.headers().set(name, value);
    }

    public static void setHeader(HttpMessage message, String name, Iterable<?> values) {
        message.headers().set(name, values);
    }

    public static void addHeader(HttpMessage message, String name, Object value) {
        message.headers().add(name, value);
    }

    public static void removeHeader(HttpMessage message, String name) {
        message.headers().remove(name);
    }

    public static void clearHeaders(HttpMessage message) {
        message.headers().clear();
    }

    public static int getIntHeader(HttpMessage message, String name) {
        String value = getHeader(message, name);
        if (value != null) {
            return Integer.parseInt(value);
        }
        throw new NumberFormatException("header not found: " + name);
    }

    public static int getIntHeader(HttpMessage message, String name, int defaultValue) {
        String value = getHeader(message, name);
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    public static void setIntHeader(HttpMessage message, String name, int value) {
        message.headers().set(name, (Object) Integer.valueOf(value));
    }

    public static void setIntHeader(HttpMessage message, String name, Iterable<Integer> values) {
        message.headers().set(name, values);
    }

    public static void addIntHeader(HttpMessage message, String name, int value) {
        message.headers().add(name, (Object) Integer.valueOf(value));
    }

    public static Date getDateHeader(HttpMessage message, String name) throws ParseException {
        String value = getHeader(message, name);
        if (value != null) {
            return HttpHeaderDateFormat.get().parse(value);
        }
        throw new ParseException("header not found: " + name, 0);
    }

    public static Date getDateHeader(HttpMessage message, String name, Date defaultValue) {
        String value = getHeader(message, name);
        if (value == null) {
            return defaultValue;
        }
        try {
            return HttpHeaderDateFormat.get().parse(value);
        } catch (ParseException e) {
            return defaultValue;
        }
    }

    public static void setDateHeader(HttpMessage message, String name, Date value) {
        if (value != null) {
            message.headers().set(name, (Object) HttpHeaderDateFormat.get().format(value));
        } else {
            message.headers().set(name, null);
        }
    }

    public static void setDateHeader(HttpMessage message, String name, Iterable<Date> values) {
        message.headers().set(name, values);
    }

    public static void addDateHeader(HttpMessage message, String name, Date value) {
        message.headers().add(name, (Object) value);
    }

    public static long getContentLength(HttpMessage message) {
        String value = getHeader(message, "Content-Length");
        if (value != null) {
            return Long.parseLong(value);
        }
        long webSocketContentLength = (long) getWebSocketContentLength(message);
        if (webSocketContentLength >= 0) {
            return webSocketContentLength;
        }
        throw new NumberFormatException("header not found: Content-Length");
    }

    public static long getContentLength(HttpMessage message, long defaultValue) {
        String contentLength = message.headers().get("Content-Length");
        if (contentLength != null) {
            try {
                return Long.parseLong(contentLength);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        } else {
            long webSocketContentLength = (long) getWebSocketContentLength(message);
            if (webSocketContentLength >= 0) {
                return webSocketContentLength;
            }
            return defaultValue;
        }
    }

    private static int getWebSocketContentLength(HttpMessage message) {
        HttpHeaders h = message.headers();
        if (message instanceof HttpRequest) {
            if (HttpMethod.GET.equals(((HttpRequest) message).getMethod()) && h.contains(Names.SEC_WEBSOCKET_KEY1) && h.contains(Names.SEC_WEBSOCKET_KEY2)) {
                return 8;
            }
        } else if ((message instanceof HttpResponse) && ((HttpResponse) message).getStatus().getCode() == 101 && h.contains(Names.SEC_WEBSOCKET_ORIGIN) && h.contains(Names.SEC_WEBSOCKET_LOCATION)) {
            return 16;
        }
        return -1;
    }

    public static void setContentLength(HttpMessage message, long length) {
        message.headers().set((String) "Content-Length", (Object) Long.valueOf(length));
    }

    public static String getHost(HttpMessage message) {
        return message.headers().get("Host");
    }

    public static String getHost(HttpMessage message, String defaultValue) {
        return getHeader(message, "Host", defaultValue);
    }

    public static void setHost(HttpMessage message, String value) {
        message.headers().set((String) "Host", (Object) value);
    }

    public static Date getDate(HttpMessage message) throws ParseException {
        return getDateHeader(message, "Date");
    }

    public static Date getDate(HttpMessage message, Date defaultValue) {
        return getDateHeader(message, "Date", defaultValue);
    }

    public static void setDate(HttpMessage message, Date value) {
        if (value != null) {
            message.headers().set((String) "Date", (Object) HttpHeaderDateFormat.get().format(value));
        } else {
            message.headers().set((String) "Date", null);
        }
    }

    public static boolean is100ContinueExpected(HttpMessage message) {
        if (!(message instanceof HttpRequest) || message.getProtocolVersion().compareTo(HttpVersion.HTTP_1_1) < 0) {
            return false;
        }
        String value = message.headers().get(Names.EXPECT);
        if (value == null) {
            return false;
        }
        if ("100-continue".equalsIgnoreCase(value)) {
            return true;
        }
        return message.headers().contains(Names.EXPECT, "100-continue", true);
    }

    public static void set100ContinueExpected(HttpMessage message) {
        set100ContinueExpected(message, true);
    }

    public static void set100ContinueExpected(HttpMessage message, boolean set) {
        if (set) {
            message.headers().set((String) Names.EXPECT, (Object) "100-continue");
        } else {
            message.headers().remove(Names.EXPECT);
        }
    }

    static void validateHeaderName(String headerName) {
        if (headerName == null) {
            throw new NullPointerException("Header names cannot be null");
        }
        for (int index = 0; index < headerName.length(); index++) {
            valideHeaderNameChar(headerName.charAt(index));
        }
    }

    static void valideHeaderNameChar(char c) {
        if (c > 127) {
            throw new IllegalArgumentException("Header name cannot contain non-ASCII characters: " + c);
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
                throw new IllegalArgumentException("Header name cannot contain the following prohibited characters: =,;: \\t\\r\\n\\v\\f ");
            default:
                return;
        }
    }

    static void validateHeaderValue(String headerValue) {
        if (headerValue == null) {
            throw new NullPointerException("Header values cannot be null");
        }
        int state = 0;
        int index = 0;
        while (index < headerValue.length()) {
            char character = headerValue.charAt(index);
            switch (character) {
                case 11:
                    throw new IllegalArgumentException("Header value contains a prohibited character '\\v': " + headerValue);
                case 12:
                    throw new IllegalArgumentException("Header value contains a prohibited character '\\f': " + headerValue);
                default:
                    switch (state) {
                        case 0:
                            switch (character) {
                                case 10:
                                    state = 2;
                                    break;
                                case 13:
                                    state = 1;
                                    break;
                            }
                        case 1:
                            switch (character) {
                                case 10:
                                    state = 2;
                                    break;
                                default:
                                    throw new IllegalArgumentException("Only '\\n' is allowed after '\\r': " + headerValue);
                            }
                        case 2:
                            switch (character) {
                                case 9:
                                case ' ':
                                    state = 0;
                                    break;
                                default:
                                    throw new IllegalArgumentException("Only ' ' and '\\t' are allowed after '\\n': " + headerValue);
                            }
                    }
                    index++;
                    break;
            }
        }
        if (state != 0) {
            throw new IllegalArgumentException("Header value must not end with '\\r' or '\\n':" + headerValue);
        }
    }

    public static boolean isTransferEncodingChunked(HttpMessage message) {
        return message.headers().contains(Names.TRANSFER_ENCODING, Values.CHUNKED, true);
    }

    public static void removeTransferEncodingChunked(HttpMessage m) {
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

    public static void setTransferEncodingChunked(HttpMessage m) {
        addHeader(m, Names.TRANSFER_ENCODING, Values.CHUNKED);
        removeHeader(m, "Content-Length");
    }

    public static boolean isContentLengthSet(HttpMessage m) {
        return m.headers().contains("Content-Length");
    }

    protected HttpHeaders() {
    }

    public HttpHeaders add(HttpHeaders headers) {
        if (headers == null) {
            throw new NullPointerException("headers");
        }
        Iterator i$ = headers.iterator();
        while (i$.hasNext()) {
            Entry<String, String> e = (Entry) i$.next();
            add(e.getKey(), (Object) e.getValue());
        }
        return this;
    }

    public HttpHeaders set(HttpHeaders headers) {
        if (headers == null) {
            throw new NullPointerException("headers");
        }
        clear();
        Iterator i$ = headers.iterator();
        while (i$.hasNext()) {
            Entry<String, String> e = (Entry) i$.next();
            add(e.getKey(), (Object) e.getValue());
        }
        return this;
    }

    public boolean contains(String name, String value, boolean ignoreCaseValue) {
        List<String> values = getAll(name);
        if (values.isEmpty()) {
            return false;
        }
        for (String v : values) {
            if (ignoreCaseValue) {
                if (v.equalsIgnoreCase(value)) {
                    return true;
                }
            } else if (v.equals(value)) {
                return true;
            }
        }
        return false;
    }
}