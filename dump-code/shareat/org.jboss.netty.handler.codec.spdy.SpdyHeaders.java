package org.jboss.netty.handler.codec.spdy;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;

public abstract class SpdyHeaders implements Iterable<Entry<String, String>> {
    public static final SpdyHeaders EMPTY_HEADERS = new SpdyHeaders() {
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

        public SpdyHeaders add(String name, Object value) {
            throw new UnsupportedOperationException("read only");
        }

        public SpdyHeaders add(String name, Iterable<?> iterable) {
            throw new UnsupportedOperationException("read only");
        }

        public SpdyHeaders set(String name, Object value) {
            throw new UnsupportedOperationException("read only");
        }

        public SpdyHeaders set(String name, Iterable<?> iterable) {
            throw new UnsupportedOperationException("read only");
        }

        public SpdyHeaders remove(String name) {
            throw new UnsupportedOperationException("read only");
        }

        public SpdyHeaders clear() {
            throw new UnsupportedOperationException("read only");
        }

        public Iterator<Entry<String, String>> iterator() {
            return entries().iterator();
        }

        public String get(String name) {
            return null;
        }
    };

    public static final class HttpNames {
        public static final String HOST = ":host";
        public static final String METHOD = ":method";
        public static final String PATH = ":path";
        public static final String SCHEME = ":scheme";
        public static final String STATUS = ":status";
        public static final String VERSION = ":version";

        private HttpNames() {
        }
    }

    public abstract SpdyHeaders add(String str, Iterable<?> iterable);

    public abstract SpdyHeaders add(String str, Object obj);

    public abstract SpdyHeaders clear();

    public abstract boolean contains(String str);

    public abstract List<Entry<String, String>> entries();

    public abstract String get(String str);

    public abstract List<String> getAll(String str);

    public abstract boolean isEmpty();

    public abstract Set<String> names();

    public abstract SpdyHeaders remove(String str);

    public abstract SpdyHeaders set(String str, Iterable<?> iterable);

    public abstract SpdyHeaders set(String str, Object obj);

    public static String getHeader(SpdyHeadersFrame frame, String name) {
        return frame.headers().get(name);
    }

    public static String getHeader(SpdyHeadersFrame frame, String name, String defaultValue) {
        String value = frame.headers().get(name);
        return value == null ? defaultValue : value;
    }

    public static void setHeader(SpdyHeadersFrame frame, String name, Object value) {
        frame.headers().set(name, value);
    }

    public static void setHeader(SpdyHeadersFrame frame, String name, Iterable<?> values) {
        frame.headers().set(name, values);
    }

    public static void addHeader(SpdyHeadersFrame frame, String name, Object value) {
        frame.headers().add(name, value);
    }

    public static void removeHost(SpdyHeadersFrame frame) {
        frame.headers().remove(HttpNames.HOST);
    }

    public static String getHost(SpdyHeadersFrame frame) {
        return frame.headers().get(HttpNames.HOST);
    }

    public static void setHost(SpdyHeadersFrame frame, String host) {
        frame.headers().set((String) HttpNames.HOST, (Object) host);
    }

    public static void removeMethod(int spdyVersion, SpdyHeadersFrame frame) {
        frame.headers().remove(HttpNames.METHOD);
    }

    public static HttpMethod getMethod(int spdyVersion, SpdyHeadersFrame frame) {
        try {
            return HttpMethod.valueOf(frame.headers().get(HttpNames.METHOD));
        } catch (Exception e) {
            return null;
        }
    }

    public static void setMethod(int spdyVersion, SpdyHeadersFrame frame, HttpMethod method) {
        frame.headers().set((String) HttpNames.METHOD, (Object) method.getName());
    }

    public static void removeScheme(int spdyVersion, SpdyHeadersFrame frame) {
        frame.headers().remove(HttpNames.SCHEME);
    }

    public static String getScheme(int spdyVersion, SpdyHeadersFrame frame) {
        return frame.headers().get(HttpNames.SCHEME);
    }

    public static void setScheme(int spdyVersion, SpdyHeadersFrame frame, String scheme) {
        frame.headers().set((String) HttpNames.SCHEME, (Object) scheme);
    }

    public static void removeStatus(int spdyVersion, SpdyHeadersFrame frame) {
        frame.headers().remove(HttpNames.STATUS);
    }

    public static HttpResponseStatus getStatus(int spdyVersion, SpdyHeadersFrame frame) {
        try {
            String status = frame.headers().get(HttpNames.STATUS);
            int space = status.indexOf(32);
            if (space == -1) {
                return HttpResponseStatus.valueOf(Integer.parseInt(status));
            }
            int code = Integer.parseInt(status.substring(0, space));
            String reasonPhrase = status.substring(space + 1);
            HttpResponseStatus responseStatus = HttpResponseStatus.valueOf(code);
            if (!responseStatus.getReasonPhrase().equals(reasonPhrase)) {
                return new HttpResponseStatus(code, reasonPhrase);
            }
            return responseStatus;
        } catch (Exception e) {
            return null;
        }
    }

    public static void setStatus(int spdyVersion, SpdyHeadersFrame frame, HttpResponseStatus status) {
        frame.headers().set((String) HttpNames.STATUS, (Object) status.toString());
    }

    public static void removeUrl(int spdyVersion, SpdyHeadersFrame frame) {
        frame.headers().remove(HttpNames.PATH);
    }

    public static String getUrl(int spdyVersion, SpdyHeadersFrame frame) {
        return frame.headers().get(HttpNames.PATH);
    }

    public static void setUrl(int spdyVersion, SpdyHeadersFrame frame, String path) {
        frame.headers().set((String) HttpNames.PATH, (Object) path);
    }

    public static void removeVersion(int spdyVersion, SpdyHeadersFrame frame) {
        frame.headers().remove(HttpNames.VERSION);
    }

    public static HttpVersion getVersion(int spdyVersion, SpdyHeadersFrame frame) {
        try {
            return HttpVersion.valueOf(frame.headers().get(HttpNames.VERSION));
        } catch (Exception e) {
            return null;
        }
    }

    public static void setVersion(int spdyVersion, SpdyHeadersFrame frame, HttpVersion httpVersion) {
        frame.headers().set((String) HttpNames.VERSION, (Object) httpVersion.getText());
    }

    public Iterator<Entry<String, String>> iterator() {
        return entries().iterator();
    }
}