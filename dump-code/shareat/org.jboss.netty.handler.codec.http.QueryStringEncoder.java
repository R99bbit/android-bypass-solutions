package org.jboss.netty.handler.codec.http;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.util.ArrayList;
import java.util.List;

public class QueryStringEncoder {
    private final Charset charset;
    private final List<Param> params;
    private final String uri;

    private static final class Param {
        final String name;
        final String value;

        Param(String name2, String value2) {
            this.value = value2;
            this.name = name2;
        }
    }

    public QueryStringEncoder(String uri2) {
        this(uri2, HttpConstants.DEFAULT_CHARSET);
    }

    public QueryStringEncoder(String uri2, Charset charset2) {
        this.params = new ArrayList();
        if (uri2 == null) {
            throw new NullPointerException("uri");
        } else if (charset2 == null) {
            throw new NullPointerException("charset");
        } else {
            this.uri = uri2;
            this.charset = charset2;
        }
    }

    @Deprecated
    public QueryStringEncoder(String uri2, String charset2) {
        this(uri2, Charset.forName(charset2));
    }

    public void addParam(String name, String value) {
        if (name == null) {
            throw new NullPointerException("name");
        } else if (value == null) {
            throw new NullPointerException(com.google.firebase.analytics.FirebaseAnalytics.Param.VALUE);
        } else {
            this.params.add(new Param(name, value));
        }
    }

    public URI toUri() throws URISyntaxException {
        return new URI(toString());
    }

    public String toString() {
        if (this.params.isEmpty()) {
            return this.uri;
        }
        StringBuilder sb = new StringBuilder(this.uri).append('?');
        for (int i = 0; i < this.params.size(); i++) {
            Param param = this.params.get(i);
            sb.append(encodeComponent(param.name, this.charset));
            sb.append('=');
            sb.append(encodeComponent(param.value, this.charset));
            if (i != this.params.size() - 1) {
                sb.append('&');
            }
        }
        return sb.toString();
    }

    private static String encodeComponent(String s, Charset charset2) {
        try {
            return URLEncoder.encode(s, charset2.name()).replaceAll("\\+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new UnsupportedCharsetException(charset2.name());
        }
    }
}