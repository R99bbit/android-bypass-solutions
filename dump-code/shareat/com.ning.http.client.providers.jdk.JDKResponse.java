package com.ning.http.client.providers.jdk;

import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.Response;
import com.ning.http.client.cookie.Cookie;
import com.ning.http.client.cookie.CookieDecoder;
import com.ning.http.util.AsyncHttpProviderUtils;
import com.ning.http.util.MiscUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;

public class JDKResponse implements Response {
    private static final String DEFAULT_CHARSET = "ISO-8859-1";
    private final List<HttpResponseBodyPart> bodyParts;
    private String content;
    private AtomicBoolean contentComputed = new AtomicBoolean(false);
    private List<Cookie> cookies;
    private final HttpResponseHeaders headers;
    private final HttpResponseStatus status;
    private final URI uri;

    public JDKResponse(HttpResponseStatus status2, HttpResponseHeaders headers2, List<HttpResponseBodyPart> bodyParts2) {
        this.bodyParts = bodyParts2;
        this.headers = headers2;
        this.status = status2;
        this.uri = this.status.getUrl();
    }

    public int getStatusCode() {
        return this.status.getStatusCode();
    }

    public String getStatusText() {
        return this.status.getStatusText();
    }

    public String getResponseBody() throws IOException {
        return getResponseBody("ISO-8859-1");
    }

    public byte[] getResponseBodyAsBytes() throws IOException {
        return AsyncHttpProviderUtils.contentToByte(this.bodyParts);
    }

    public ByteBuffer getResponseBodyAsByteBuffer() throws IOException {
        return ByteBuffer.wrap(getResponseBodyAsBytes());
    }

    public String getResponseBody(String charset) throws IOException {
        if (!this.contentComputed.get()) {
            this.content = AsyncHttpProviderUtils.contentToString(this.bodyParts, computeCharset(charset));
        }
        return this.content;
    }

    public InputStream getResponseBodyAsStream() throws IOException {
        if (this.contentComputed.get()) {
            return new ByteArrayInputStream(this.content.getBytes("ISO-8859-1"));
        }
        return AsyncHttpProviderUtils.contentToInputStream(this.bodyParts);
    }

    public String getResponseBodyExcerpt(int maxLength) throws IOException {
        return getResponseBodyExcerpt(maxLength, "ISO-8859-1");
    }

    public String getResponseBodyExcerpt(int maxLength, String charset) throws IOException {
        String charset2 = computeCharset(charset);
        if (!this.contentComputed.get()) {
            List<HttpResponseBodyPart> list = this.bodyParts;
            if (charset2 == null) {
                charset2 = "ISO-8859-1";
            }
            this.content = AsyncHttpProviderUtils.contentToString(list, charset2);
        }
        return this.content.length() <= maxLength ? this.content : this.content.substring(0, maxLength);
    }

    private String computeCharset(String charset) {
        if (charset == null) {
            String contentType = getContentType();
            if (contentType != null) {
                charset = AsyncHttpProviderUtils.parseCharset(contentType);
            }
        }
        return charset != null ? charset : "ISO-8859-1";
    }

    public URI getUri() throws MalformedURLException {
        return this.uri;
    }

    public String getContentType() {
        return getHeader("Content-Type");
    }

    public String getHeader(String name) {
        if (this.headers != null) {
            return this.headers.getHeaders().getFirstValue(name);
        }
        return null;
    }

    public List<String> getHeaders(String name) {
        return this.headers != null ? this.headers.getHeaders().get((Object) name) : Collections.emptyList();
    }

    public FluentCaseInsensitiveStringsMap getHeaders() {
        return this.headers != null ? this.headers.getHeaders() : new FluentCaseInsensitiveStringsMap();
    }

    public boolean isRedirected() {
        switch (this.status.getStatusCode()) {
            case 301:
            case 302:
            case 303:
            case 307:
            case 308:
                return true;
            default:
                return false;
        }
    }

    public List<Cookie> getCookies() {
        if (this.headers == null) {
            return Collections.emptyList();
        }
        if (!MiscUtil.isNonEmpty((Collection<?>) this.cookies)) {
            List<Cookie> localCookies = new ArrayList<>();
            for (Entry<String, List<String>> header : this.headers.getHeaders().entrySet()) {
                if (header.getKey().equalsIgnoreCase(Names.SET_COOKIE)) {
                    for (String value : header.getValue()) {
                        localCookies.add(CookieDecoder.decode(value));
                    }
                }
            }
            this.cookies = Collections.unmodifiableList(localCookies);
        }
        return this.cookies;
    }

    public boolean hasResponseStatus() {
        return this.bodyParts != null;
    }

    public boolean hasResponseHeaders() {
        return this.headers != null;
    }

    public boolean hasResponseBody() {
        return MiscUtil.isNonEmpty((Collection<?>) this.bodyParts);
    }
}