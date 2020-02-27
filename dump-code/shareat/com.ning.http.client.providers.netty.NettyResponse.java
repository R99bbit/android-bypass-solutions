package com.ning.http.client.providers.netty;

import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.Response;
import com.ning.http.client.cookie.Cookie;
import com.ning.http.client.cookie.CookieDecoder;
import com.ning.http.util.AsyncHttpProviderUtils;
import com.ning.http.util.MiscUtil;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferInputStream;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;

public class NettyResponse implements Response {
    private static final Charset DEFAULT_CHARSET = Charset.forName("ISO-8859-1");
    private final List<HttpResponseBodyPart> bodyParts;
    private List<Cookie> cookies;
    private final HttpResponseHeaders headers;
    private final HttpResponseStatus status;

    public NettyResponse(HttpResponseStatus status2, HttpResponseHeaders headers2, List<HttpResponseBodyPart> bodyParts2) {
        this.status = status2;
        this.headers = headers2;
        this.bodyParts = bodyParts2;
    }

    public int getStatusCode() {
        return this.status.getStatusCode();
    }

    public String getStatusText() {
        return this.status.getStatusText();
    }

    public byte[] getResponseBodyAsBytes() throws IOException {
        return ChannelBufferUtil.channelBuffer2bytes(getResponseBodyAsChannelBuffer());
    }

    public ByteBuffer getResponseBodyAsByteBuffer() throws IOException {
        return getResponseBodyAsChannelBuffer().toByteBuffer();
    }

    public String getResponseBody() throws IOException {
        return getResponseBody(null);
    }

    public String getResponseBody(String charset) throws IOException {
        return getResponseBodyAsChannelBuffer().toString(computeCharset(charset));
    }

    public InputStream getResponseBodyAsStream() throws IOException {
        return new ChannelBufferInputStream(getResponseBodyAsChannelBuffer());
    }

    public ChannelBuffer getResponseBodyAsChannelBuffer() throws IOException {
        switch (this.bodyParts.size()) {
            case 0:
                return ChannelBuffers.EMPTY_BUFFER;
            case 1:
                return ResponseBodyPart.class.cast(this.bodyParts.get(0)).getChannelBuffer();
            default:
                ChannelBuffer[] channelBuffers = new ChannelBuffer[this.bodyParts.size()];
                for (int i = 0; i < this.bodyParts.size(); i++) {
                    channelBuffers[i] = ResponseBodyPart.class.cast(this.bodyParts.get(i)).getChannelBuffer();
                }
                return ChannelBuffers.wrappedBuffer(channelBuffers);
        }
    }

    public String getResponseBodyExcerpt(int maxLength) throws IOException {
        return getResponseBodyExcerpt(maxLength, null);
    }

    public String getResponseBodyExcerpt(int maxLength, String charset) throws IOException {
        String response = getResponseBody(charset);
        return response.length() <= maxLength ? response : response.substring(0, maxLength);
    }

    private Charset computeCharset(String charset) {
        if (charset == null) {
            String contentType = getContentType();
            if (contentType != null) {
                charset = AsyncHttpProviderUtils.parseCharset(contentType);
            }
        }
        return charset != null ? Charset.forName(charset) : DEFAULT_CHARSET;
    }

    public URI getUri() throws MalformedURLException {
        return this.status.getUrl();
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
        if (this.cookies == null) {
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
        return this.status != null;
    }

    public boolean hasResponseHeaders() {
        return this.headers != null;
    }

    public boolean hasResponseBody() {
        return MiscUtil.isNonEmpty((Collection<?>) this.bodyParts);
    }
}