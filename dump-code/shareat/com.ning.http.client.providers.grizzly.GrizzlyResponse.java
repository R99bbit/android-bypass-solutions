package com.ning.http.client.providers.grizzly;

import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.HttpResponseStatus;
import com.ning.http.client.Response;
import com.ning.http.client.cookie.Cookie;
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
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http.Cookies;
import org.glassfish.grizzly.http.CookiesBuilder.ServerCookiesBuilder;
import org.glassfish.grizzly.memory.Buffers;
import org.glassfish.grizzly.memory.MemoryManager;
import org.glassfish.grizzly.utils.BufferInputStream;
import org.glassfish.grizzly.utils.Charsets;

public class GrizzlyResponse implements Response {
    private final Collection<HttpResponseBodyPart> bodyParts;
    private List<Cookie> cookies;
    private final HttpResponseHeaders headers;
    private final Buffer responseBody;
    private final HttpResponseStatus status;

    public GrizzlyResponse(HttpResponseStatus status2, HttpResponseHeaders headers2, List<HttpResponseBodyPart> bodyParts2) {
        this.status = status2;
        this.headers = headers2;
        this.bodyParts = bodyParts2;
        if (!MiscUtil.isNonEmpty((Collection<?>) bodyParts2)) {
            this.responseBody = Buffers.EMPTY_BUFFER;
        } else if (bodyParts2.size() == 1) {
            this.responseBody = ((GrizzlyResponseBodyPart) bodyParts2.get(0)).getBodyBuffer();
        } else {
            Buffer firstBuffer = ((GrizzlyResponseBodyPart) bodyParts2.get(0)).getBodyBuffer();
            MemoryManager mm = MemoryManager.DEFAULT_MEMORY_MANAGER;
            Buffer constructedBodyBuffer = firstBuffer;
            int len = bodyParts2.size();
            for (int i = 1; i < len; i++) {
                constructedBodyBuffer = Buffers.appendBuffers(mm, constructedBodyBuffer, ((GrizzlyResponseBodyPart) bodyParts2.get(i)).getBodyBuffer());
            }
            this.responseBody = constructedBodyBuffer;
        }
    }

    public int getStatusCode() {
        return this.status.getStatusCode();
    }

    public String getStatusText() {
        return this.status.getStatusText();
    }

    public InputStream getResponseBodyAsStream() throws IOException {
        return new BufferInputStream(this.responseBody);
    }

    public String getResponseBodyExcerpt(int maxLength, String charset) throws IOException {
        int len = Math.min(this.responseBody.remaining(), maxLength);
        int pos = this.responseBody.position();
        return this.responseBody.toStringContent(getCharset(charset), pos, len + pos);
    }

    public String getResponseBody(String charset) throws IOException {
        return this.responseBody.toStringContent(getCharset(charset));
    }

    public String getResponseBodyExcerpt(int maxLength) throws IOException {
        return getResponseBodyExcerpt(maxLength, null);
    }

    public String getResponseBody() throws IOException {
        return getResponseBody(null);
    }

    public byte[] getResponseBodyAsBytes() throws IOException {
        byte[] responseBodyBytes = new byte[this.responseBody.remaining()];
        int origPos = this.responseBody.position();
        this.responseBody.get(responseBodyBytes);
        this.responseBody.position(origPos);
        return responseBodyBytes;
    }

    public ByteBuffer getResponseBodyAsByteBuffer() throws IOException {
        return this.responseBody.toByteBuffer();
    }

    private Buffer getResponseBodyAsBuffer() {
        return this.responseBody;
    }

    public URI getUri() throws MalformedURLException {
        return this.status.getUrl();
    }

    public String getContentType() {
        return this.headers.getHeaders().getFirstValue("Content-Type");
    }

    public String getHeader(String name) {
        return this.headers.getHeaders().getFirstValue(name);
    }

    public List<String> getHeaders(String name) {
        return this.headers.getHeaders().get((Object) name);
    }

    public FluentCaseInsensitiveStringsMap getHeaders() {
        return this.headers.getHeaders();
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
            List<String> values = this.headers.getHeaders().get((Object) "set-cookie");
            if (MiscUtil.isNonEmpty((Collection<?>) values)) {
                ServerCookiesBuilder builder = new ServerCookiesBuilder(false, true);
                for (String header : values) {
                    builder.parse(header);
                }
                this.cookies = convertCookies(builder.build());
            } else {
                this.cookies = Collections.emptyList();
            }
        }
        return this.cookies;
    }

    public boolean hasResponseStatus() {
        return this.status != null;
    }

    public boolean hasResponseHeaders() {
        return this.headers != null && !this.headers.getHeaders().isEmpty();
    }

    public boolean hasResponseBody() {
        return MiscUtil.isNonEmpty(this.bodyParts);
    }

    private List<Cookie> convertCookies(Cookies cookies2) {
        org.glassfish.grizzly.http.Cookie[] grizzlyCookies = cookies2.get();
        List<Cookie> convertedCookies = new ArrayList<>(grizzlyCookies.length);
        org.glassfish.grizzly.http.Cookie[] arr$ = grizzlyCookies;
        int len$ = arr$.length;
        for (int i$ = 0; i$ < len$; i$++) {
            org.glassfish.grizzly.http.Cookie gCookie = arr$[i$];
            convertedCookies.add(new Cookie(gCookie.getName(), gCookie.getValue(), gCookie.getValue(), gCookie.getDomain(), gCookie.getPath(), -1, gCookie.getMaxAge(), gCookie.isSecure(), false));
        }
        return Collections.unmodifiableList(convertedCookies);
    }

    private Charset getCharset(String charset) {
        String charsetLocal = charset;
        if (charsetLocal == null) {
            String contentType = getContentType();
            if (contentType != null) {
                charsetLocal = AsyncHttpProviderUtils.parseCharset(contentType);
            }
        }
        if (charsetLocal == null) {
            charsetLocal = Charsets.DEFAULT_CHARACTER_ENCODING;
        }
        return Charsets.lookupCharset(charsetLocal);
    }
}