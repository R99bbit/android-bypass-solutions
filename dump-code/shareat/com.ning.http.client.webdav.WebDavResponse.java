package com.ning.http.client.webdav;

import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.Response;
import com.ning.http.client.cookie.Cookie;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.List;
import org.w3c.dom.Document;

public class WebDavResponse implements Response {
    private final Document document;
    private final Response response;

    public WebDavResponse(Response response2, Document document2) {
        this.response = response2;
        this.document = document2;
    }

    public int getStatusCode() {
        return this.response.getStatusCode();
    }

    public String getStatusText() {
        return this.response.getStatusText();
    }

    public byte[] getResponseBodyAsBytes() throws IOException {
        return this.response.getResponseBodyAsBytes();
    }

    public ByteBuffer getResponseBodyAsByteBuffer() throws IOException {
        return ByteBuffer.wrap(getResponseBodyAsBytes());
    }

    public InputStream getResponseBodyAsStream() throws IOException {
        return this.response.getResponseBodyAsStream();
    }

    public String getResponseBodyExcerpt(int maxLength) throws IOException {
        return this.response.getResponseBodyExcerpt(maxLength);
    }

    public String getResponseBodyExcerpt(int maxLength, String charset) throws IOException {
        return this.response.getResponseBodyExcerpt(maxLength, charset);
    }

    public String getResponseBody() throws IOException {
        return this.response.getResponseBody();
    }

    public String getResponseBody(String charset) throws IOException {
        return this.response.getResponseBody(charset);
    }

    public URI getUri() throws MalformedURLException {
        return this.response.getUri();
    }

    public String getContentType() {
        return this.response.getContentType();
    }

    public String getHeader(String name) {
        return this.response.getHeader(name);
    }

    public List<String> getHeaders(String name) {
        return this.response.getHeaders(name);
    }

    public FluentCaseInsensitiveStringsMap getHeaders() {
        return this.response.getHeaders();
    }

    public boolean isRedirected() {
        return this.response.isRedirected();
    }

    public List<Cookie> getCookies() {
        return this.response.getCookies();
    }

    public boolean hasResponseStatus() {
        return this.response.hasResponseStatus();
    }

    public boolean hasResponseHeaders() {
        return this.response.hasResponseHeaders();
    }

    public boolean hasResponseBody() {
        return this.response.hasResponseBody();
    }

    public Document getBodyAsXML() {
        return this.document;
    }
}