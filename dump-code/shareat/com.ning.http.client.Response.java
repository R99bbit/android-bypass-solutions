package com.ning.http.client;

import com.ning.http.client.cookie.Cookie;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public interface Response {

    public static class ResponseBuilder {
        private final List<HttpResponseBodyPart> bodies = Collections.synchronizedList(new ArrayList());
        private HttpResponseHeaders headers;
        private HttpResponseStatus status;

        public ResponseBuilder accumulate(HttpContent httpContent) {
            if (httpContent instanceof HttpResponseStatus) {
                this.status = (HttpResponseStatus) httpContent;
            } else if (httpContent instanceof HttpResponseHeaders) {
                this.headers = (HttpResponseHeaders) httpContent;
            } else if (httpContent instanceof HttpResponseBodyPart) {
                HttpResponseBodyPart part = (HttpResponseBodyPart) httpContent;
                if (part.length() > 0) {
                    this.bodies.add(part);
                }
            }
            return this;
        }

        public Response build() {
            if (this.status == null) {
                return null;
            }
            return this.status.provider().prepareResponse(this.status, this.headers, this.bodies);
        }

        public void reset() {
            this.bodies.clear();
            this.status = null;
            this.headers = null;
        }
    }

    String getContentType();

    List<Cookie> getCookies();

    String getHeader(String str);

    FluentCaseInsensitiveStringsMap getHeaders();

    List<String> getHeaders(String str);

    String getResponseBody() throws IOException;

    String getResponseBody(String str) throws IOException;

    ByteBuffer getResponseBodyAsByteBuffer() throws IOException;

    byte[] getResponseBodyAsBytes() throws IOException;

    InputStream getResponseBodyAsStream() throws IOException;

    String getResponseBodyExcerpt(int i) throws IOException;

    String getResponseBodyExcerpt(int i, String str) throws IOException;

    int getStatusCode();

    String getStatusText();

    URI getUri() throws MalformedURLException;

    boolean hasResponseBody();

    boolean hasResponseHeaders();

    boolean hasResponseStatus();

    boolean isRedirected();

    String toString();
}