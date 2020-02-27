package com.ning.http.client.providers.grizzly;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseHeaders;
import java.net.URI;
import org.glassfish.grizzly.http.HttpResponsePacket;
import org.glassfish.grizzly.http.util.MimeHeaders;

public class GrizzlyResponseHeaders extends HttpResponseHeaders {
    private final FluentCaseInsensitiveStringsMap headers = new FluentCaseInsensitiveStringsMap();
    private volatile boolean initialized;
    private final HttpResponsePacket response;

    public GrizzlyResponseHeaders(HttpResponsePacket response2, URI uri, AsyncHttpProvider provider) {
        super(uri, provider);
        this.response = response2;
    }

    public FluentCaseInsensitiveStringsMap getHeaders() {
        if (!this.initialized) {
            synchronized (this.headers) {
                if (!this.initialized) {
                    this.initialized = true;
                    MimeHeaders headersLocal = this.response.getHeaders();
                    for (String name : headersLocal.names()) {
                        for (String header : headersLocal.values(name)) {
                            this.headers.add(name, header);
                        }
                    }
                }
            }
        }
        return this.headers;
    }
}