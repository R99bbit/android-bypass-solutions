package com.ning.http.client.providers.netty;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseHeaders;
import java.net.URI;
import java.util.Map.Entry;
import org.jboss.netty.handler.codec.http.HttpChunkTrailer;
import org.jboss.netty.handler.codec.http.HttpResponse;

public class ResponseHeaders extends HttpResponseHeaders {
    private final FluentCaseInsensitiveStringsMap headers;
    private final HttpResponse response;
    private final HttpChunkTrailer trailingHeaders;

    public ResponseHeaders(URI uri, HttpResponse response2, AsyncHttpProvider provider) {
        super(uri, provider, false);
        this.trailingHeaders = null;
        this.response = response2;
        this.headers = computerHeaders();
    }

    public ResponseHeaders(URI uri, HttpResponse response2, AsyncHttpProvider provider, HttpChunkTrailer traillingHeaders) {
        super(uri, provider, true);
        this.trailingHeaders = traillingHeaders;
        this.response = response2;
        this.headers = computerHeaders();
    }

    private FluentCaseInsensitiveStringsMap computerHeaders() {
        FluentCaseInsensitiveStringsMap h = new FluentCaseInsensitiveStringsMap();
        for (Entry<String, String> header : this.response.getHeaders()) {
            h.add(header.getKey(), header.getValue());
        }
        if (this.trailingHeaders != null) {
            for (Entry<String, String> header2 : this.trailingHeaders.getHeaders()) {
                h.add(header2.getKey(), header2.getValue());
            }
        }
        return h;
    }

    public FluentCaseInsensitiveStringsMap getHeaders() {
        return this.headers;
    }
}