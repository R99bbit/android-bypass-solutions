package com.ning.http.client;

import java.net.URI;

public abstract class HttpResponseHeaders extends HttpContent {
    private final boolean traillingHeaders;

    public abstract FluentCaseInsensitiveStringsMap getHeaders();

    public HttpResponseHeaders(URI uri, AsyncHttpProvider provider) {
        super(uri, provider);
        this.traillingHeaders = false;
    }

    public HttpResponseHeaders(URI uri, AsyncHttpProvider provider, boolean traillingHeaders2) {
        super(uri, provider);
        this.traillingHeaders = traillingHeaders2;
    }

    public boolean isTraillingHeadersReceived() {
        return this.traillingHeaders;
    }
}