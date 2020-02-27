package com.ning.http.client;

import java.net.URI;

public class HttpContent {
    protected final AsyncHttpProvider provider;
    protected final URI uri;

    protected HttpContent(URI url, AsyncHttpProvider provider2) {
        this.provider = provider2;
        this.uri = url;
    }

    public final AsyncHttpProvider provider() {
        return this.provider;
    }

    public final URI getUrl() {
        return this.uri;
    }
}