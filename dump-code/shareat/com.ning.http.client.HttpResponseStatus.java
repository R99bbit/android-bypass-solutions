package com.ning.http.client;

import java.net.URI;

public abstract class HttpResponseStatus extends HttpContent {
    public abstract int getProtocolMajorVersion();

    public abstract int getProtocolMinorVersion();

    public abstract String getProtocolName();

    public abstract String getProtocolText();

    public abstract int getStatusCode();

    public abstract String getStatusText();

    public HttpResponseStatus(URI uri, AsyncHttpProvider provider) {
        super(uri, provider);
    }
}