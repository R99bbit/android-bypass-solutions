package com.ning.http.client.providers.netty;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.HttpResponseStatus;
import java.net.URI;
import org.jboss.netty.handler.codec.http.HttpResponse;

public class ResponseStatus extends HttpResponseStatus {
    private final HttpResponse response;

    public ResponseStatus(URI uri, HttpResponse response2, AsyncHttpProvider provider) {
        super(uri, provider);
        this.response = response2;
    }

    public int getStatusCode() {
        return this.response.getStatus().getCode();
    }

    public String getStatusText() {
        return this.response.getStatus().getReasonPhrase();
    }

    public String getProtocolName() {
        return this.response.getProtocolVersion().getProtocolName();
    }

    public int getProtocolMajorVersion() {
        return this.response.getProtocolVersion().getMajorVersion();
    }

    public int getProtocolMinorVersion() {
        return this.response.getProtocolVersion().getMinorVersion();
    }

    public String getProtocolText() {
        return this.response.getProtocolVersion().getText();
    }
}