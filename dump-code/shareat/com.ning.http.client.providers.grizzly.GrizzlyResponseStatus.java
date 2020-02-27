package com.ning.http.client.providers.grizzly;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.HttpResponseStatus;
import java.net.URI;
import org.glassfish.grizzly.http.HttpResponsePacket;

public class GrizzlyResponseStatus extends HttpResponseStatus {
    private final HttpResponsePacket response;

    public GrizzlyResponseStatus(HttpResponsePacket response2, URI uri, AsyncHttpProvider provider) {
        super(uri, provider);
        this.response = response2;
    }

    public int getStatusCode() {
        return this.response.getStatus();
    }

    public String getStatusText() {
        return this.response.getReasonPhrase();
    }

    public String getProtocolName() {
        return "http";
    }

    public int getProtocolMajorVersion() {
        return this.response.getProtocol().getMajorVersion();
    }

    public int getProtocolMinorVersion() {
        return this.response.getProtocol().getMinorVersion();
    }

    public String getProtocolText() {
        return this.response.getProtocolString();
    }
}