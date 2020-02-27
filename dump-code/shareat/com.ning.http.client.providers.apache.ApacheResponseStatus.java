package com.ning.http.client.providers.apache;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.HttpResponseStatus;
import java.net.URI;
import org.apache.commons.httpclient.HttpMethodBase;

public class ApacheResponseStatus extends HttpResponseStatus {
    private final HttpMethodBase method;

    public ApacheResponseStatus(URI uri, HttpMethodBase method2, AsyncHttpProvider provider) {
        super(uri, provider);
        this.method = method2;
    }

    public int getStatusCode() {
        return this.method.getStatusCode();
    }

    public String getStatusText() {
        return this.method.getStatusText();
    }

    public String getProtocolName() {
        return this.method.getStatusLine().getHttpVersion();
    }

    public int getProtocolMajorVersion() {
        return 1;
    }

    public int getProtocolMinorVersion() {
        return 1;
    }

    public String getProtocolText() {
        return "";
    }
}