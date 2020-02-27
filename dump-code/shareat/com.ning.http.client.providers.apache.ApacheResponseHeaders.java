package com.ning.http.client.providers.apache;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseHeaders;
import java.net.URI;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethodBase;

public class ApacheResponseHeaders extends HttpResponseHeaders {
    private final FluentCaseInsensitiveStringsMap headers = computerHeaders();
    private final HttpMethodBase method;

    public ApacheResponseHeaders(URI uri, HttpMethodBase method2, AsyncHttpProvider provider) {
        super(uri, provider, false);
        this.method = method2;
    }

    private FluentCaseInsensitiveStringsMap computerHeaders() {
        Header[] arr$;
        Header[] arr$2;
        FluentCaseInsensitiveStringsMap h = new FluentCaseInsensitiveStringsMap();
        for (Header e : this.method.getResponseHeaders()) {
            if (e.getName() != null) {
                h.add(e.getName(), e.getValue());
            }
        }
        for (Header e2 : this.method.getResponseFooters()) {
            if (e2.getName() != null) {
                h.add(e2.getName(), e2.getValue());
            }
        }
        return h;
    }

    public FluentCaseInsensitiveStringsMap getHeaders() {
        return this.headers;
    }
}