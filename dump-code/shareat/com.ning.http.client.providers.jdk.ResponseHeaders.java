package com.ning.http.client.providers.jdk;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseHeaders;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;

public class ResponseHeaders extends HttpResponseHeaders {
    private final FluentCaseInsensitiveStringsMap headers = computerHeaders();
    private final HttpURLConnection urlConnection;

    public ResponseHeaders(URI uri, HttpURLConnection urlConnection2, AsyncHttpProvider provider) {
        super(uri, provider, false);
        this.urlConnection = urlConnection2;
    }

    private FluentCaseInsensitiveStringsMap computerHeaders() {
        FluentCaseInsensitiveStringsMap h = new FluentCaseInsensitiveStringsMap();
        for (Entry<String, List<String>> e : this.urlConnection.getHeaderFields().entrySet()) {
            if (e.getKey() != null) {
                h.add(e.getKey(), (Collection<String>) e.getValue());
            }
        }
        return h;
    }

    public FluentCaseInsensitiveStringsMap getHeaders() {
        return this.headers;
    }
}