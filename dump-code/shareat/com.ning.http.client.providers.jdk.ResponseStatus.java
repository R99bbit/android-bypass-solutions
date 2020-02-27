package com.ning.http.client.providers.jdk;

import com.ning.http.client.AsyncHttpProvider;
import com.ning.http.client.HttpResponseStatus;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;

public class ResponseStatus extends HttpResponseStatus {
    private final HttpURLConnection urlConnection;

    public ResponseStatus(URI uri, HttpURLConnection urlConnection2, AsyncHttpProvider provider) {
        super(uri, provider);
        this.urlConnection = urlConnection2;
    }

    public int getStatusCode() {
        try {
            return this.urlConnection.getResponseCode();
        } catch (IOException e) {
            return 500;
        }
    }

    public String getStatusText() {
        try {
            return this.urlConnection.getResponseMessage();
        } catch (IOException e) {
            return "Internal Error";
        }
    }

    public String getProtocolName() {
        return "http";
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