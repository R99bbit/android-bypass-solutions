package com.ning.http.client;

import com.ning.http.util.AsyncHttpProviderUtils;
import java.net.URI;

public enum DefaultConnectionPoolStrategy implements ConnectionPoolKeyStrategy {
    INSTANCE;

    public String getKey(URI uri) {
        return AsyncHttpProviderUtils.getBaseUrl(uri);
    }
}