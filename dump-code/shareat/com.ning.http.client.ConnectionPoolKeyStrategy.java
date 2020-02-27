package com.ning.http.client;

import java.net.URI;

public interface ConnectionPoolKeyStrategy {
    String getKey(URI uri);
}