package com.ning.http.client;

import java.util.Map.Entry;
import java.util.Set;

public interface AsyncHttpProviderConfig<U, V> {
    AsyncHttpProviderConfig addProperty(U u, V v);

    V getProperty(U u);

    Set<Entry<U, V>> propertiesSet();

    V removeProperty(U u);
}