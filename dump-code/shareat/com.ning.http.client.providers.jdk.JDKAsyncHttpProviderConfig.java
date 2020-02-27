package com.ning.http.client.providers.jdk;

import com.ning.http.client.AsyncHttpProviderConfig;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class JDKAsyncHttpProviderConfig implements AsyncHttpProviderConfig<String, String> {
    public static final String FORCE_RESPONSE_BUFFERING = "bufferResponseInMemory";
    private final ConcurrentHashMap<String, String> properties = new ConcurrentHashMap<>();

    public AsyncHttpProviderConfig addProperty(String name, String value) {
        this.properties.put(name, value);
        return this;
    }

    public String getProperty(String name) {
        return this.properties.get(name);
    }

    public String removeProperty(String name) {
        return this.properties.remove(name);
    }

    public Set<Entry<String, String>> propertiesSet() {
        return this.properties.entrySet();
    }
}