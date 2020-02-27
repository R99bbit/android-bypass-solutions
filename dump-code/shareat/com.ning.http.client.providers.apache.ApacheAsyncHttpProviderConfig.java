package com.ning.http.client.providers.apache;

import com.ning.http.client.AsyncHttpProviderConfig;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;

public class ApacheAsyncHttpProviderConfig implements AsyncHttpProviderConfig<String, String> {
    private final ConcurrentHashMap<String, String> properties = new ConcurrentHashMap<>();
    private ScheduledExecutorService reaper;

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

    public void setReaper(ScheduledExecutorService reaper2) {
        this.reaper = reaper2;
    }

    public ScheduledExecutorService getReaper() {
        return this.reaper;
    }
}