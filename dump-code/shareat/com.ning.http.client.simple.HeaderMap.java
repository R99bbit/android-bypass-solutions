package com.ning.http.client.simple;

import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public class HeaderMap implements Map<String, List<String>> {
    private FluentCaseInsensitiveStringsMap headers;

    public HeaderMap(FluentCaseInsensitiveStringsMap headers2) {
        this.headers = headers2;
    }

    public Set<String> keySet() {
        return this.headers.keySet();
    }

    public Set<Entry<String, List<String>>> entrySet() {
        return this.headers.entrySet();
    }

    public int size() {
        return this.headers.size();
    }

    public boolean isEmpty() {
        return this.headers.isEmpty();
    }

    public boolean containsKey(Object key) {
        return this.headers.containsKey(key);
    }

    public boolean containsValue(Object value) {
        return this.headers.containsValue(value);
    }

    public String getFirstValue(String key) {
        return this.headers.getFirstValue(key);
    }

    public String getJoinedValue(String key, String delimiter) {
        return this.headers.getJoinedValue(key, delimiter);
    }

    public List<String> get(Object key) {
        return this.headers.get(key);
    }

    public List<String> put(String key, List<String> list) {
        throw new UnsupportedOperationException("Only read access is supported.");
    }

    public List<String> remove(Object key) {
        throw new UnsupportedOperationException("Only read access is supported.");
    }

    public void putAll(Map<? extends String, ? extends List<String>> map) {
        throw new UnsupportedOperationException("Only read access is supported.");
    }

    public void clear() {
        throw new UnsupportedOperationException("Only read access is supported.");
    }

    public Collection<List<String>> values() {
        return this.headers.values();
    }
}