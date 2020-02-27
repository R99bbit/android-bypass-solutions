package com.ning.http.client;

import com.ning.http.util.MiscUtil;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public class FluentStringsMap implements Map<String, List<String>>, Iterable<Entry<String, List<String>>> {
    private final Map<String, List<String>> values = new LinkedHashMap();

    public FluentStringsMap() {
    }

    public FluentStringsMap(FluentStringsMap src) {
        if (src != null) {
            Iterator i$ = src.iterator();
            while (i$.hasNext()) {
                Entry<String, List<String>> header = i$.next();
                add(header.getKey(), (Collection<String>) header.getValue());
            }
        }
    }

    public FluentStringsMap(Map<String, Collection<String>> src) {
        if (src != null) {
            for (Entry<String, Collection<String>> header : src.entrySet()) {
                add(header.getKey(), header.getValue());
            }
        }
    }

    public FluentStringsMap add(String key, String... values2) {
        if (MiscUtil.isNonEmpty((Object[]) values2)) {
            add(key, (Collection<String>) Arrays.asList(values2));
        }
        return this;
    }

    public FluentStringsMap add(String key, Collection<String> values2) {
        if (key != null && MiscUtil.isNonEmpty(values2)) {
            List<String> curValues = this.values.get(key);
            if (curValues == null) {
                this.values.put(key, new ArrayList(values2));
            } else {
                curValues.addAll(values2);
            }
        }
        return this;
    }

    public FluentStringsMap addAll(FluentStringsMap src) {
        if (src != null) {
            Iterator i$ = src.iterator();
            while (i$.hasNext()) {
                Entry<String, List<String>> header = i$.next();
                add(header.getKey(), (Collection<String>) header.getValue());
            }
        }
        return this;
    }

    public FluentStringsMap addAll(Map<String, Collection<String>> src) {
        if (src != null) {
            for (Entry<String, Collection<String>> header : src.entrySet()) {
                add(header.getKey(), header.getValue());
            }
        }
        return this;
    }

    public FluentStringsMap replace(String key, String... values2) {
        return replace(key, (Collection<String>) Arrays.asList(values2));
    }

    public FluentStringsMap replace(String key, Collection<String> values2) {
        if (key != null) {
            if (values2 == null) {
                this.values.remove(key);
            } else {
                this.values.put(key, new ArrayList(values2));
            }
        }
        return this;
    }

    public FluentStringsMap replaceAll(FluentStringsMap src) {
        if (src != null) {
            Iterator i$ = src.iterator();
            while (i$.hasNext()) {
                Entry<String, List<String>> header = i$.next();
                replace(header.getKey(), (Collection<String>) header.getValue());
            }
        }
        return this;
    }

    public FluentStringsMap replaceAll(Map<? extends String, ? extends Collection<String>> src) {
        if (src != null) {
            for (Entry<? extends String, ? extends Collection<String>> header : src.entrySet()) {
                replace((String) header.getKey(), (Collection) header.getValue());
            }
        }
        return this;
    }

    public List<String> put(String key, List<String> value) {
        if (key == null) {
            throw new NullPointerException("Null keys are not allowed");
        }
        List<String> oldValue = get((Object) key);
        replace(key, (Collection<String>) value);
        return oldValue;
    }

    public void putAll(Map<? extends String, ? extends List<String>> values2) {
        replaceAll(values2);
    }

    public FluentStringsMap delete(String key) {
        this.values.remove(key);
        return this;
    }

    public FluentStringsMap deleteAll(String... keys) {
        if (keys != null) {
            for (String key : keys) {
                remove((Object) key);
            }
        }
        return this;
    }

    public FluentStringsMap deleteAll(Collection<String> keys) {
        if (keys != null) {
            for (String key : keys) {
                remove((Object) key);
            }
        }
        return this;
    }

    public List<String> remove(Object key) {
        if (key == null) {
            return null;
        }
        List<String> list = get((Object) key.toString());
        delete(key.toString());
        return list;
    }

    public void clear() {
        this.values.clear();
    }

    public Iterator<Entry<String, List<String>>> iterator() {
        return Collections.unmodifiableSet(this.values.entrySet()).iterator();
    }

    public Set<String> keySet() {
        return Collections.unmodifiableSet(this.values.keySet());
    }

    public Set<Entry<String, List<String>>> entrySet() {
        return this.values.entrySet();
    }

    public int size() {
        return this.values.size();
    }

    public boolean isEmpty() {
        return this.values.isEmpty();
    }

    public boolean containsKey(Object key) {
        if (key == null) {
            return false;
        }
        return this.values.containsKey(key.toString());
    }

    public boolean containsValue(Object value) {
        return this.values.containsValue(value);
    }

    public String getFirstValue(String key) {
        List<String> values2 = get((Object) key);
        if (values2 == null) {
            return null;
        }
        if (values2.isEmpty()) {
            return "";
        }
        return values2.get(0);
    }

    public String getJoinedValue(String key, String delimiter) {
        List<String> values2 = get((Object) key);
        if (values2 == null) {
            return null;
        }
        if (values2.size() == 1) {
            return values2.get(0);
        }
        StringBuilder result = new StringBuilder();
        for (String value : values2) {
            if (result.length() > 0) {
                result.append(delimiter);
            }
            result.append(value);
        }
        return result.toString();
    }

    public List<String> get(Object key) {
        if (key == null) {
            return null;
        }
        return this.values.get(key.toString());
    }

    public Collection<List<String>> values() {
        return this.values.values();
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        FluentStringsMap other = (FluentStringsMap) obj;
        if (this.values == null) {
            if (other.values != null) {
                return false;
            }
            return true;
        } else if (!this.values.equals(other.values)) {
            return false;
        } else {
            return true;
        }
    }

    public int hashCode() {
        if (this.values == null) {
            return 0;
        }
        return this.values.hashCode();
    }

    public String toString() {
        StringBuilder result = new StringBuilder();
        for (Entry<String, List<String>> entry : this.values.entrySet()) {
            if (result.length() > 0) {
                result.append("; ");
            }
            result.append("\"");
            result.append(entry.getKey());
            result.append("=");
            boolean needsComma = false;
            for (String value : entry.getValue()) {
                if (needsComma) {
                    result.append(", ");
                } else {
                    needsComma = true;
                }
                result.append(value);
            }
            result.append("\"");
        }
        return result.toString();
    }
}