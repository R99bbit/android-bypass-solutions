package com.ning.http.client;

import com.ning.http.util.MiscUtil;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public class FluentCaseInsensitiveStringsMap implements Map<String, List<String>>, Iterable<Entry<String, List<String>>> {
    private final Map<String, String> keyLookup = new LinkedHashMap();
    private final Map<String, List<String>> values = new LinkedHashMap();

    public FluentCaseInsensitiveStringsMap() {
    }

    public FluentCaseInsensitiveStringsMap(FluentCaseInsensitiveStringsMap src) {
        if (src != null) {
            Iterator i$ = src.iterator();
            while (i$.hasNext()) {
                Entry<String, List<String>> header = i$.next();
                add(header.getKey(), (Collection<String>) header.getValue());
            }
        }
    }

    public FluentCaseInsensitiveStringsMap(Map<String, Collection<String>> src) {
        if (src != null) {
            for (Entry<String, Collection<String>> header : src.entrySet()) {
                add(header.getKey(), header.getValue());
            }
        }
    }

    public FluentCaseInsensitiveStringsMap add(String key, String... values2) {
        if (MiscUtil.isNonEmpty((Object[]) values2)) {
            add(key, (Collection<String>) Arrays.asList(values2));
        }
        return this;
    }

    private List<String> fetchValues(Collection<String> values2) {
        List<String> result = null;
        if (values2 != null) {
            for (String value : values2) {
                if (value == null) {
                    value = "";
                }
                if (result == null) {
                    result = new ArrayList<>();
                }
                result.add(value);
            }
        }
        return result;
    }

    /* JADX WARNING: type inference failed for: r7v0, types: [java.util.Collection<java.lang.String>, java.util.Collection] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public FluentCaseInsensitiveStringsMap add(String key, Collection<String> r7) {
        if (key != null) {
            List<String> nonNullValues = fetchValues(r7);
            if (nonNullValues != null) {
                String lcKey = key.toLowerCase(Locale.ENGLISH);
                String realKey = this.keyLookup.get(lcKey);
                List<String> curValues = null;
                if (realKey == null) {
                    realKey = key;
                    this.keyLookup.put(lcKey, key);
                } else {
                    curValues = this.values.get(realKey);
                }
                if (curValues == null) {
                    curValues = new ArrayList<>();
                    this.values.put(realKey, curValues);
                }
                curValues.addAll(nonNullValues);
            }
        }
        return this;
    }

    public FluentCaseInsensitiveStringsMap addAll(FluentCaseInsensitiveStringsMap src) {
        if (src != null) {
            Iterator i$ = src.iterator();
            while (i$.hasNext()) {
                Entry<String, List<String>> header = i$.next();
                add(header.getKey(), (Collection<String>) header.getValue());
            }
        }
        return this;
    }

    public FluentCaseInsensitiveStringsMap addAll(Map<String, Collection<String>> src) {
        if (src != null) {
            for (Entry<String, Collection<String>> header : src.entrySet()) {
                add(header.getKey(), header.getValue());
            }
        }
        return this;
    }

    public FluentCaseInsensitiveStringsMap replace(String key, String... values2) {
        return replace(key, (Collection<String>) Arrays.asList(values2));
    }

    /* JADX WARNING: type inference failed for: r6v0, types: [java.util.Collection<java.lang.String>, java.util.Collection] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public FluentCaseInsensitiveStringsMap replace(String key, Collection<String> r6) {
        if (key != null) {
            List<String> nonNullValues = fetchValues(r6);
            String lcKkey = key.toLowerCase(Locale.ENGLISH);
            String realKey = this.keyLookup.get(lcKkey);
            if (nonNullValues == null) {
                this.keyLookup.remove(lcKkey);
                if (realKey != null) {
                    this.values.remove(realKey);
                }
            } else {
                if (!key.equals(realKey)) {
                    this.keyLookup.put(lcKkey, key);
                    this.values.remove(realKey);
                }
                this.values.put(key, nonNullValues);
            }
        }
        return this;
    }

    public FluentCaseInsensitiveStringsMap replaceAll(FluentCaseInsensitiveStringsMap src) {
        if (src != null) {
            Iterator i$ = src.iterator();
            while (i$.hasNext()) {
                Entry<String, List<String>> header = i$.next();
                replace(header.getKey(), (Collection<String>) header.getValue());
            }
        }
        return this;
    }

    public FluentCaseInsensitiveStringsMap replaceAll(Map<? extends String, ? extends Collection<String>> src) {
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

    public FluentCaseInsensitiveStringsMap delete(String key) {
        if (key != null) {
            String realKey = this.keyLookup.remove(key.toLowerCase(Locale.ENGLISH));
            if (realKey != null) {
                this.values.remove(realKey);
            }
        }
        return this;
    }

    public FluentCaseInsensitiveStringsMap deleteAll(String... keys) {
        if (keys != null) {
            for (String key : keys) {
                remove((Object) key);
            }
        }
        return this;
    }

    public FluentCaseInsensitiveStringsMap deleteAll(Collection<String> keys) {
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
        this.keyLookup.clear();
        this.values.clear();
    }

    public Iterator<Entry<String, List<String>>> iterator() {
        return Collections.unmodifiableSet(this.values.entrySet()).iterator();
    }

    public Set<String> keySet() {
        return new LinkedHashSet(this.keyLookup.values());
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
        return this.keyLookup.containsKey(key.toString().toLowerCase(Locale.ENGLISH));
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
        String realKey = this.keyLookup.get(key.toString().toLowerCase(Locale.ENGLISH));
        if (realKey != null) {
            return this.values.get(realKey);
        }
        return null;
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
        FluentCaseInsensitiveStringsMap other = (FluentCaseInsensitiveStringsMap) obj;
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