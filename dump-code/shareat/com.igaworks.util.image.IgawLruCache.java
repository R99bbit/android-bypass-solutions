package com.igaworks.util.image;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

public class IgawLruCache<K, V> {
    private int createCount;
    private int evictionCount;
    private int hitCount;
    private final LinkedHashMap<K, V> map;
    private int maxSize;
    private int missCount;
    private int putCount;
    private int size;

    public IgawLruCache(int maxSize2) {
        if (maxSize2 <= 0) {
            throw new IllegalArgumentException("maxSize <= 0");
        }
        this.maxSize = maxSize2;
        this.map = new LinkedHashMap<>(0, 0.75f, true);
    }

    public final synchronized V get(K key) {
        V result;
        if (key == null) {
            throw new NullPointerException("key == null");
        }
        V result2 = this.map.get(key);
        if (result2 != null) {
            this.hitCount++;
            result = result2;
        } else {
            this.missCount++;
            V result3 = create(key);
            if (result3 != null) {
                this.createCount++;
                this.size += safeSizeOf(key, result3);
                this.map.put(key, result3);
                trimToSize(this.maxSize);
            }
            result = result3;
        }
        return result;
    }

    public final synchronized V put(K key, V value) {
        V previous;
        if (key == null || value == null) {
            throw new NullPointerException("key == null || value == null");
        }
        this.putCount++;
        this.size += safeSizeOf(key, value);
        previous = this.map.put(key, value);
        if (previous != null) {
            this.size -= safeSizeOf(key, previous);
        }
        trimToSize(this.maxSize);
        return previous;
    }

    private void trimToSize(int maxSize2) {
        while (this.size > maxSize2 && !this.map.isEmpty()) {
            Entry<K, V> toEvict = this.map.entrySet().iterator().next();
            if (toEvict == null) {
                break;
            }
            K key = toEvict.getKey();
            V value = toEvict.getValue();
            this.map.remove(key);
            this.size -= safeSizeOf(key, value);
            this.evictionCount++;
            entryEvicted(key, value);
        }
        if (this.size < 0 || (this.map.isEmpty() && this.size != 0)) {
            throw new IllegalStateException(new StringBuilder(String.valueOf(getClass().getName())).append(".sizeOf() is reporting inconsistent results!").toString());
        }
    }

    public final synchronized V remove(K key) {
        V previous;
        if (key == null) {
            throw new NullPointerException("key == null");
        }
        previous = this.map.remove(key);
        if (previous != null) {
            this.size -= safeSizeOf(key, previous);
        }
        return previous;
    }

    /* access modifiers changed from: protected */
    public void entryEvicted(K k, V v) {
    }

    /* access modifiers changed from: protected */
    public V create(K k) {
        return null;
    }

    private int safeSizeOf(K key, V value) {
        int result = sizeOf(key, value);
        if (result >= 0) {
            return result;
        }
        throw new IllegalStateException("Negative size: " + key + "=" + value);
    }

    /* access modifiers changed from: protected */
    public int sizeOf(K k, V v) {
        return 1;
    }

    public final synchronized void evictAll() {
        trimToSize(-1);
    }

    public final synchronized int size() {
        return this.size;
    }

    public final synchronized int maxSize() {
        return this.maxSize;
    }

    public final synchronized int hitCount() {
        return this.hitCount;
    }

    public final synchronized int missCount() {
        return this.missCount;
    }

    public final synchronized int createCount() {
        return this.createCount;
    }

    public final synchronized int putCount() {
        return this.putCount;
    }

    public final synchronized int evictionCount() {
        return this.evictionCount;
    }

    public final synchronized Map<K, V> snapshot() {
        return new LinkedHashMap(this.map);
    }

    public final synchronized String toString() {
        String format;
        int hitPercent = 0;
        synchronized (this) {
            int accesses = this.hitCount + this.missCount;
            if (accesses != 0) {
                hitPercent = (this.hitCount * 100) / accesses;
            }
            format = String.format("LruCache[maxSize=%d,hits=%d,misses=%d,hitRate=%d%%]", new Object[]{Integer.valueOf(this.maxSize), Integer.valueOf(this.hitCount), Integer.valueOf(this.missCount), Integer.valueOf(hitPercent)});
        }
        return format;
    }
}