package com.nuvent.shareat.util.crop;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.LinkedHashMap;

public class LruCache<K, V> {
    private final HashMap<K, V> mLruMap;
    private ReferenceQueue<V> mQueue = new ReferenceQueue<>();
    private final HashMap<K, Entry<K, V>> mWeakMap = new HashMap<>();

    private static class Entry<K, V> extends WeakReference<V> {
        K mKey;

        public Entry(K key, V value, ReferenceQueue<V> queue) {
            super(value, queue);
            this.mKey = key;
        }
    }

    public LruCache(int capacity) {
        final int i = capacity;
        this.mLruMap = new LinkedHashMap<K, V>(16, 0.75f, true) {
            /* access modifiers changed from: protected */
            public boolean removeEldestEntry(java.util.Map.Entry<K, V> entry) {
                return size() > i;
            }
        };
    }

    private void cleanUpWeakMap() {
        Entry<K, V> entry = (Entry) this.mQueue.poll();
        while (entry != null) {
            this.mWeakMap.remove(entry.mKey);
            entry = (Entry) this.mQueue.poll();
        }
    }

    public synchronized V put(K key, V value) {
        Entry<K, V> entry;
        cleanUpWeakMap();
        this.mLruMap.put(key, value);
        entry = this.mWeakMap.put(key, new Entry(key, value, this.mQueue));
        return entry == null ? null : entry.get();
    }

    public synchronized V get(K key) {
        V value;
        try {
            cleanUpWeakMap();
            value = this.mLruMap.get(key);
            if (value == null) {
                Entry<K, V> entry = this.mWeakMap.get(key);
                value = entry == null ? null : entry.get();
            }
        }
        return value;
    }

    public synchronized void clear() {
        this.mLruMap.clear();
        this.mWeakMap.clear();
        this.mQueue = new ReferenceQueue<>();
    }
}