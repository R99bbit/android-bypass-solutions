package org.jboss.netty.util.internal;

import java.util.AbstractCollection;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;

public final class ConcurrentHashMap<K, V> extends AbstractMap<K, V> implements ConcurrentMap<K, V> {
    static final int DEFAULT_CONCURRENCY_LEVEL = 16;
    static final int DEFAULT_INITIAL_CAPACITY = 16;
    static final float DEFAULT_LOAD_FACTOR = 0.75f;
    static final int MAXIMUM_CAPACITY = 1073741824;
    static final int MAX_SEGMENTS = 65536;
    static final int RETRIES_BEFORE_LOCK = 2;
    Set<Entry<K, V>> entrySet;
    Set<K> keySet;
    final int segmentMask;
    final int segmentShift;
    final Segment<K, V>[] segments;
    Collection<V> values;

    final class EntryIterator extends HashIterator implements ReusableIterator<Entry<K, V>> {
        EntryIterator() {
            super();
        }

        public Entry<K, V> next() {
            HashEntry<K, V> e = nextEntry();
            return new WriteThroughEntry(e.key(), e.value());
        }
    }

    final class EntrySet extends AbstractSet<Entry<K, V>> {
        EntrySet() {
        }

        public Iterator<Entry<K, V>> iterator() {
            return new EntryIterator();
        }

        public boolean contains(Object o) {
            if (!(o instanceof Entry)) {
                return false;
            }
            Entry<?, ?> e = (Entry) o;
            V v = ConcurrentHashMap.this.get(e.getKey());
            if (v == null || !v.equals(e.getValue())) {
                return false;
            }
            return true;
        }

        public boolean remove(Object o) {
            if (!(o instanceof Entry)) {
                return false;
            }
            Entry<?, ?> e = (Entry) o;
            return ConcurrentHashMap.this.remove(e.getKey(), e.getValue());
        }

        public int size() {
            return ConcurrentHashMap.this.size();
        }

        public boolean isEmpty() {
            return ConcurrentHashMap.this.isEmpty();
        }

        public void clear() {
            ConcurrentHashMap.this.clear();
        }
    }

    static final class HashEntry<K, V> {
        final int hash;
        final Object key;
        final HashEntry<K, V> next;
        volatile Object value;

        HashEntry(K key2, int hash2, HashEntry<K, V> next2, V value2) {
            this.hash = hash2;
            this.next = next2;
            this.key = key2;
            this.value = value2;
        }

        /* access modifiers changed from: 0000 */
        public K key() {
            return this.key;
        }

        /* access modifiers changed from: 0000 */
        public V value() {
            return this.value;
        }

        /* access modifiers changed from: 0000 */
        public void setValue(V value2) {
            this.value = value2;
        }

        static <K, V> HashEntry<K, V>[] newArray(int i) {
            return new HashEntry[i];
        }
    }

    abstract class HashIterator {
        K currentKey;
        HashEntry<K, V>[] currentTable;
        HashEntry<K, V> lastReturned;
        HashEntry<K, V> nextEntry;
        int nextSegmentIndex;
        int nextTableIndex = -1;

        HashIterator() {
            this.nextSegmentIndex = ConcurrentHashMap.this.segments.length - 1;
            advance();
        }

        public void rewind() {
            this.nextSegmentIndex = ConcurrentHashMap.this.segments.length - 1;
            this.nextTableIndex = -1;
            this.currentTable = null;
            this.nextEntry = null;
            this.lastReturned = null;
            this.currentKey = null;
            advance();
        }

        public boolean hasMoreElements() {
            return hasNext();
        }

        /* access modifiers changed from: 0000 */
        public final void advance() {
            if (this.nextEntry != null) {
                HashEntry<K, V> hashEntry = this.nextEntry.next;
                this.nextEntry = hashEntry;
                if (hashEntry != null) {
                    return;
                }
            }
            while (this.nextTableIndex >= 0) {
                HashEntry<K, V>[] hashEntryArr = this.currentTable;
                int i = this.nextTableIndex;
                this.nextTableIndex = i - 1;
                HashEntry<K, V> hashEntry2 = hashEntryArr[i];
                this.nextEntry = hashEntry2;
                if (hashEntry2 != null) {
                    return;
                }
            }
            while (this.nextSegmentIndex >= 0) {
                Segment<K, V>[] segmentArr = ConcurrentHashMap.this.segments;
                int i2 = this.nextSegmentIndex;
                this.nextSegmentIndex = i2 - 1;
                Segment<K, V> seg = segmentArr[i2];
                if (seg.count != 0) {
                    this.currentTable = seg.table;
                    for (int j = this.currentTable.length - 1; j >= 0; j--) {
                        HashEntry<K, V> hashEntry3 = this.currentTable[j];
                        this.nextEntry = hashEntry3;
                        if (hashEntry3 != null) {
                            this.nextTableIndex = j - 1;
                            return;
                        }
                    }
                    continue;
                }
            }
        }

        public boolean hasNext() {
            while (this.nextEntry != null) {
                if (this.nextEntry.key() != null) {
                    return true;
                }
                advance();
            }
            return false;
        }

        /* access modifiers changed from: 0000 */
        public HashEntry<K, V> nextEntry() {
            while (this.nextEntry != null) {
                this.lastReturned = this.nextEntry;
                this.currentKey = this.lastReturned.key();
                advance();
                if (this.currentKey != null) {
                    return this.lastReturned;
                }
            }
            throw new NoSuchElementException();
        }

        public void remove() {
            if (this.lastReturned == null) {
                throw new IllegalStateException();
            }
            ConcurrentHashMap.this.remove(this.currentKey);
            this.lastReturned = null;
        }
    }

    final class KeyIterator extends HashIterator implements ReusableIterator<K>, Enumeration<K> {
        KeyIterator() {
            super();
        }

        public K next() {
            return nextEntry().key();
        }

        public K nextElement() {
            return nextEntry().key();
        }
    }

    final class KeySet extends AbstractSet<K> {
        KeySet() {
        }

        public Iterator<K> iterator() {
            return new KeyIterator();
        }

        public int size() {
            return ConcurrentHashMap.this.size();
        }

        public boolean isEmpty() {
            return ConcurrentHashMap.this.isEmpty();
        }

        public boolean contains(Object o) {
            return ConcurrentHashMap.this.containsKey(o);
        }

        public boolean remove(Object o) {
            return ConcurrentHashMap.this.remove(o) != null;
        }

        public void clear() {
            ConcurrentHashMap.this.clear();
        }
    }

    static final class Segment<K, V> extends ReentrantLock {
        private static final long serialVersionUID = -2001752926705396395L;
        volatile transient int count;
        final float loadFactor;
        int modCount;
        volatile transient HashEntry<K, V>[] table;
        int threshold;

        Segment(int initialCapacity, float lf) {
            this.loadFactor = lf;
            setTable(HashEntry.newArray(initialCapacity));
        }

        static <K, V> Segment<K, V>[] newArray(int i) {
            return new Segment[i];
        }

        private static boolean keyEq(Object src, Object dest) {
            return src.equals(dest);
        }

        /* access modifiers changed from: 0000 */
        public void setTable(HashEntry<K, V>[] newTable) {
            this.threshold = (int) (((float) newTable.length) * this.loadFactor);
            this.table = newTable;
        }

        /* access modifiers changed from: 0000 */
        public HashEntry<K, V> getFirst(int hash) {
            HashEntry<K, V>[] tab = this.table;
            return tab[(tab.length - 1) & hash];
        }

        /* access modifiers changed from: 0000 */
        public HashEntry<K, V> newHashEntry(K key, int hash, HashEntry<K, V> next, V value) {
            return new HashEntry<>(key, hash, next, value);
        }

        /* access modifiers changed from: 0000 */
        public V readValueUnderLock(HashEntry<K, V> e) {
            lock();
            try {
                return e.value();
            } finally {
                unlock();
            }
        }

        /* access modifiers changed from: 0000 */
        public V get(Object key, int hash) {
            if (this.count != 0) {
                HashEntry<K, V> e = getFirst(hash);
                while (e != null) {
                    if (e.hash != hash || !keyEq(key, e.key())) {
                        e = e.next;
                    } else {
                        V opaque = e.value();
                        if (opaque != null) {
                            return opaque;
                        }
                        return readValueUnderLock(e);
                    }
                }
            }
            return null;
        }

        /* access modifiers changed from: 0000 */
        public boolean containsKey(Object key, int hash) {
            if (this.count != 0) {
                for (HashEntry<K, V> e = getFirst(hash); e != null; e = e.next) {
                    if (e.hash == hash && keyEq(key, e.key())) {
                        return true;
                    }
                }
            }
            return false;
        }

        /* access modifiers changed from: 0000 */
        public boolean containsValue(Object value) {
            HashEntry<K, V>[] arr$;
            V v;
            if (this.count != 0) {
                for (HashEntry<K, V> e : this.table) {
                    while (e != null) {
                        V opaque = e.value();
                        if (opaque == null) {
                            v = readValueUnderLock(e);
                        } else {
                            v = opaque;
                        }
                        if (value.equals(v)) {
                            return true;
                        }
                        e = e.next;
                    }
                }
            }
            return false;
        }

        /* access modifiers changed from: 0000 */
        public boolean replace(K key, int hash, V oldValue, V newValue) {
            lock();
            try {
                HashEntry<K, V> e = getFirst(hash);
                while (e != null && (e.hash != hash || !keyEq(key, e.key()))) {
                    e = e.next;
                }
                boolean replaced = false;
                if (e != null && oldValue.equals(e.value())) {
                    replaced = true;
                    e.setValue(newValue);
                }
                return replaced;
            } finally {
                unlock();
            }
        }

        /* access modifiers changed from: 0000 */
        public V replace(K key, int hash, V newValue) {
            lock();
            try {
                HashEntry<K, V> e = getFirst(hash);
                while (e != null && (e.hash != hash || !keyEq(key, e.key()))) {
                    e = e.next;
                }
                V oldValue = null;
                if (e != null) {
                    oldValue = e.value();
                    e.setValue(newValue);
                }
                return oldValue;
            } finally {
                unlock();
            }
        }

        /* access modifiers changed from: 0000 */
        /* JADX WARNING: Removed duplicated region for block: B:15:0x0036 A[Catch:{ all -> 0x0053 }] */
        /* JADX WARNING: Removed duplicated region for block: B:20:0x0043  */
        public V put(K key, int hash, V value, boolean onlyIfAbsent) {
            int c;
            HashEntry<K, V> e;
            V oldValue;
            lock();
            try {
                int c2 = this.count;
                int c3 = c2 + 1;
                if (c2 > this.threshold) {
                    int reduced = rehash();
                    if (reduced > 0) {
                        c = c3 - reduced;
                        this.count = c - 1;
                        HashEntry<K, V>[] tab = this.table;
                        int index = hash & (tab.length - 1);
                        HashEntry<K, V> first = tab[index];
                        e = first;
                        while (e != null && (e.hash != hash || !keyEq(key, e.key()))) {
                            e = e.next;
                        }
                        if (e == null) {
                            oldValue = e.value();
                            if (!onlyIfAbsent) {
                                e.setValue(value);
                            }
                        } else {
                            oldValue = null;
                            this.modCount++;
                            tab[index] = newHashEntry(key, hash, first, value);
                            this.count = c;
                        }
                        return oldValue;
                    }
                }
                c = c3;
                HashEntry<K, V>[] tab2 = this.table;
                int index2 = hash & (tab2.length - 1);
                HashEntry<K, V> first2 = tab2[index2];
                e = first2;
                while (e != null) {
                    e = e.next;
                }
                if (e == null) {
                }
                return oldValue;
            } finally {
                unlock();
            }
        }

        /* access modifiers changed from: 0000 */
        public int rehash() {
            HashEntry<K, V>[] hashEntryArr;
            HashEntry<K, V>[] oldTable = this.table;
            int oldCapacity = oldTable.length;
            if (oldCapacity >= ConcurrentHashMap.MAXIMUM_CAPACITY) {
                return 0;
            }
            HashEntry<K, V>[] newTable = HashEntry.newArray(oldCapacity << 1);
            this.threshold = (int) (((float) newTable.length) * this.loadFactor);
            int sizeMask = newTable.length - 1;
            int reduce = 0;
            for (HashEntry<K, V> e : oldTable) {
                if (e != null) {
                    HashEntry<K, V> next = e.next;
                    int idx = e.hash & sizeMask;
                    if (next == null) {
                        newTable[idx] = e;
                    } else {
                        HashEntry<K, V> lastRun = e;
                        int lastIdx = idx;
                        for (HashEntry<K, V> last = next; last != null; last = last.next) {
                            int k = last.hash & sizeMask;
                            if (k != lastIdx) {
                                lastIdx = k;
                                lastRun = last;
                            }
                        }
                        newTable[lastIdx] = lastRun;
                        for (HashEntry<K, V> p = e; p != lastRun; p = p.next) {
                            K key = p.key();
                            if (key == null) {
                                reduce++;
                            } else {
                                int k2 = p.hash & sizeMask;
                                newTable[k2] = newHashEntry(key, p.hash, newTable[k2], p.value());
                            }
                        }
                    }
                }
            }
            this.table = newTable;
            return reduce;
        }

        /* access modifiers changed from: 0000 */
        public V remove(Object key, int hash, Object value, boolean refRemove) {
            lock();
            try {
                int c = this.count - 1;
                HashEntry<K, V>[] tab = this.table;
                int index = hash & (tab.length - 1);
                HashEntry<K, V> first = tab[index];
                HashEntry<K, V> e = first;
                while (e != null && key != e.key && (refRemove || hash != e.hash || !keyEq(key, e.key()))) {
                    e = e.next;
                }
                V oldValue = null;
                if (e != null) {
                    V v = e.value();
                    if (value == null || value.equals(v)) {
                        oldValue = v;
                        this.modCount++;
                        HashEntry<K, V> newFirst = e.next;
                        for (HashEntry<K, V> p = first; p != e; p = p.next) {
                            K pKey = p.key();
                            if (pKey == null) {
                                c--;
                            } else {
                                newFirst = newHashEntry(pKey, p.hash, newFirst, p.value());
                            }
                        }
                        tab[index] = newFirst;
                        this.count = c;
                    }
                }
                return oldValue;
            } finally {
                unlock();
            }
        }

        /* access modifiers changed from: 0000 */
        public void clear() {
            if (this.count != 0) {
                lock();
                try {
                    HashEntry<K, V>[] tab = this.table;
                    for (int i = 0; i < tab.length; i++) {
                        tab[i] = null;
                    }
                    this.modCount++;
                    this.count = 0;
                } finally {
                    unlock();
                }
            }
        }
    }

    static class SimpleEntry<K, V> implements Entry<K, V> {
        private final K key;
        private V value;

        public SimpleEntry(K key2, V value2) {
            this.key = key2;
            this.value = value2;
        }

        public SimpleEntry(Entry<? extends K, ? extends V> entry) {
            this.key = entry.getKey();
            this.value = entry.getValue();
        }

        public K getKey() {
            return this.key;
        }

        public V getValue() {
            return this.value;
        }

        public V setValue(V value2) {
            V oldValue = this.value;
            this.value = value2;
            return oldValue;
        }

        public boolean equals(Object o) {
            if (!(o instanceof Entry)) {
                return false;
            }
            Entry e = (Entry) o;
            if (!eq(this.key, e.getKey()) || !eq(this.value, e.getValue())) {
                return false;
            }
            return true;
        }

        public int hashCode() {
            int i = 0;
            int hashCode = this.key == null ? 0 : this.key.hashCode();
            if (this.value != null) {
                i = this.value.hashCode();
            }
            return hashCode ^ i;
        }

        public String toString() {
            return this.key + "=" + this.value;
        }

        private static boolean eq(Object o1, Object o2) {
            if (o1 == null) {
                return o2 == null;
            }
            return o1.equals(o2);
        }
    }

    final class ValueIterator extends HashIterator implements ReusableIterator<V>, Enumeration<V> {
        ValueIterator() {
            super();
        }

        public V next() {
            return nextEntry().value();
        }

        public V nextElement() {
            return nextEntry().value();
        }
    }

    final class Values extends AbstractCollection<V> {
        Values() {
        }

        public Iterator<V> iterator() {
            return new ValueIterator();
        }

        public int size() {
            return ConcurrentHashMap.this.size();
        }

        public boolean isEmpty() {
            return ConcurrentHashMap.this.isEmpty();
        }

        public boolean contains(Object o) {
            return ConcurrentHashMap.this.containsValue(o);
        }

        public void clear() {
            ConcurrentHashMap.this.clear();
        }
    }

    final class WriteThroughEntry extends SimpleEntry<K, V> {
        WriteThroughEntry(K k, V v) {
            super(k, v);
        }

        public V setValue(V value) {
            if (value == null) {
                throw new NullPointerException();
            }
            V v = super.setValue(value);
            ConcurrentHashMap.this.put(getKey(), value);
            return v;
        }
    }

    private static int hash(int h) {
        int h2 = h + ((h << 15) ^ -12931);
        int h3 = h2 ^ (h2 >>> 10);
        int h4 = h3 + (h3 << 3);
        int h5 = h4 ^ (h4 >>> 6);
        int h6 = h5 + (h5 << 2) + (h5 << 14);
        return (h6 >>> 16) ^ h6;
    }

    /* access modifiers changed from: 0000 */
    public Segment<K, V> segmentFor(int hash) {
        return this.segments[(hash >>> this.segmentShift) & this.segmentMask];
    }

    private static int hashOf(Object key) {
        return hash(key.hashCode());
    }

    public ConcurrentHashMap(int initialCapacity, float loadFactor, int concurrencyLevel) {
        if (loadFactor <= 0.0f || initialCapacity < 0 || concurrencyLevel <= 0) {
            throw new IllegalArgumentException();
        }
        int sshift = 0;
        int ssize = 1;
        while (ssize < (concurrencyLevel > 65536 ? 65536 : concurrencyLevel)) {
            sshift++;
            ssize <<= 1;
        }
        this.segmentShift = 32 - sshift;
        this.segmentMask = ssize - 1;
        this.segments = Segment.newArray(ssize);
        initialCapacity = initialCapacity > MAXIMUM_CAPACITY ? MAXIMUM_CAPACITY : initialCapacity;
        int c = initialCapacity / ssize;
        int cap = 1;
        while (cap < (c * ssize < initialCapacity ? c + 1 : c)) {
            cap <<= 1;
        }
        for (int i = 0; i < this.segments.length; i++) {
            this.segments[i] = new Segment<>(cap, loadFactor);
        }
    }

    public ConcurrentHashMap(int initialCapacity, float loadFactor) {
        this(initialCapacity, loadFactor, 16);
    }

    public ConcurrentHashMap(int initialCapacity) {
        this(initialCapacity, DEFAULT_LOAD_FACTOR, 16);
    }

    public ConcurrentHashMap() {
        this(16, DEFAULT_LOAD_FACTOR, 16);
    }

    public ConcurrentHashMap(Map<? extends K, ? extends V> m) {
        this(Math.max(((int) (((float) m.size()) / DEFAULT_LOAD_FACTOR)) + 1, 16), DEFAULT_LOAD_FACTOR, 16);
        putAll(m);
    }

    public boolean isEmpty() {
        Segment<K, V>[] segments2 = this.segments;
        int[] mc = new int[segments2.length];
        int mcsum = 0;
        for (int i = 0; i < segments2.length; i++) {
            if (segments2[i].count != 0) {
                return false;
            }
            int i2 = segments2[i].modCount;
            mc[i] = i2;
            mcsum += i2;
        }
        if (mcsum != 0) {
            for (int i3 = 0; i3 < segments2.length; i3++) {
                if (segments2[i3].count != 0 || mc[i3] != segments2[i3].modCount) {
                    return false;
                }
            }
        }
        return true;
    }

    public int size() {
        Segment[] segments2 = this.segments;
        long sum = 0;
        long check = 0;
        int[] mc = new int[segments2.length];
        for (int k = 0; k < 2; k++) {
            check = 0;
            sum = 0;
            int mcsum = 0;
            for (int i = 0; i < segments2.length; i++) {
                sum += (long) segments2[i].count;
                int i2 = segments2[i].modCount;
                mc[i] = i2;
                mcsum += i2;
            }
            if (mcsum != 0) {
                int i3 = 0;
                while (true) {
                    if (i3 >= segments2.length) {
                        break;
                    }
                    check += (long) segments2[i3].count;
                    if (mc[i3] != segments2[i3].modCount) {
                        check = -1;
                        break;
                    }
                    i3++;
                }
            }
            if (check == sum) {
                break;
            }
        }
        if (check != sum) {
            long sum2 = 0;
            for (Segment lock : segments2) {
                lock.lock();
            }
            for (Segment segment : segments2) {
                sum2 = sum + ((long) segment.count);
            }
            for (Segment unlock : segments2) {
                unlock.unlock();
            }
        }
        if (sum > 2147483647L) {
            return ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }
        return (int) sum;
    }

    public V get(Object key) {
        int hash = hashOf(key);
        return segmentFor(hash).get(key, hash);
    }

    public boolean containsKey(Object key) {
        int hash = hashOf(key);
        return segmentFor(hash).containsKey(key, hash);
    }

    public boolean containsValue(Object value) {
        if (value == null) {
            throw new NullPointerException();
        }
        Segment[] segments2 = this.segments;
        int[] mc = new int[segments2.length];
        for (int k = 0; k < 2; k++) {
            int mcsum = 0;
            for (int i = 0; i < segments2.length; i++) {
                int i2 = segments2[i].modCount;
                mc[i] = i2;
                mcsum += i2;
                if (segments2[i].containsValue(value)) {
                    return true;
                }
            }
            boolean cleanSweep = true;
            if (mcsum != 0) {
                int i3 = 0;
                while (true) {
                    if (i3 >= segments2.length) {
                        break;
                    } else if (mc[i3] != segments2[i3].modCount) {
                        cleanSweep = false;
                        break;
                    } else {
                        i3++;
                    }
                }
            }
            if (cleanSweep) {
                return false;
            }
        }
        for (Segment lock : segments2) {
            lock.lock();
        }
        boolean found = false;
        Segment[] arr$ = segments2;
        try {
            int len$ = arr$.length;
            int i$ = 0;
            while (true) {
                if (i$ >= len$) {
                    break;
                } else if (arr$[i$].containsValue(value)) {
                    found = true;
                    break;
                } else {
                    i$++;
                }
            }
            return found;
        } finally {
            for (Segment unlock : segments2) {
                unlock.unlock();
            }
        }
    }

    public boolean contains(Object value) {
        return containsValue(value);
    }

    public V put(K key, V value) {
        if (value == null) {
            throw new NullPointerException();
        }
        int hash = hashOf(key);
        return segmentFor(hash).put(key, hash, value, false);
    }

    public V putIfAbsent(K key, V value) {
        if (value == null) {
            throw new NullPointerException();
        }
        int hash = hashOf(key);
        return segmentFor(hash).put(key, hash, value, true);
    }

    public void putAll(Map<? extends K, ? extends V> m) {
        for (Entry<? extends K, ? extends V> e : m.entrySet()) {
            put(e.getKey(), e.getValue());
        }
    }

    public V remove(Object key) {
        int hash = hashOf(key);
        return segmentFor(hash).remove(key, hash, null, false);
    }

    public boolean remove(Object key, Object value) {
        int hash = hashOf(key);
        if (value == null || segmentFor(hash).remove(key, hash, value, false) == null) {
            return false;
        }
        return true;
    }

    public boolean replace(K key, V oldValue, V newValue) {
        if (oldValue == null || newValue == null) {
            throw new NullPointerException();
        }
        int hash = hashOf(key);
        return segmentFor(hash).replace(key, hash, oldValue, newValue);
    }

    public V replace(K key, V value) {
        if (value == null) {
            throw new NullPointerException();
        }
        int hash = hashOf(key);
        return segmentFor(hash).replace(key, hash, value);
    }

    public void clear() {
        for (Segment<K, V> segment : this.segments) {
            segment.clear();
        }
    }

    public Set<K> keySet() {
        Set<K> ks = this.keySet;
        if (ks != null) {
            return ks;
        }
        Set<K> ks2 = new KeySet<>();
        this.keySet = ks2;
        return ks2;
    }

    public Collection<V> values() {
        Collection<V> vs = this.values;
        if (vs != null) {
            return vs;
        }
        Collection<V> vs2 = new Values<>();
        this.values = vs2;
        return vs2;
    }

    public Set<Entry<K, V>> entrySet() {
        Set<Entry<K, V>> es = this.entrySet;
        if (es != null) {
            return es;
        }
        Set<Entry<K, V>> es2 = new EntrySet<>();
        this.entrySet = es2;
        return es2;
    }

    public Enumeration<K> keys() {
        return new KeyIterator();
    }

    public Enumeration<V> elements() {
        return new ValueIterator();
    }
}