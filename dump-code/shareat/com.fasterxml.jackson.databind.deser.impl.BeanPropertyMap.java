package com.fasterxml.jackson.databind.deser.impl;

import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;
import com.fasterxml.jackson.databind.util.NameTransformer;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.NoSuchElementException;

public final class BeanPropertyMap implements Iterable<SettableBeanProperty>, Serializable {
    private static final long serialVersionUID = 1;
    private final Bucket[] _buckets;
    private final int _hashMask;
    private int _nextBucketIndex = 0;
    private final int _size;

    private static final class Bucket implements Serializable {
        private static final long serialVersionUID = 1;
        public final int index;
        public final String key;
        public final Bucket next;
        public final SettableBeanProperty value;

        public Bucket(Bucket bucket, String str, SettableBeanProperty settableBeanProperty, int i) {
            this.next = bucket;
            this.key = str;
            this.value = settableBeanProperty;
            this.index = i;
        }
    }

    private static final class IteratorImpl implements Iterator<SettableBeanProperty> {
        private final Bucket[] _buckets;
        private Bucket _currentBucket;
        private int _nextBucketIndex;

        public IteratorImpl(Bucket[] bucketArr) {
            int i;
            this._buckets = bucketArr;
            int i2 = 0;
            int length = this._buckets.length;
            while (true) {
                if (i2 >= length) {
                    i = i2;
                    break;
                }
                i = i2 + 1;
                Bucket bucket = this._buckets[i2];
                if (bucket != null) {
                    this._currentBucket = bucket;
                    break;
                }
                i2 = i;
            }
            this._nextBucketIndex = i;
        }

        public boolean hasNext() {
            return this._currentBucket != null;
        }

        public SettableBeanProperty next() {
            Bucket bucket = this._currentBucket;
            if (bucket == null) {
                throw new NoSuchElementException();
            }
            Bucket bucket2 = bucket.next;
            while (bucket2 == null && this._nextBucketIndex < this._buckets.length) {
                Bucket[] bucketArr = this._buckets;
                int i = this._nextBucketIndex;
                this._nextBucketIndex = i + 1;
                bucket2 = bucketArr[i];
            }
            this._currentBucket = bucket2;
            return bucket.value;
        }

        public void remove() {
            throw new UnsupportedOperationException();
        }
    }

    public BeanPropertyMap(Collection<SettableBeanProperty> collection) {
        this._size = collection.size();
        int findSize = findSize(this._size);
        this._hashMask = findSize - 1;
        Bucket[] bucketArr = new Bucket[findSize];
        for (SettableBeanProperty next : collection) {
            String name = next.getName();
            int hashCode = name.hashCode() & this._hashMask;
            Bucket bucket = bucketArr[hashCode];
            int i = this._nextBucketIndex;
            this._nextBucketIndex = i + 1;
            bucketArr[hashCode] = new Bucket(bucket, name, next, i);
        }
        this._buckets = bucketArr;
    }

    private BeanPropertyMap(Bucket[] bucketArr, int i, int i2) {
        this._buckets = bucketArr;
        this._size = i;
        this._hashMask = bucketArr.length - 1;
        this._nextBucketIndex = i2;
    }

    public BeanPropertyMap withProperty(SettableBeanProperty settableBeanProperty) {
        int length = this._buckets.length;
        Bucket[] bucketArr = new Bucket[length];
        System.arraycopy(this._buckets, 0, bucketArr, 0, length);
        String name = settableBeanProperty.getName();
        if (find(settableBeanProperty.getName()) == null) {
            int hashCode = name.hashCode() & this._hashMask;
            Bucket bucket = bucketArr[hashCode];
            int i = this._nextBucketIndex;
            this._nextBucketIndex = i + 1;
            bucketArr[hashCode] = new Bucket(bucket, name, settableBeanProperty, i);
            return new BeanPropertyMap(bucketArr, this._size + 1, this._nextBucketIndex);
        }
        BeanPropertyMap beanPropertyMap = new BeanPropertyMap(bucketArr, length, this._nextBucketIndex);
        beanPropertyMap.replace(settableBeanProperty);
        return beanPropertyMap;
    }

    public BeanPropertyMap renameAll(NameTransformer nameTransformer) {
        if (nameTransformer == null || nameTransformer == NameTransformer.NOP) {
            return this;
        }
        Iterator<SettableBeanProperty> it = iterator();
        ArrayList arrayList = new ArrayList();
        while (it.hasNext()) {
            SettableBeanProperty next = it.next();
            SettableBeanProperty withSimpleName = next.withSimpleName(nameTransformer.transform(next.getName()));
            JsonDeserializer<Object> valueDeserializer = withSimpleName.getValueDeserializer();
            if (valueDeserializer != null) {
                JsonDeserializer<Object> unwrappingDeserializer = valueDeserializer.unwrappingDeserializer(nameTransformer);
                if (unwrappingDeserializer != valueDeserializer) {
                    withSimpleName = withSimpleName.withValueDeserializer(unwrappingDeserializer);
                }
            }
            arrayList.add(withSimpleName);
        }
        return new BeanPropertyMap(arrayList);
    }

    public BeanPropertyMap assignIndexes() {
        Bucket[] bucketArr;
        int i = 0;
        for (Bucket bucket : this._buckets) {
            while (bucket != null) {
                bucket.value.assignIndex(i);
                bucket = bucket.next;
                i++;
            }
        }
        return this;
    }

    private static final int findSize(int i) {
        int i2 = 2;
        while (i2 < (i <= 32 ? i + i : (i >> 2) + i)) {
            i2 += i2;
        }
        return i2;
    }

    public String toString() {
        SettableBeanProperty[] propertiesInInsertionOrder;
        int i = 0;
        StringBuilder sb = new StringBuilder();
        sb.append("Properties=[");
        for (SettableBeanProperty settableBeanProperty : getPropertiesInInsertionOrder()) {
            if (settableBeanProperty != null) {
                int i2 = i + 1;
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(settableBeanProperty.getName());
                sb.append('(');
                sb.append(settableBeanProperty.getType());
                sb.append(')');
                i = i2;
            }
        }
        sb.append(']');
        return sb.toString();
    }

    public Iterator<SettableBeanProperty> iterator() {
        return new IteratorImpl(this._buckets);
    }

    public SettableBeanProperty[] getPropertiesInInsertionOrder() {
        Bucket[] bucketArr;
        SettableBeanProperty[] settableBeanPropertyArr = new SettableBeanProperty[this._nextBucketIndex];
        for (Bucket bucket : this._buckets) {
            while (bucket != null) {
                settableBeanPropertyArr[bucket.index] = bucket.value;
                bucket = bucket.next;
            }
        }
        return settableBeanPropertyArr;
    }

    public int size() {
        return this._size;
    }

    public SettableBeanProperty find(String str) {
        if (str == null) {
            throw new IllegalArgumentException("Can not pass null property name");
        }
        int hashCode = this._hashMask & str.hashCode();
        Bucket bucket = this._buckets[hashCode];
        if (bucket == null) {
            return null;
        }
        if (bucket.key == str) {
            return bucket.value;
        }
        do {
            bucket = bucket.next;
            if (bucket == null) {
                return _findWithEquals(str, hashCode);
            }
        } while (bucket.key != str);
        return bucket.value;
    }

    public SettableBeanProperty find(int i) {
        for (Bucket bucket : this._buckets) {
            while (bucket != null) {
                if (bucket.index == i) {
                    return bucket.value;
                }
                bucket = bucket.next;
            }
        }
        return null;
    }

    public void replace(SettableBeanProperty settableBeanProperty) {
        String name = settableBeanProperty.getName();
        int hashCode = name.hashCode() & (this._buckets.length - 1);
        int i = -1;
        Bucket bucket = null;
        for (Bucket bucket2 = this._buckets[hashCode]; bucket2 != null; bucket2 = bucket2.next) {
            if (i >= 0 || !bucket2.key.equals(name)) {
                bucket = new Bucket(bucket, bucket2.key, bucket2.value, bucket2.index);
            } else {
                i = bucket2.index;
            }
        }
        if (i < 0) {
            throw new NoSuchElementException("No entry '" + settableBeanProperty + "' found, can't replace");
        }
        this._buckets[hashCode] = new Bucket(bucket, name, settableBeanProperty, i);
    }

    public void remove(SettableBeanProperty settableBeanProperty) {
        String name = settableBeanProperty.getName();
        int hashCode = name.hashCode() & (this._buckets.length - 1);
        boolean z = false;
        Bucket bucket = null;
        for (Bucket bucket2 = this._buckets[hashCode]; bucket2 != null; bucket2 = bucket2.next) {
            if (z || !bucket2.key.equals(name)) {
                bucket = new Bucket(bucket, bucket2.key, bucket2.value, bucket2.index);
            } else {
                z = true;
            }
        }
        if (!z) {
            throw new NoSuchElementException("No entry '" + settableBeanProperty + "' found, can't remove");
        }
        this._buckets[hashCode] = bucket;
    }

    private SettableBeanProperty _findWithEquals(String str, int i) {
        for (Bucket bucket = this._buckets[i]; bucket != null; bucket = bucket.next) {
            if (str.equals(bucket.key)) {
                return bucket.value;
            }
        }
        return null;
    }
}