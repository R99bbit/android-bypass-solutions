package org.jboss.netty.handler.codec.serialization;

import java.lang.ref.Reference;
import java.lang.ref.SoftReference;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

public class SoftReferenceMap<K, V> extends ReferenceMap<K, V> {
    public /* bridge */ /* synthetic */ void clear() {
        super.clear();
    }

    public /* bridge */ /* synthetic */ boolean containsKey(Object x0) {
        return super.containsKey(x0);
    }

    public /* bridge */ /* synthetic */ boolean containsValue(Object x0) {
        return super.containsValue(x0);
    }

    public /* bridge */ /* synthetic */ Set entrySet() {
        return super.entrySet();
    }

    public /* bridge */ /* synthetic */ Object get(Object x0) {
        return super.get(x0);
    }

    public /* bridge */ /* synthetic */ boolean isEmpty() {
        return super.isEmpty();
    }

    public /* bridge */ /* synthetic */ Set keySet() {
        return super.keySet();
    }

    public /* bridge */ /* synthetic */ Object put(Object x0, Object x1) {
        return super.put(x0, x1);
    }

    public /* bridge */ /* synthetic */ void putAll(Map x0) {
        super.putAll(x0);
    }

    public /* bridge */ /* synthetic */ Object remove(Object x0) {
        return super.remove(x0);
    }

    public /* bridge */ /* synthetic */ int size() {
        return super.size();
    }

    public /* bridge */ /* synthetic */ Collection values() {
        return super.values();
    }

    public SoftReferenceMap(Map<K, Reference<V>> delegate) {
        super(delegate);
    }

    /* access modifiers changed from: 0000 */
    public Reference<V> fold(V value) {
        return new SoftReference(value);
    }
}