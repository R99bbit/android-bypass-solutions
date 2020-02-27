package com.fasterxml.jackson.databind.introspect;

import com.fasterxml.jackson.databind.util.Annotations;
import java.lang.annotation.Annotation;
import java.util.Collections;
import java.util.HashMap;

public final class AnnotationMap implements Annotations {
    protected HashMap<Class<? extends Annotation>, Annotation> _annotations;

    public AnnotationMap() {
    }

    private AnnotationMap(HashMap<Class<? extends Annotation>, Annotation> hashMap) {
        this._annotations = hashMap;
    }

    public <A extends Annotation> A get(Class<A> cls) {
        if (this._annotations == null) {
            return null;
        }
        return (Annotation) this._annotations.get(cls);
    }

    public Iterable<Annotation> annotations() {
        if (this._annotations == null || this._annotations.size() == 0) {
            return Collections.emptyList();
        }
        return this._annotations.values();
    }

    public static AnnotationMap merge(AnnotationMap annotationMap, AnnotationMap annotationMap2) {
        if (annotationMap == null || annotationMap._annotations == null || annotationMap._annotations.isEmpty()) {
            return annotationMap2;
        }
        if (annotationMap2 == null || annotationMap2._annotations == null || annotationMap2._annotations.isEmpty()) {
            return annotationMap;
        }
        HashMap hashMap = new HashMap();
        for (Annotation next : annotationMap2._annotations.values()) {
            hashMap.put(next.annotationType(), next);
        }
        for (Annotation next2 : annotationMap._annotations.values()) {
            hashMap.put(next2.annotationType(), next2);
        }
        return new AnnotationMap(hashMap);
    }

    public int size() {
        if (this._annotations == null) {
            return 0;
        }
        return this._annotations.size();
    }

    public void addIfNotPresent(Annotation annotation) {
        if (this._annotations == null || !this._annotations.containsKey(annotation.annotationType())) {
            _add(annotation);
        }
    }

    public void add(Annotation annotation) {
        _add(annotation);
    }

    public String toString() {
        if (this._annotations == null) {
            return "[null]";
        }
        return this._annotations.toString();
    }

    /* access modifiers changed from: protected */
    public final void _add(Annotation annotation) {
        if (this._annotations == null) {
            this._annotations = new HashMap<>();
        }
        this._annotations.put(annotation.annotationType(), annotation);
    }
}