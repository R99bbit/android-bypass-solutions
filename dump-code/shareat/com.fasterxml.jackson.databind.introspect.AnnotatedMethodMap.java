package com.fasterxml.jackson.databind.introspect;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;

public final class AnnotatedMethodMap implements Iterable<AnnotatedMethod> {
    protected LinkedHashMap<MemberKey, AnnotatedMethod> _methods;

    public void add(AnnotatedMethod annotatedMethod) {
        if (this._methods == null) {
            this._methods = new LinkedHashMap<>();
        }
        this._methods.put(new MemberKey(annotatedMethod.getAnnotated()), annotatedMethod);
    }

    public AnnotatedMethod remove(AnnotatedMethod annotatedMethod) {
        return remove(annotatedMethod.getAnnotated());
    }

    public AnnotatedMethod remove(Method method) {
        if (this._methods != null) {
            return (AnnotatedMethod) this._methods.remove(new MemberKey(method));
        }
        return null;
    }

    public boolean isEmpty() {
        return this._methods == null || this._methods.size() == 0;
    }

    public int size() {
        if (this._methods == null) {
            return 0;
        }
        return this._methods.size();
    }

    public AnnotatedMethod find(String str, Class<?>[] clsArr) {
        if (this._methods == null) {
            return null;
        }
        return this._methods.get(new MemberKey(str, clsArr));
    }

    public AnnotatedMethod find(Method method) {
        if (this._methods == null) {
            return null;
        }
        return this._methods.get(new MemberKey(method));
    }

    public Iterator<AnnotatedMethod> iterator() {
        if (this._methods != null) {
            return this._methods.values().iterator();
        }
        return Collections.emptyList().iterator();
    }
}