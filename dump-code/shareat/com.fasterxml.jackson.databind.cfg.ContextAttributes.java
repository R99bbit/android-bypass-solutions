package com.fasterxml.jackson.databind.cfg;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class ContextAttributes {

    public static class Impl extends ContextAttributes implements Serializable {
        protected static final Impl EMPTY = new Impl(Collections.emptyMap());
        protected static final Object NULL_SURROGATE = new Object();
        private static final long serialVersionUID = 1;
        protected transient Map<Object, Object> _nonShared;
        protected final Map<Object, Object> _shared;

        protected Impl(Map<Object, Object> map) {
            this._shared = map;
            this._nonShared = null;
        }

        protected Impl(Map<Object, Object> map, Map<Object, Object> map2) {
            this._shared = map;
            this._nonShared = map2;
        }

        public static ContextAttributes getEmpty() {
            return EMPTY;
        }

        public ContextAttributes withSharedAttribute(Object obj, Object obj2) {
            Map _copy;
            if (this == EMPTY) {
                _copy = new HashMap(8);
            } else {
                _copy = _copy(this._shared);
            }
            _copy.put(obj, obj2);
            return new Impl(_copy);
        }

        public ContextAttributes withSharedAttributes(Map<Object, Object> map) {
            return new Impl(map);
        }

        public ContextAttributes withoutSharedAttribute(Object obj) {
            if (this._shared.isEmpty() || !this._shared.containsKey(obj)) {
                return this;
            }
            if (this._shared.size() == 1) {
                return EMPTY;
            }
            Map<Object, Object> _copy = _copy(this._shared);
            _copy.remove(obj);
            return new Impl(_copy);
        }

        public Object getAttribute(Object obj) {
            if (this._nonShared != null) {
                Object obj2 = this._nonShared.get(obj);
                if (obj2 != null) {
                    if (obj2 == NULL_SURROGATE) {
                        return null;
                    }
                    return obj2;
                }
            }
            return this._shared.get(obj);
        }

        public ContextAttributes withPerCallAttribute(Object obj, Object obj2) {
            if (obj2 == null) {
                if (!this._shared.containsKey(obj)) {
                    return this;
                }
                obj2 = NULL_SURROGATE;
            }
            if (this._nonShared == null) {
                return nonSharedInstance(obj, obj2);
            }
            this._nonShared.put(obj, obj2);
            return this;
        }

        /* access modifiers changed from: protected */
        public ContextAttributes nonSharedInstance(Object obj, Object obj2) {
            HashMap hashMap = new HashMap();
            if (obj2 == null) {
                obj2 = NULL_SURROGATE;
            }
            hashMap.put(obj, obj2);
            return new Impl(this._shared, hashMap);
        }

        private Map<Object, Object> _copy(Map<Object, Object> map) {
            return new HashMap(map);
        }
    }

    public abstract Object getAttribute(Object obj);

    public abstract ContextAttributes withPerCallAttribute(Object obj, Object obj2);

    public abstract ContextAttributes withSharedAttribute(Object obj, Object obj2);

    public abstract ContextAttributes withSharedAttributes(Map<Object, Object> map);

    public abstract ContextAttributes withoutSharedAttribute(Object obj);

    public static ContextAttributes getEmpty() {
        return Impl.getEmpty();
    }
}