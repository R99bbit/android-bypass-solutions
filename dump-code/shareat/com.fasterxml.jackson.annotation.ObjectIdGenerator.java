package com.fasterxml.jackson.annotation;

import java.io.Serializable;

public abstract class ObjectIdGenerator<T> implements Serializable {

    public static final class IdKey implements Serializable {
        private static final long serialVersionUID = 1;
        private final int hashCode;
        private final Object key;
        private final Class<?> scope;
        private final Class<?> type;

        public IdKey(Class<?> cls, Class<?> cls2, Object obj) {
            this.type = cls;
            this.scope = cls2;
            this.key = obj;
            this.hashCode = cls2 != null ? (obj.hashCode() + cls.getName().hashCode()) ^ cls2.getName().hashCode() : obj.hashCode() + cls.getName().hashCode();
        }

        public int hashCode() {
            return this.hashCode;
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (obj.getClass() != getClass()) {
                return false;
            }
            IdKey idKey = (IdKey) obj;
            if (idKey.key.equals(this.key) && idKey.type == this.type && idKey.scope == this.scope) {
                return true;
            }
            return false;
        }
    }

    public abstract boolean canUseFor(ObjectIdGenerator<?> objectIdGenerator);

    public abstract ObjectIdGenerator<T> forScope(Class<?> cls);

    public abstract T generateId(Object obj);

    public abstract Class<?> getScope();

    public abstract IdKey key(Object obj);

    public abstract ObjectIdGenerator<T> newForSerialization(Object obj);
}