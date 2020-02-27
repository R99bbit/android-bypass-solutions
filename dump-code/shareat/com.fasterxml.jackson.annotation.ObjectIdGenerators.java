package com.fasterxml.jackson.annotation;

import com.fasterxml.jackson.annotation.ObjectIdGenerator.IdKey;
import java.util.UUID;

public class ObjectIdGenerators {

    private static abstract class Base<T> extends ObjectIdGenerator<T> {
        protected final Class<?> _scope;

        public abstract T generateId(Object obj);

        protected Base(Class<?> cls) {
            this._scope = cls;
        }

        public final Class<?> getScope() {
            return this._scope;
        }

        public boolean canUseFor(ObjectIdGenerator<?> objectIdGenerator) {
            return objectIdGenerator.getClass() == getClass() && objectIdGenerator.getScope() == this._scope;
        }
    }

    public static final class IntSequenceGenerator extends Base<Integer> {
        private static final long serialVersionUID = 1;
        protected transient int _nextValue;

        public /* bridge */ /* synthetic */ boolean canUseFor(ObjectIdGenerator objectIdGenerator) {
            return super.canUseFor(objectIdGenerator);
        }

        public IntSequenceGenerator() {
            this(Object.class, -1);
        }

        public IntSequenceGenerator(Class<?> cls, int i) {
            super(cls);
            this._nextValue = i;
        }

        /* access modifiers changed from: protected */
        public int initialValue() {
            return 1;
        }

        public ObjectIdGenerator<Integer> forScope(Class<?> cls) {
            return this._scope == cls ? this : new IntSequenceGenerator(cls, this._nextValue);
        }

        public ObjectIdGenerator<Integer> newForSerialization(Object obj) {
            return new IntSequenceGenerator(this._scope, initialValue());
        }

        public IdKey key(Object obj) {
            return new IdKey(getClass(), this._scope, obj);
        }

        public Integer generateId(Object obj) {
            int i = this._nextValue;
            this._nextValue++;
            return Integer.valueOf(i);
        }
    }

    public static abstract class None extends ObjectIdGenerator<Object> {
    }

    public static abstract class PropertyGenerator extends Base<Object> {
        private static final long serialVersionUID = 1;

        public /* bridge */ /* synthetic */ boolean canUseFor(ObjectIdGenerator objectIdGenerator) {
            return super.canUseFor(objectIdGenerator);
        }

        protected PropertyGenerator(Class<?> cls) {
            super(cls);
        }
    }

    public static final class UUIDGenerator extends Base<UUID> {
        private static final long serialVersionUID = 1;

        public UUIDGenerator() {
            this(Object.class);
        }

        private UUIDGenerator(Class<?> cls) {
            super(Object.class);
        }

        public ObjectIdGenerator<UUID> forScope(Class<?> cls) {
            return this;
        }

        public ObjectIdGenerator<UUID> newForSerialization(Object obj) {
            return this;
        }

        public UUID generateId(Object obj) {
            return UUID.randomUUID();
        }

        public IdKey key(Object obj) {
            return new IdKey(getClass(), null, obj);
        }

        public boolean canUseFor(ObjectIdGenerator<?> objectIdGenerator) {
            return objectIdGenerator.getClass() == getClass();
        }
    }
}