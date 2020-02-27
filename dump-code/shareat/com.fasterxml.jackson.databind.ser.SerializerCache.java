package com.fasterxml.jackson.databind.ser;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.impl.ReadOnlyClassToSerializerMap;
import java.util.HashMap;

public final class SerializerCache {
    private volatile ReadOnlyClassToSerializerMap _readOnlyMap = null;
    private HashMap<TypeKey, JsonSerializer<Object>> _sharedMap = new HashMap<>(64);

    public static final class TypeKey {
        protected Class<?> _class;
        protected int _hashCode;
        protected boolean _isTyped;
        protected JavaType _type;

        public TypeKey(Class<?> cls, boolean z) {
            this._class = cls;
            this._type = null;
            this._isTyped = z;
            this._hashCode = hash(cls, z);
        }

        public TypeKey(JavaType javaType, boolean z) {
            this._type = javaType;
            this._class = null;
            this._isTyped = z;
            this._hashCode = hash(javaType, z);
        }

        private static final int hash(Class<?> cls, boolean z) {
            int hashCode = cls.getName().hashCode();
            if (z) {
                return hashCode + 1;
            }
            return hashCode;
        }

        private static final int hash(JavaType javaType, boolean z) {
            int hashCode = javaType.hashCode() - 1;
            if (z) {
                return hashCode - 1;
            }
            return hashCode;
        }

        public void resetTyped(Class<?> cls) {
            this._type = null;
            this._class = cls;
            this._isTyped = true;
            this._hashCode = hash(cls, true);
        }

        public void resetUntyped(Class<?> cls) {
            this._type = null;
            this._class = cls;
            this._isTyped = false;
            this._hashCode = hash(cls, false);
        }

        public void resetTyped(JavaType javaType) {
            this._type = javaType;
            this._class = null;
            this._isTyped = true;
            this._hashCode = hash(javaType, true);
        }

        public void resetUntyped(JavaType javaType) {
            this._type = javaType;
            this._class = null;
            this._isTyped = false;
            this._hashCode = hash(javaType, false);
        }

        public final int hashCode() {
            return this._hashCode;
        }

        public final String toString() {
            if (this._class != null) {
                return "{class: " + this._class.getName() + ", typed? " + this._isTyped + "}";
            }
            return "{type: " + this._type + ", typed? " + this._isTyped + "}";
        }

        public final boolean equals(Object obj) {
            boolean z = true;
            if (obj == null) {
                return false;
            }
            if (obj == this) {
                return true;
            }
            if (obj.getClass() != getClass()) {
                return false;
            }
            TypeKey typeKey = (TypeKey) obj;
            if (typeKey._isTyped != this._isTyped) {
                return false;
            }
            if (this._class == null) {
                return this._type.equals(typeKey._type);
            }
            if (typeKey._class != this._class) {
                z = false;
            }
            return z;
        }
    }

    public ReadOnlyClassToSerializerMap getReadOnlyLookupMap() {
        ReadOnlyClassToSerializerMap readOnlyClassToSerializerMap = this._readOnlyMap;
        if (readOnlyClassToSerializerMap == null) {
            synchronized (this) {
                try {
                    readOnlyClassToSerializerMap = this._readOnlyMap;
                    if (readOnlyClassToSerializerMap == null) {
                        readOnlyClassToSerializerMap = ReadOnlyClassToSerializerMap.from(this._sharedMap);
                        this._readOnlyMap = readOnlyClassToSerializerMap;
                    }
                }
            }
        }
        return readOnlyClassToSerializerMap.instance();
    }

    public synchronized int size() {
        try {
        }
        return this._sharedMap.size();
    }

    public JsonSerializer<Object> untypedValueSerializer(Class<?> cls) {
        JsonSerializer<Object> jsonSerializer;
        synchronized (this) {
            try {
                jsonSerializer = this._sharedMap.get(new TypeKey(cls, false));
            }
        }
        return jsonSerializer;
    }

    public JsonSerializer<Object> untypedValueSerializer(JavaType javaType) {
        JsonSerializer<Object> jsonSerializer;
        synchronized (this) {
            try {
                jsonSerializer = this._sharedMap.get(new TypeKey(javaType, false));
            }
        }
        return jsonSerializer;
    }

    public JsonSerializer<Object> typedValueSerializer(JavaType javaType) {
        JsonSerializer<Object> jsonSerializer;
        synchronized (this) {
            try {
                jsonSerializer = this._sharedMap.get(new TypeKey(javaType, true));
            }
        }
        return jsonSerializer;
    }

    public JsonSerializer<Object> typedValueSerializer(Class<?> cls) {
        JsonSerializer<Object> jsonSerializer;
        synchronized (this) {
            try {
                jsonSerializer = this._sharedMap.get(new TypeKey(cls, true));
            }
        }
        return jsonSerializer;
    }

    public void addTypedSerializer(JavaType javaType, JsonSerializer<Object> jsonSerializer) {
        synchronized (this) {
            if (this._sharedMap.put(new TypeKey(javaType, true), jsonSerializer) == null) {
                this._readOnlyMap = null;
            }
        }
    }

    public void addTypedSerializer(Class<?> cls, JsonSerializer<Object> jsonSerializer) {
        synchronized (this) {
            if (this._sharedMap.put(new TypeKey(cls, true), jsonSerializer) == null) {
                this._readOnlyMap = null;
            }
        }
    }

    public void addAndResolveNonTypedSerializer(Class<?> cls, JsonSerializer<Object> jsonSerializer, SerializerProvider serializerProvider) throws JsonMappingException {
        synchronized (this) {
            if (this._sharedMap.put(new TypeKey(cls, false), jsonSerializer) == null) {
                this._readOnlyMap = null;
            }
            if (jsonSerializer instanceof ResolvableSerializer) {
                ((ResolvableSerializer) jsonSerializer).resolve(serializerProvider);
            }
        }
    }

    public void addAndResolveNonTypedSerializer(JavaType javaType, JsonSerializer<Object> jsonSerializer, SerializerProvider serializerProvider) throws JsonMappingException {
        synchronized (this) {
            if (this._sharedMap.put(new TypeKey(javaType, false), jsonSerializer) == null) {
                this._readOnlyMap = null;
            }
            if (jsonSerializer instanceof ResolvableSerializer) {
                ((ResolvableSerializer) jsonSerializer).resolve(serializerProvider);
            }
        }
    }

    public synchronized void flush() {
        this._sharedMap.clear();
    }
}