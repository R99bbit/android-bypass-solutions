package com.fasterxml.jackson.databind.ser.impl;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ser.SerializerCache.TypeKey;
import java.util.HashMap;

public final class ReadOnlyClassToSerializerMap {
    protected TypeKey _cacheKey = null;
    protected final JsonSerializerMap _map;

    private ReadOnlyClassToSerializerMap(JsonSerializerMap jsonSerializerMap) {
        this._map = jsonSerializerMap;
    }

    public ReadOnlyClassToSerializerMap instance() {
        return new ReadOnlyClassToSerializerMap(this._map);
    }

    public static ReadOnlyClassToSerializerMap from(HashMap<TypeKey, JsonSerializer<Object>> hashMap) {
        return new ReadOnlyClassToSerializerMap(new JsonSerializerMap(hashMap));
    }

    public JsonSerializer<Object> typedValueSerializer(JavaType javaType) {
        if (this._cacheKey == null) {
            this._cacheKey = new TypeKey(javaType, true);
        } else {
            this._cacheKey.resetTyped(javaType);
        }
        return this._map.find(this._cacheKey);
    }

    public JsonSerializer<Object> typedValueSerializer(Class<?> cls) {
        if (this._cacheKey == null) {
            this._cacheKey = new TypeKey(cls, true);
        } else {
            this._cacheKey.resetTyped(cls);
        }
        return this._map.find(this._cacheKey);
    }

    public JsonSerializer<Object> untypedValueSerializer(JavaType javaType) {
        if (this._cacheKey == null) {
            this._cacheKey = new TypeKey(javaType, false);
        } else {
            this._cacheKey.resetUntyped(javaType);
        }
        return this._map.find(this._cacheKey);
    }

    public JsonSerializer<Object> untypedValueSerializer(Class<?> cls) {
        if (this._cacheKey == null) {
            this._cacheKey = new TypeKey(cls, false);
        } else {
            this._cacheKey.resetUntyped(cls);
        }
        return this._map.find(this._cacheKey);
    }
}