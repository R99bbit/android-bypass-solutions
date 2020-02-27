package com.fasterxml.jackson.databind.jsontype.impl;

import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import java.lang.reflect.Type;
import java.util.Collection;
import java.util.HashMap;

public class TypeNameIdResolver extends TypeIdResolverBase {
    protected final MapperConfig<?> _config;
    protected final HashMap<String, JavaType> _idToType;
    protected final HashMap<String, String> _typeToId;

    protected TypeNameIdResolver(MapperConfig<?> mapperConfig, JavaType javaType, HashMap<String, String> hashMap, HashMap<String, JavaType> hashMap2) {
        super(javaType, mapperConfig.getTypeFactory());
        this._config = mapperConfig;
        this._typeToId = hashMap;
        this._idToType = hashMap2;
    }

    public static TypeNameIdResolver construct(MapperConfig<?> mapperConfig, JavaType javaType, Collection<NamedType> collection, boolean z, boolean z2) {
        HashMap hashMap;
        HashMap hashMap2;
        if (z == z2) {
            throw new IllegalArgumentException();
        }
        if (z) {
            hashMap = new HashMap();
        } else {
            hashMap = null;
        }
        if (z2) {
            hashMap2 = new HashMap();
        } else {
            hashMap2 = null;
        }
        if (collection != null) {
            for (NamedType next : collection) {
                Class<?> type = next.getType();
                String _defaultTypeId = next.hasName() ? next.getName() : _defaultTypeId(type);
                if (z) {
                    hashMap.put(type.getName(), _defaultTypeId);
                }
                if (z2) {
                    JavaType javaType2 = (JavaType) hashMap2.get(_defaultTypeId);
                    if (javaType2 == null || !type.isAssignableFrom(javaType2.getRawClass())) {
                        hashMap2.put(_defaultTypeId, mapperConfig.constructType(type));
                    }
                }
            }
        }
        return new TypeNameIdResolver(mapperConfig, javaType, hashMap, hashMap2);
    }

    public Id getMechanism() {
        return Id.NAME;
    }

    public String idFromValue(Object obj) {
        String str;
        Class<?> rawClass = this._typeFactory.constructType((Type) obj.getClass()).getRawClass();
        String name = rawClass.getName();
        synchronized (this._typeToId) {
            str = this._typeToId.get(name);
            if (str == null) {
                if (this._config.isAnnotationProcessingEnabled()) {
                    str = this._config.getAnnotationIntrospector().findTypeName(this._config.introspectClassAnnotations(rawClass).getClassInfo());
                }
                if (str == null) {
                    str = _defaultTypeId(rawClass);
                }
                this._typeToId.put(name, str);
            }
        }
        return str;
    }

    public String idFromValueAndType(Object obj, Class<?> cls) {
        if (obj == null) {
            return null;
        }
        return idFromValue(obj);
    }

    @Deprecated
    public JavaType typeFromId(String str) {
        return _typeFromId(str);
    }

    public JavaType typeFromId(DatabindContext databindContext, String str) {
        return _typeFromId(str);
    }

    /* access modifiers changed from: protected */
    public JavaType _typeFromId(String str) {
        return this._idToType.get(str);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('[').append(getClass().getName());
        sb.append("; id-to-type=").append(this._idToType);
        sb.append(']');
        return sb.toString();
    }

    protected static String _defaultTypeId(Class<?> cls) {
        String name = cls.getName();
        int lastIndexOf = name.lastIndexOf(46);
        return lastIndexOf < 0 ? name : name.substring(lastIndexOf + 1);
    }
}