package com.fasterxml.jackson.databind.jsontype.impl;

import com.fasterxml.jackson.annotation.JsonTypeInfo.As;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.annotation.NoClass;
import com.fasterxml.jackson.databind.deser.std.NullifyingDeserializer;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;

public abstract class TypeDeserializerBase extends TypeDeserializer implements Serializable {
    private static final long serialVersionUID = 278445030337366675L;
    protected final JavaType _baseType;
    protected final JavaType _defaultImpl;
    protected JsonDeserializer<Object> _defaultImplDeserializer;
    protected final HashMap<String, JsonDeserializer<Object>> _deserializers;
    protected final TypeIdResolver _idResolver;
    protected final BeanProperty _property;
    protected final boolean _typeIdVisible;
    protected final String _typePropertyName;

    public abstract TypeDeserializer forProperty(BeanProperty beanProperty);

    public abstract As getTypeInclusion();

    protected TypeDeserializerBase(JavaType javaType, TypeIdResolver typeIdResolver, String str, boolean z, Class<?> cls) {
        this._baseType = javaType;
        this._idResolver = typeIdResolver;
        this._typePropertyName = str;
        this._typeIdVisible = z;
        this._deserializers = new HashMap<>();
        if (cls == null) {
            this._defaultImpl = null;
        } else {
            this._defaultImpl = javaType.forcedNarrowBy(cls);
        }
        this._property = null;
    }

    protected TypeDeserializerBase(TypeDeserializerBase typeDeserializerBase, BeanProperty beanProperty) {
        this._baseType = typeDeserializerBase._baseType;
        this._idResolver = typeDeserializerBase._idResolver;
        this._typePropertyName = typeDeserializerBase._typePropertyName;
        this._typeIdVisible = typeDeserializerBase._typeIdVisible;
        this._deserializers = typeDeserializerBase._deserializers;
        this._defaultImpl = typeDeserializerBase._defaultImpl;
        this._defaultImplDeserializer = typeDeserializerBase._defaultImplDeserializer;
        this._property = beanProperty;
    }

    public String baseTypeName() {
        return this._baseType.getRawClass().getName();
    }

    public final String getPropertyName() {
        return this._typePropertyName;
    }

    public TypeIdResolver getTypeIdResolver() {
        return this._idResolver;
    }

    public Class<?> getDefaultImpl() {
        if (this._defaultImpl == null) {
            return null;
        }
        return this._defaultImpl.getRawClass();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('[').append(getClass().getName());
        sb.append("; base-type:").append(this._baseType);
        sb.append("; id-resolver: ").append(this._idResolver);
        sb.append(']');
        return sb.toString();
    }

    /* access modifiers changed from: protected */
    public final JsonDeserializer<Object> _findDeserializer(DeserializationContext deserializationContext, String str) throws IOException, JsonProcessingException {
        JsonDeserializer<Object> jsonDeserializer;
        JavaType typeFromId;
        synchronized (this._deserializers) {
            try {
                jsonDeserializer = this._deserializers.get(str);
                if (jsonDeserializer == null) {
                    if (this._idResolver instanceof TypeIdResolverBase) {
                        typeFromId = ((TypeIdResolverBase) this._idResolver).typeFromId(deserializationContext, str);
                    } else {
                        typeFromId = this._idResolver.typeFromId(str);
                    }
                    if (typeFromId != null) {
                        if (this._baseType != null && this._baseType.getClass() == typeFromId.getClass()) {
                            typeFromId = this._baseType.narrowBy(typeFromId.getRawClass());
                        }
                        jsonDeserializer = deserializationContext.findContextualValueDeserializer(typeFromId, this._property);
                    } else if (this._defaultImpl == null) {
                        throw deserializationContext.unknownTypeException(this._baseType, str);
                    } else {
                        jsonDeserializer = _findDefaultImplDeserializer(deserializationContext);
                    }
                    this._deserializers.put(str, jsonDeserializer);
                }
            }
        }
        return jsonDeserializer;
    }

    /* access modifiers changed from: protected */
    public final JsonDeserializer<Object> _findDefaultImplDeserializer(DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        JsonDeserializer<Object> jsonDeserializer;
        if (this._defaultImpl == null) {
            if (!deserializationContext.isEnabled(DeserializationFeature.FAIL_ON_INVALID_SUBTYPE)) {
                return NullifyingDeserializer.instance;
            }
            return null;
        } else if (this._defaultImpl.getRawClass() == NoClass.class) {
            return NullifyingDeserializer.instance;
        } else {
            synchronized (this._defaultImpl) {
                if (this._defaultImplDeserializer == null) {
                    this._defaultImplDeserializer = deserializationContext.findContextualValueDeserializer(this._defaultImpl, this._property);
                }
                jsonDeserializer = this._defaultImplDeserializer;
            }
            return jsonDeserializer;
        }
    }

    /* access modifiers changed from: protected */
    public Object _deserializeWithNativeTypeId(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        JsonDeserializer<Object> _findDeserializer;
        Object typeId = jsonParser.getTypeId();
        if (typeId != null) {
            _findDeserializer = _findDeserializer(deserializationContext, typeId instanceof String ? (String) typeId : String.valueOf(typeId));
        } else if (this._defaultImpl != null) {
            _findDeserializer = _findDefaultImplDeserializer(deserializationContext);
        } else {
            throw deserializationContext.mappingException((String) "No (native) type id found when one was expected for polymorphic type handling");
        }
        return _findDeserializer.deserialize(jsonParser, deserializationContext);
    }
}