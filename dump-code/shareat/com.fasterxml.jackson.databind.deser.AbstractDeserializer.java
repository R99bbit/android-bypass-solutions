package com.fasterxml.jackson.databind.deser;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.deser.impl.ObjectIdReader;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import java.io.IOException;
import java.io.Serializable;
import java.util.Map;

public class AbstractDeserializer extends JsonDeserializer<Object> implements Serializable {
    private static final long serialVersionUID = -3010349050434697698L;
    protected final boolean _acceptBoolean;
    protected final boolean _acceptDouble;
    protected final boolean _acceptInt;
    protected final boolean _acceptString;
    protected final Map<String, SettableBeanProperty> _backRefProperties;
    protected final JavaType _baseType;
    protected final ObjectIdReader _objectIdReader;

    public AbstractDeserializer(BeanDeserializerBuilder beanDeserializerBuilder, BeanDescription beanDescription, Map<String, SettableBeanProperty> map) {
        boolean z;
        boolean z2;
        boolean z3 = false;
        this._baseType = beanDescription.getType();
        this._objectIdReader = beanDeserializerBuilder.getObjectIdReader();
        this._backRefProperties = map;
        Class<?> rawClass = this._baseType.getRawClass();
        this._acceptString = rawClass.isAssignableFrom(String.class);
        if (rawClass == Boolean.TYPE || rawClass.isAssignableFrom(Boolean.class)) {
            z = true;
        } else {
            z = false;
        }
        this._acceptBoolean = z;
        if (rawClass == Integer.TYPE || rawClass.isAssignableFrom(Integer.class)) {
            z2 = true;
        } else {
            z2 = false;
        }
        this._acceptInt = z2;
        this._acceptDouble = (rawClass == Double.TYPE || rawClass.isAssignableFrom(Double.class)) ? true : z3;
    }

    protected AbstractDeserializer(BeanDescription beanDescription) {
        boolean z;
        boolean z2;
        boolean z3 = false;
        this._baseType = beanDescription.getType();
        this._objectIdReader = null;
        this._backRefProperties = null;
        Class<?> rawClass = this._baseType.getRawClass();
        this._acceptString = rawClass.isAssignableFrom(String.class);
        if (rawClass == Boolean.TYPE || rawClass.isAssignableFrom(Boolean.class)) {
            z = true;
        } else {
            z = false;
        }
        this._acceptBoolean = z;
        if (rawClass == Integer.TYPE || rawClass.isAssignableFrom(Integer.class)) {
            z2 = true;
        } else {
            z2 = false;
        }
        this._acceptInt = z2;
        this._acceptDouble = (rawClass == Double.TYPE || rawClass.isAssignableFrom(Double.class)) ? true : z3;
    }

    public static AbstractDeserializer constructForNonPOJO(BeanDescription beanDescription) {
        return new AbstractDeserializer(beanDescription);
    }

    public Class<?> handledType() {
        return this._baseType.getRawClass();
    }

    public boolean isCachable() {
        return true;
    }

    public ObjectIdReader getObjectIdReader() {
        return this._objectIdReader;
    }

    public SettableBeanProperty findBackReference(String str) {
        if (this._backRefProperties == null) {
            return null;
        }
        return this._backRefProperties.get(str);
    }

    public Object deserializeWithType(JsonParser jsonParser, DeserializationContext deserializationContext, TypeDeserializer typeDeserializer) throws IOException, JsonProcessingException {
        if (this._objectIdReader != null) {
            JsonToken currentToken = jsonParser.getCurrentToken();
            if (currentToken != null && currentToken.isScalarValue()) {
                return _deserializeFromObjectId(jsonParser, deserializationContext);
            }
        }
        Object _deserializeIfNatural = _deserializeIfNatural(jsonParser, deserializationContext);
        return _deserializeIfNatural == null ? typeDeserializer.deserializeTypedFromObject(jsonParser, deserializationContext) : _deserializeIfNatural;
    }

    public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        throw deserializationContext.instantiationException(this._baseType.getRawClass(), (String) "abstract types either need to be mapped to concrete types, have custom deserializer, or be instantiated with additional type information");
    }

    /* access modifiers changed from: protected */
    public Object _deserializeIfNatural(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        JsonToken currentToken = jsonParser.getCurrentToken();
        if (currentToken.isScalarValue()) {
            if (currentToken == JsonToken.VALUE_STRING) {
                if (this._acceptString) {
                    return jsonParser.getText();
                }
            } else if (currentToken == JsonToken.VALUE_NUMBER_INT) {
                if (this._acceptInt) {
                    return Integer.valueOf(jsonParser.getIntValue());
                }
            } else if (currentToken == JsonToken.VALUE_NUMBER_FLOAT) {
                if (this._acceptDouble) {
                    return Double.valueOf(jsonParser.getDoubleValue());
                }
            } else if (currentToken == JsonToken.VALUE_TRUE) {
                if (this._acceptBoolean) {
                    return Boolean.TRUE;
                }
            } else if (currentToken == JsonToken.VALUE_FALSE && this._acceptBoolean) {
                return Boolean.FALSE;
            }
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public Object _deserializeFromObjectId(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        Object readObjectReference = this._objectIdReader.readObjectReference(jsonParser, deserializationContext);
        Object obj = deserializationContext.findObjectId(readObjectReference, this._objectIdReader.generator).item;
        if (obj != null) {
            return obj;
        }
        throw new IllegalStateException("Could not resolve Object Id [" + readObjectReference + "] -- unresolved forward-reference?");
    }
}