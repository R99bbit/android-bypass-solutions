package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.annotation.JacksonStdImpl;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;
import com.fasterxml.jackson.databind.deser.ResolvableDeserializer;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.databind.util.ClassUtil;
import com.fasterxml.jackson.databind.util.ObjectBuffer;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@JacksonStdImpl
public class UntypedObjectDeserializer extends StdDeserializer<Object> implements ResolvableDeserializer, ContextualDeserializer {
    private static final Object[] NO_OBJECTS = new Object[0];
    @Deprecated
    public static final UntypedObjectDeserializer instance = new UntypedObjectDeserializer();
    private static final long serialVersionUID = 1;
    protected JsonDeserializer<Object> _listDeserializer;
    protected JsonDeserializer<Object> _mapDeserializer;
    protected JsonDeserializer<Object> _numberDeserializer;
    protected JsonDeserializer<Object> _stringDeserializer;

    public UntypedObjectDeserializer() {
        super(Object.class);
    }

    public UntypedObjectDeserializer(UntypedObjectDeserializer untypedObjectDeserializer, JsonDeserializer<?> jsonDeserializer, JsonDeserializer<?> jsonDeserializer2, JsonDeserializer<?> jsonDeserializer3, JsonDeserializer<?> jsonDeserializer4) {
        super(Object.class);
        this._mapDeserializer = jsonDeserializer;
        this._listDeserializer = jsonDeserializer2;
        this._stringDeserializer = jsonDeserializer3;
        this._numberDeserializer = jsonDeserializer4;
    }

    public void resolve(DeserializationContext deserializationContext) throws JsonMappingException {
        JavaType constructType = deserializationContext.constructType(Object.class);
        JavaType constructType2 = deserializationContext.constructType(String.class);
        TypeFactory typeFactory = deserializationContext.getTypeFactory();
        this._mapDeserializer = _findCustomDeser(deserializationContext, typeFactory.constructMapType(Map.class, constructType2, constructType));
        this._listDeserializer = _findCustomDeser(deserializationContext, typeFactory.constructCollectionType(List.class, constructType));
        this._stringDeserializer = _findCustomDeser(deserializationContext, constructType2);
        this._numberDeserializer = _findCustomDeser(deserializationContext, typeFactory.constructType((Type) Number.class));
    }

    /* access modifiers changed from: protected */
    public JsonDeserializer<Object> _findCustomDeser(DeserializationContext deserializationContext, JavaType javaType) throws JsonMappingException {
        JsonDeserializer<Object> findRootValueDeserializer = deserializationContext.findRootValueDeserializer(javaType);
        if (ClassUtil.isJacksonStdImpl((Object) findRootValueDeserializer)) {
            return null;
        }
        return findRootValueDeserializer;
    }

    public JsonDeserializer<?> createContextual(DeserializationContext deserializationContext, BeanProperty beanProperty) throws JsonMappingException {
        JsonDeserializer jsonDeserializer;
        JsonDeserializer jsonDeserializer2;
        JsonDeserializer jsonDeserializer3;
        JsonDeserializer jsonDeserializer4 = this._mapDeserializer;
        if (jsonDeserializer4 instanceof ContextualDeserializer) {
            jsonDeserializer = ((ContextualDeserializer) jsonDeserializer4).createContextual(deserializationContext, beanProperty);
        } else {
            jsonDeserializer = jsonDeserializer4;
        }
        JsonDeserializer jsonDeserializer5 = this._listDeserializer;
        if (jsonDeserializer5 instanceof ContextualDeserializer) {
            jsonDeserializer2 = ((ContextualDeserializer) jsonDeserializer5).createContextual(deserializationContext, beanProperty);
        } else {
            jsonDeserializer2 = jsonDeserializer5;
        }
        JsonDeserializer jsonDeserializer6 = this._stringDeserializer;
        if (jsonDeserializer6 instanceof ContextualDeserializer) {
            jsonDeserializer3 = ((ContextualDeserializer) jsonDeserializer6).createContextual(deserializationContext, beanProperty);
        } else {
            jsonDeserializer3 = jsonDeserializer6;
        }
        JsonDeserializer jsonDeserializer7 = this._numberDeserializer;
        if (jsonDeserializer7 instanceof ContextualDeserializer) {
            jsonDeserializer7 = ((ContextualDeserializer) jsonDeserializer7).createContextual(deserializationContext, beanProperty);
        }
        if (jsonDeserializer == this._mapDeserializer && jsonDeserializer2 == this._listDeserializer && jsonDeserializer3 == this._stringDeserializer && jsonDeserializer7 == this._numberDeserializer) {
            return this;
        }
        return _withResolved(jsonDeserializer, jsonDeserializer2, jsonDeserializer3, jsonDeserializer7);
    }

    /* access modifiers changed from: protected */
    public JsonDeserializer<?> _withResolved(JsonDeserializer<?> jsonDeserializer, JsonDeserializer<?> jsonDeserializer2, JsonDeserializer<?> jsonDeserializer3, JsonDeserializer<?> jsonDeserializer4) {
        return new UntypedObjectDeserializer(this, jsonDeserializer, jsonDeserializer2, jsonDeserializer3, jsonDeserializer4);
    }

    public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        switch (jsonParser.getCurrentToken()) {
            case FIELD_NAME:
            case START_OBJECT:
                if (this._mapDeserializer != null) {
                    return this._mapDeserializer.deserialize(jsonParser, deserializationContext);
                }
                return mapObject(jsonParser, deserializationContext);
            case START_ARRAY:
                if (deserializationContext.isEnabled(DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY)) {
                    return mapArrayToArray(jsonParser, deserializationContext);
                }
                if (this._listDeserializer != null) {
                    return this._listDeserializer.deserialize(jsonParser, deserializationContext);
                }
                return mapArray(jsonParser, deserializationContext);
            case VALUE_EMBEDDED_OBJECT:
                return jsonParser.getEmbeddedObject();
            case VALUE_STRING:
                if (this._stringDeserializer != null) {
                    return this._stringDeserializer.deserialize(jsonParser, deserializationContext);
                }
                return jsonParser.getText();
            case VALUE_NUMBER_INT:
                if (this._numberDeserializer != null) {
                    return this._numberDeserializer.deserialize(jsonParser, deserializationContext);
                }
                if (deserializationContext.isEnabled(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)) {
                    return jsonParser.getBigIntegerValue();
                }
                return jsonParser.getNumberValue();
            case VALUE_NUMBER_FLOAT:
                if (this._numberDeserializer != null) {
                    return this._numberDeserializer.deserialize(jsonParser, deserializationContext);
                }
                if (deserializationContext.isEnabled(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)) {
                    return jsonParser.getDecimalValue();
                }
                return Double.valueOf(jsonParser.getDoubleValue());
            case VALUE_TRUE:
                return Boolean.TRUE;
            case VALUE_FALSE:
                return Boolean.FALSE;
            case VALUE_NULL:
                return null;
            default:
                throw deserializationContext.mappingException(Object.class);
        }
    }

    public Object deserializeWithType(JsonParser jsonParser, DeserializationContext deserializationContext, TypeDeserializer typeDeserializer) throws IOException, JsonProcessingException {
        switch (jsonParser.getCurrentToken()) {
            case FIELD_NAME:
            case START_OBJECT:
            case START_ARRAY:
                return typeDeserializer.deserializeTypedFromAny(jsonParser, deserializationContext);
            case VALUE_EMBEDDED_OBJECT:
                return jsonParser.getEmbeddedObject();
            case VALUE_STRING:
                if (this._stringDeserializer != null) {
                    return this._stringDeserializer.deserialize(jsonParser, deserializationContext);
                }
                return jsonParser.getText();
            case VALUE_NUMBER_INT:
                if (this._numberDeserializer != null) {
                    return this._numberDeserializer.deserialize(jsonParser, deserializationContext);
                }
                if (deserializationContext.isEnabled(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)) {
                    return jsonParser.getBigIntegerValue();
                }
                return jsonParser.getNumberValue();
            case VALUE_NUMBER_FLOAT:
                if (this._numberDeserializer != null) {
                    return this._numberDeserializer.deserialize(jsonParser, deserializationContext);
                }
                if (deserializationContext.isEnabled(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)) {
                    return jsonParser.getDecimalValue();
                }
                return Double.valueOf(jsonParser.getDoubleValue());
            case VALUE_TRUE:
                return Boolean.TRUE;
            case VALUE_FALSE:
                return Boolean.FALSE;
            case VALUE_NULL:
                return null;
            default:
                throw deserializationContext.mappingException(Object.class);
        }
    }

    /* access modifiers changed from: protected */
    public Object mapArray(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        int i;
        if (jsonParser.nextToken() == JsonToken.END_ARRAY) {
            return new ArrayList(4);
        }
        ObjectBuffer leaseObjectBuffer = deserializationContext.leaseObjectBuffer();
        int i2 = 0;
        Object[] resetAndStart = leaseObjectBuffer.resetAndStart();
        int i3 = 0;
        do {
            Object deserialize = deserialize(jsonParser, deserializationContext);
            i3++;
            if (i2 >= resetAndStart.length) {
                resetAndStart = leaseObjectBuffer.appendCompletedChunk(resetAndStart);
                i = 0;
            } else {
                i = i2;
            }
            i2 = i + 1;
            resetAndStart[i] = deserialize;
        } while (jsonParser.nextToken() != JsonToken.END_ARRAY);
        ArrayList arrayList = new ArrayList(i3 + (i3 >> 3) + 1);
        leaseObjectBuffer.completeAndClearBuffer(resetAndStart, i2, (List<Object>) arrayList);
        return arrayList;
    }

    /* access modifiers changed from: protected */
    public Object mapObject(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        JsonToken currentToken = jsonParser.getCurrentToken();
        if (currentToken == JsonToken.START_OBJECT) {
            currentToken = jsonParser.nextToken();
        }
        if (currentToken != JsonToken.FIELD_NAME) {
            return new LinkedHashMap(4);
        }
        String text = jsonParser.getText();
        jsonParser.nextToken();
        Object deserialize = deserialize(jsonParser, deserializationContext);
        if (jsonParser.nextToken() != JsonToken.FIELD_NAME) {
            LinkedHashMap linkedHashMap = new LinkedHashMap(4);
            linkedHashMap.put(text, deserialize);
            return linkedHashMap;
        }
        String text2 = jsonParser.getText();
        jsonParser.nextToken();
        Object deserialize2 = deserialize(jsonParser, deserializationContext);
        if (jsonParser.nextToken() != JsonToken.FIELD_NAME) {
            LinkedHashMap linkedHashMap2 = new LinkedHashMap(4);
            linkedHashMap2.put(text, deserialize);
            linkedHashMap2.put(text2, deserialize2);
            return linkedHashMap2;
        }
        LinkedHashMap linkedHashMap3 = new LinkedHashMap();
        linkedHashMap3.put(text, deserialize);
        linkedHashMap3.put(text2, deserialize2);
        do {
            String text3 = jsonParser.getText();
            jsonParser.nextToken();
            linkedHashMap3.put(text3, deserialize(jsonParser, deserializationContext));
        } while (jsonParser.nextToken() != JsonToken.END_OBJECT);
        return linkedHashMap3;
    }

    /* access modifiers changed from: protected */
    public Object[] mapArrayToArray(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        int i;
        if (jsonParser.nextToken() == JsonToken.END_ARRAY) {
            return NO_OBJECTS;
        }
        ObjectBuffer leaseObjectBuffer = deserializationContext.leaseObjectBuffer();
        Object[] resetAndStart = leaseObjectBuffer.resetAndStart();
        int i2 = 0;
        do {
            Object deserialize = deserialize(jsonParser, deserializationContext);
            if (i2 >= resetAndStart.length) {
                resetAndStart = leaseObjectBuffer.appendCompletedChunk(resetAndStart);
                i = 0;
            } else {
                i = i2;
            }
            i2 = i + 1;
            resetAndStart[i] = deserialize;
        } while (jsonParser.nextToken() != JsonToken.END_ARRAY);
        return leaseObjectBuffer.completeAndClearBuffer(resetAndStart, i2);
    }
}