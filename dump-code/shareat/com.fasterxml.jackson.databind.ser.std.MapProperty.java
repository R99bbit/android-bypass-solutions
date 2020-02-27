package com.fasterxml.jackson.databind.ser.std;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonObjectFormatVisitor;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ser.PropertyWriter;
import java.io.IOException;

public class MapProperty extends PropertyWriter {
    protected Object _key;
    protected JsonSerializer<Object> _keySerializer;
    protected TypeSerializer _typeSerializer;
    protected Object _value;
    protected JsonSerializer<Object> _valueSerializer;

    public MapProperty(TypeSerializer typeSerializer) {
        this._typeSerializer = typeSerializer;
    }

    public void reset(Object obj, Object obj2, JsonSerializer<Object> jsonSerializer, JsonSerializer<Object> jsonSerializer2) {
        this._key = obj;
        this._value = obj2;
        this._keySerializer = jsonSerializer;
        this._valueSerializer = jsonSerializer2;
    }

    public String getName() {
        if (this._key instanceof String) {
            return (String) this._key;
        }
        return String.valueOf(this._key);
    }

    public PropertyName getFullName() {
        return new PropertyName(getName());
    }

    public void serializeAsField(Object obj, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        this._keySerializer.serialize(this._key, jsonGenerator, serializerProvider);
        if (this._typeSerializer == null) {
            this._valueSerializer.serialize(this._value, jsonGenerator, serializerProvider);
        } else {
            this._valueSerializer.serializeWithType(this._value, jsonGenerator, serializerProvider, this._typeSerializer);
        }
    }

    public void serializeAsOmittedField(Object obj, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws Exception {
        if (!jsonGenerator.canOmitFields()) {
            jsonGenerator.writeOmittedField(getName());
        }
    }

    public void serializeAsElement(Object obj, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws Exception {
        if (this._typeSerializer == null) {
            this._valueSerializer.serialize(this._value, jsonGenerator, serializerProvider);
        } else {
            this._valueSerializer.serializeWithType(this._value, jsonGenerator, serializerProvider, this._typeSerializer);
        }
    }

    public void serializeAsPlaceholder(Object obj, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws Exception {
        jsonGenerator.writeNull();
    }

    public void depositSchemaProperty(JsonObjectFormatVisitor jsonObjectFormatVisitor) throws JsonMappingException {
    }

    @Deprecated
    public void depositSchemaProperty(ObjectNode objectNode, SerializerProvider serializerProvider) throws JsonMappingException {
    }
}