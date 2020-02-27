package com.fasterxml.jackson.databind.node;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;

public class POJONode extends ValueNode {
    protected final Object _value;

    public POJONode(Object obj) {
        this._value = obj;
    }

    public JsonNodeType getNodeType() {
        return JsonNodeType.POJO;
    }

    public JsonToken asToken() {
        return JsonToken.VALUE_EMBEDDED_OBJECT;
    }

    public byte[] binaryValue() throws IOException {
        if (this._value instanceof byte[]) {
            return (byte[]) this._value;
        }
        return super.binaryValue();
    }

    public String asText() {
        return this._value == null ? "null" : this._value.toString();
    }

    public boolean asBoolean(boolean z) {
        if (this._value == null || !(this._value instanceof Boolean)) {
            return z;
        }
        return ((Boolean) this._value).booleanValue();
    }

    public int asInt(int i) {
        if (this._value instanceof Number) {
            return ((Number) this._value).intValue();
        }
        return i;
    }

    public long asLong(long j) {
        if (this._value instanceof Number) {
            return ((Number) this._value).longValue();
        }
        return j;
    }

    public double asDouble(double d) {
        if (this._value instanceof Number) {
            return ((Number) this._value).doubleValue();
        }
        return d;
    }

    public final void serialize(JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonProcessingException {
        if (this._value == null) {
            serializerProvider.defaultSerializeNull(jsonGenerator);
        } else {
            jsonGenerator.writeObject(this._value);
        }
    }

    public Object getPojo() {
        return this._value;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || !(obj instanceof POJONode)) {
            return false;
        }
        return _pojoEquals((POJONode) obj);
    }

    /* access modifiers changed from: protected */
    public boolean _pojoEquals(POJONode pOJONode) {
        if (this._value == null) {
            return pOJONode._value == null;
        }
        return this._value.equals(pOJONode._value);
    }

    public int hashCode() {
        return this._value.hashCode();
    }

    public String toString() {
        return String.valueOf(this._value);
    }
}