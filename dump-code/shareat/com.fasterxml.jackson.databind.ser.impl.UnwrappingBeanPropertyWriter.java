package com.fasterxml.jackson.databind.ser.impl;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.core.io.SerializedString;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.util.NameTransformer;
import com.kakao.auth.helper.ServerProtocol;
import java.util.Iterator;
import java.util.Map.Entry;

public class UnwrappingBeanPropertyWriter extends BeanPropertyWriter {
    protected final NameTransformer _nameTransformer;

    public UnwrappingBeanPropertyWriter(BeanPropertyWriter beanPropertyWriter, NameTransformer nameTransformer) {
        super(beanPropertyWriter);
        this._nameTransformer = nameTransformer;
    }

    private UnwrappingBeanPropertyWriter(UnwrappingBeanPropertyWriter unwrappingBeanPropertyWriter, NameTransformer nameTransformer, SerializedString serializedString) {
        super(unwrappingBeanPropertyWriter, serializedString);
        this._nameTransformer = nameTransformer;
    }

    public UnwrappingBeanPropertyWriter rename(NameTransformer nameTransformer) {
        return new UnwrappingBeanPropertyWriter(this, NameTransformer.chainedTransformer(nameTransformer, this._nameTransformer), new SerializedString(nameTransformer.transform(this._name.getValue())));
    }

    public boolean isUnwrapping() {
        return true;
    }

    public void serializeAsField(Object obj, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws Exception {
        Object obj2 = get(obj);
        if (obj2 != null) {
            JsonSerializer<Object> jsonSerializer = this._serializer;
            if (jsonSerializer == null) {
                Class cls = obj2.getClass();
                PropertySerializerMap propertySerializerMap = this._dynamicSerializers;
                jsonSerializer = propertySerializerMap.serializerFor(cls);
                if (jsonSerializer == null) {
                    jsonSerializer = _findAndAddDynamic(propertySerializerMap, cls, serializerProvider);
                }
            }
            if (this._suppressableValue != null) {
                if (MARKER_FOR_EMPTY == this._suppressableValue) {
                    if (jsonSerializer.isEmpty(obj2)) {
                        return;
                    }
                } else if (this._suppressableValue.equals(obj2)) {
                    return;
                }
            }
            if (obj2 == obj) {
                _handleSelfReference(obj, jsonSerializer);
            }
            if (!jsonSerializer.isUnwrappingSerializer()) {
                jsonGenerator.writeFieldName((SerializableString) this._name);
            }
            if (this._typeSerializer == null) {
                jsonSerializer.serialize(obj2, jsonGenerator, serializerProvider);
            } else {
                jsonSerializer.serializeWithType(obj2, jsonGenerator, serializerProvider, this._typeSerializer);
            }
        }
    }

    public void assignSerializer(JsonSerializer<Object> jsonSerializer) {
        NameTransformer nameTransformer;
        super.assignSerializer(jsonSerializer);
        if (this._serializer != null) {
            NameTransformer nameTransformer2 = this._nameTransformer;
            if (this._serializer.isUnwrappingSerializer()) {
                nameTransformer = NameTransformer.chainedTransformer(nameTransformer2, ((UnwrappingBeanSerializer) this._serializer)._nameTransformer);
            } else {
                nameTransformer = nameTransformer2;
            }
            this._serializer = this._serializer.unwrappingSerializer(nameTransformer);
        }
    }

    /* access modifiers changed from: protected */
    public void _depositSchemaProperty(ObjectNode objectNode, JsonNode jsonNode) {
        JsonNode jsonNode2 = jsonNode.get((String) ServerProtocol.PROPERTIES_KEY);
        if (jsonNode2 != null) {
            Iterator<Entry<String, JsonNode>> fields = jsonNode2.fields();
            while (fields.hasNext()) {
                Entry next = fields.next();
                String str = (String) next.getKey();
                if (this._nameTransformer != null) {
                    str = this._nameTransformer.transform(str);
                }
                objectNode.put(str, (JsonNode) next.getValue());
            }
        }
    }

    /* JADX WARNING: type inference failed for: r5v0, types: [java.lang.Class<?>, java.lang.Class] */
    /* access modifiers changed from: protected */
    /* JADX WARNING: Unknown variable types count: 1 */
    public JsonSerializer<Object> _findAndAddDynamic(PropertySerializerMap propertySerializerMap, Class<?> r5, SerializerProvider serializerProvider) throws JsonMappingException {
        JsonSerializer<Object> findValueSerializer;
        NameTransformer nameTransformer;
        if (this._nonTrivialBaseType != null) {
            findValueSerializer = serializerProvider.findValueSerializer(serializerProvider.constructSpecializedType(this._nonTrivialBaseType, r5), (BeanProperty) this);
        } else {
            findValueSerializer = serializerProvider.findValueSerializer((Class<?>) r5, (BeanProperty) this);
        }
        NameTransformer nameTransformer2 = this._nameTransformer;
        if (findValueSerializer.isUnwrappingSerializer()) {
            nameTransformer = NameTransformer.chainedTransformer(nameTransformer2, ((UnwrappingBeanSerializer) findValueSerializer)._nameTransformer);
        } else {
            nameTransformer = nameTransformer2;
        }
        JsonSerializer<Object> unwrappingSerializer = findValueSerializer.unwrappingSerializer(nameTransformer);
        this._dynamicSerializers = this._dynamicSerializers.newWith(r5, unwrappingSerializer);
        return unwrappingSerializer;
    }
}