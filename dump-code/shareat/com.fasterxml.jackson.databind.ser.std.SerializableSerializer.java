package com.fasterxml.jackson.databind.ser.std;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializable;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JacksonStdImpl;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonFormatVisitorWrapper;
import com.fasterxml.jackson.databind.jsonschema.JsonSerializableSchema;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.kakao.auth.helper.ServerProtocol;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.concurrent.atomic.AtomicReference;

@JacksonStdImpl
public class SerializableSerializer extends StdSerializer<JsonSerializable> {
    private static final AtomicReference<ObjectMapper> _mapperReference = new AtomicReference<>();
    public static final SerializableSerializer instance = new SerializableSerializer();

    protected SerializableSerializer() {
        super(JsonSerializable.class);
    }

    public void serialize(JsonSerializable jsonSerializable, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException {
        jsonSerializable.serialize(jsonGenerator, serializerProvider);
    }

    public final void serializeWithType(JsonSerializable jsonSerializable, JsonGenerator jsonGenerator, SerializerProvider serializerProvider, TypeSerializer typeSerializer) throws IOException, JsonGenerationException {
        jsonSerializable.serializeWithType(jsonGenerator, serializerProvider, typeSerializer);
    }

    /* JADX WARNING: Removed duplicated region for block: B:12:0x004d  */
    /* JADX WARNING: Removed duplicated region for block: B:16:0x005d  */
    public JsonNode getSchema(SerializerProvider serializerProvider, Type type) throws JsonMappingException {
        String str;
        String str2 = null;
        ObjectNode createObjectNode = createObjectNode();
        String str3 = "any";
        if (type != null) {
            Class<?> rawClass = TypeFactory.rawClass(type);
            if (rawClass.isAnnotationPresent(JsonSerializableSchema.class)) {
                JsonSerializableSchema jsonSerializableSchema = (JsonSerializableSchema) rawClass.getAnnotation(JsonSerializableSchema.class);
                String schemaType = jsonSerializableSchema.schemaType();
                if (!JsonSerializableSchema.NO_VALUE.equals(jsonSerializableSchema.schemaObjectPropertiesDefinition())) {
                    str = jsonSerializableSchema.schemaObjectPropertiesDefinition();
                } else {
                    str = null;
                }
                if (!JsonSerializableSchema.NO_VALUE.equals(jsonSerializableSchema.schemaItemDefinition())) {
                    str2 = jsonSerializableSchema.schemaItemDefinition();
                    str3 = schemaType;
                } else {
                    str3 = schemaType;
                }
                createObjectNode.put((String) KakaoTalkLinkProtocol.ACTION_TYPE, str3);
                if (str != null) {
                    try {
                        createObjectNode.put((String) ServerProtocol.PROPERTIES_KEY, _getObjectMapper().readTree(str));
                    } catch (IOException e) {
                        throw new JsonMappingException("Failed to parse @JsonSerializableSchema.schemaObjectPropertiesDefinition value");
                    }
                }
                if (str2 != null) {
                    try {
                        createObjectNode.put((String) "items", _getObjectMapper().readTree(str2));
                    } catch (IOException e2) {
                        throw new JsonMappingException("Failed to parse @JsonSerializableSchema.schemaItemDefinition value");
                    }
                }
                return createObjectNode;
            }
        }
        str = null;
        createObjectNode.put((String) KakaoTalkLinkProtocol.ACTION_TYPE, str3);
        if (str != null) {
        }
        if (str2 != null) {
        }
        return createObjectNode;
    }

    private static final synchronized ObjectMapper _getObjectMapper() {
        ObjectMapper objectMapper;
        synchronized (SerializableSerializer.class) {
            objectMapper = _mapperReference.get();
            if (objectMapper == null) {
                objectMapper = new ObjectMapper();
                _mapperReference.set(objectMapper);
            }
        }
        return objectMapper;
    }

    public void acceptJsonFormatVisitor(JsonFormatVisitorWrapper jsonFormatVisitorWrapper, JavaType javaType) throws JsonMappingException {
        jsonFormatVisitorWrapper.expectAnyFormat(javaType);
    }
}