package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.annotation.JacksonStdImpl;
import com.fasterxml.jackson.databind.util.ClassUtil;
import java.io.IOException;

@JacksonStdImpl
public class ClassDeserializer extends StdScalarDeserializer<Class<?>> {
    public static final ClassDeserializer instance = new ClassDeserializer();
    private static final long serialVersionUID = 1;

    public ClassDeserializer() {
        super(Class.class);
    }

    public Class<?> deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        JsonToken currentToken = jsonParser.getCurrentToken();
        if (currentToken == JsonToken.VALUE_STRING) {
            try {
                return deserializationContext.findClass(jsonParser.getText().trim());
            } catch (Exception e) {
                throw deserializationContext.instantiationException(this._valueClass, ClassUtil.getRootCause(e));
            }
        } else {
            throw deserializationContext.mappingException(this._valueClass, currentToken);
        }
    }
}