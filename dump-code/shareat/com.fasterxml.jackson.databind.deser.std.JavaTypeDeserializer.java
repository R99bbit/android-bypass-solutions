package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import java.io.IOException;

public class JavaTypeDeserializer extends StdScalarDeserializer<JavaType> {
    public static final JavaTypeDeserializer instance = new JavaTypeDeserializer();
    private static final long serialVersionUID = 1;

    public JavaTypeDeserializer() {
        super(JavaType.class);
    }

    public JavaType deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        JsonToken currentToken = jsonParser.getCurrentToken();
        if (currentToken == JsonToken.VALUE_STRING) {
            String trim = jsonParser.getText().trim();
            if (trim.length() == 0) {
                return (JavaType) getEmptyValue();
            }
            return deserializationContext.getTypeFactory().constructFromCanonical(trim);
        } else if (currentToken == JsonToken.VALUE_EMBEDDED_OBJECT) {
            return (JavaType) jsonParser.getEmbeddedObject();
        } else {
            throw deserializationContext.mappingException(this._valueClass);
        }
    }
}