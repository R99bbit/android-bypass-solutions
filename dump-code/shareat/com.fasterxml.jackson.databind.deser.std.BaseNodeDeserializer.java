package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonParser.NumberType;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;

/* compiled from: JsonNodeDeserializer */
abstract class BaseNodeDeserializer<T extends JsonNode> extends StdDeserializer<T> {
    public BaseNodeDeserializer(Class<T> cls) {
        super(cls);
    }

    public Object deserializeWithType(JsonParser jsonParser, DeserializationContext deserializationContext, TypeDeserializer typeDeserializer) throws IOException, JsonProcessingException {
        return typeDeserializer.deserializeTypedFromAny(jsonParser, deserializationContext);
    }

    /* access modifiers changed from: protected */
    public void _reportProblem(JsonParser jsonParser, String str) throws JsonMappingException {
        throw new JsonMappingException(str, jsonParser.getTokenLocation());
    }

    /* access modifiers changed from: protected */
    @Deprecated
    public void _handleDuplicateField(String str, ObjectNode objectNode, JsonNode jsonNode, JsonNode jsonNode2) throws JsonProcessingException {
    }

    /* access modifiers changed from: protected */
    public void _handleDuplicateField(JsonParser jsonParser, DeserializationContext deserializationContext, JsonNodeFactory jsonNodeFactory, String str, ObjectNode objectNode, JsonNode jsonNode, JsonNode jsonNode2) throws JsonProcessingException {
        if (deserializationContext.isEnabled(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)) {
            _reportProblem(jsonParser, "Duplicate field '" + str + "' for ObjectNode: not allowed when FAIL_ON_READING_DUP_TREE_KEY enabled");
        }
        _handleDuplicateField(str, objectNode, jsonNode, jsonNode2);
    }

    /* access modifiers changed from: protected */
    public final ObjectNode deserializeObject(JsonParser jsonParser, DeserializationContext deserializationContext, JsonNodeFactory jsonNodeFactory) throws IOException, JsonProcessingException {
        JsonNode textNode;
        ObjectNode objectNode = jsonNodeFactory.objectNode();
        JsonToken currentToken = jsonParser.getCurrentToken();
        if (currentToken == JsonToken.START_OBJECT) {
            currentToken = jsonParser.nextToken();
        }
        while (currentToken == JsonToken.FIELD_NAME) {
            String currentName = jsonParser.getCurrentName();
            switch (jsonParser.nextToken()) {
                case START_OBJECT:
                    textNode = deserializeObject(jsonParser, deserializationContext, jsonNodeFactory);
                    break;
                case START_ARRAY:
                    textNode = deserializeArray(jsonParser, deserializationContext, jsonNodeFactory);
                    break;
                case VALUE_STRING:
                    textNode = jsonNodeFactory.textNode(jsonParser.getText());
                    break;
                default:
                    textNode = deserializeAny(jsonParser, deserializationContext, jsonNodeFactory);
                    break;
            }
            JsonNode replace = objectNode.replace(currentName, textNode);
            if (replace != null) {
                _handleDuplicateField(jsonParser, deserializationContext, jsonNodeFactory, currentName, objectNode, replace, textNode);
            }
            currentToken = jsonParser.nextToken();
        }
        return objectNode;
    }

    /* access modifiers changed from: protected */
    public final ArrayNode deserializeArray(JsonParser jsonParser, DeserializationContext deserializationContext, JsonNodeFactory jsonNodeFactory) throws IOException, JsonProcessingException {
        ArrayNode arrayNode = jsonNodeFactory.arrayNode();
        while (true) {
            JsonToken nextToken = jsonParser.nextToken();
            if (nextToken != null) {
                switch (nextToken) {
                    case START_OBJECT:
                        arrayNode.add((JsonNode) deserializeObject(jsonParser, deserializationContext, jsonNodeFactory));
                        break;
                    case START_ARRAY:
                        arrayNode.add((JsonNode) deserializeArray(jsonParser, deserializationContext, jsonNodeFactory));
                        break;
                    case VALUE_STRING:
                        arrayNode.add((JsonNode) jsonNodeFactory.textNode(jsonParser.getText()));
                        break;
                    case END_ARRAY:
                        return arrayNode;
                    default:
                        arrayNode.add(deserializeAny(jsonParser, deserializationContext, jsonNodeFactory));
                        break;
                }
            } else {
                throw deserializationContext.mappingException((String) "Unexpected end-of-input when binding data into ArrayNode");
            }
        }
    }

    /* access modifiers changed from: protected */
    public final JsonNode deserializeAny(JsonParser jsonParser, DeserializationContext deserializationContext, JsonNodeFactory jsonNodeFactory) throws IOException, JsonProcessingException {
        switch (jsonParser.getCurrentToken()) {
            case START_OBJECT:
            case END_OBJECT:
                return deserializeObject(jsonParser, deserializationContext, jsonNodeFactory);
            case START_ARRAY:
                return deserializeArray(jsonParser, deserializationContext, jsonNodeFactory);
            case VALUE_STRING:
                return jsonNodeFactory.textNode(jsonParser.getText());
            case FIELD_NAME:
                return deserializeObject(jsonParser, deserializationContext, jsonNodeFactory);
            case VALUE_EMBEDDED_OBJECT:
                Object embeddedObject = jsonParser.getEmbeddedObject();
                if (embeddedObject == null) {
                    return jsonNodeFactory.nullNode();
                }
                if (embeddedObject.getClass() == byte[].class) {
                    return jsonNodeFactory.binaryNode((byte[]) embeddedObject);
                }
                return jsonNodeFactory.pojoNode(embeddedObject);
            case VALUE_NUMBER_INT:
                NumberType numberType = jsonParser.getNumberType();
                if (numberType == NumberType.BIG_INTEGER || deserializationContext.isEnabled(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)) {
                    return jsonNodeFactory.numberNode(jsonParser.getBigIntegerValue());
                }
                if (numberType == NumberType.INT) {
                    return jsonNodeFactory.numberNode(jsonParser.getIntValue());
                }
                return jsonNodeFactory.numberNode(jsonParser.getLongValue());
            case VALUE_NUMBER_FLOAT:
                if (jsonParser.getNumberType() == NumberType.BIG_DECIMAL || deserializationContext.isEnabled(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)) {
                    return jsonNodeFactory.numberNode(jsonParser.getDecimalValue());
                }
                return jsonNodeFactory.numberNode(jsonParser.getDoubleValue());
            case VALUE_TRUE:
                return jsonNodeFactory.booleanNode(true);
            case VALUE_FALSE:
                return jsonNodeFactory.booleanNode(false);
            case VALUE_NULL:
                return jsonNodeFactory.nullNode();
            default:
                throw deserializationContext.mappingException(handledType());
        }
    }
}