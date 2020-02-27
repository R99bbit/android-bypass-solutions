package com.fasterxml.jackson.databind.node;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonPointer;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class ObjectNode extends ContainerNode<ObjectNode> {
    private final Map<String, JsonNode> _children = new LinkedHashMap();

    public ObjectNode(JsonNodeFactory jsonNodeFactory) {
        super(jsonNodeFactory);
    }

    /* access modifiers changed from: protected */
    public JsonNode _at(JsonPointer jsonPointer) {
        return get(jsonPointer.getMatchingProperty());
    }

    public ObjectNode deepCopy() {
        ObjectNode objectNode = new ObjectNode(this._nodeFactory);
        for (Entry next : this._children.entrySet()) {
            objectNode._children.put(next.getKey(), ((JsonNode) next.getValue()).deepCopy());
        }
        return objectNode;
    }

    public JsonNodeType getNodeType() {
        return JsonNodeType.OBJECT;
    }

    public JsonToken asToken() {
        return JsonToken.START_OBJECT;
    }

    public int size() {
        return this._children.size();
    }

    public Iterator<JsonNode> elements() {
        return this._children.values().iterator();
    }

    public JsonNode get(int i) {
        return null;
    }

    public JsonNode get(String str) {
        return this._children.get(str);
    }

    public Iterator<String> fieldNames() {
        return this._children.keySet().iterator();
    }

    public JsonNode path(int i) {
        return MissingNode.getInstance();
    }

    public JsonNode path(String str) {
        JsonNode jsonNode = this._children.get(str);
        return jsonNode != null ? jsonNode : MissingNode.getInstance();
    }

    public Iterator<Entry<String, JsonNode>> fields() {
        return this._children.entrySet().iterator();
    }

    public ObjectNode with(String str) {
        JsonNode jsonNode = this._children.get(str);
        if (jsonNode == null) {
            ObjectNode objectNode = objectNode();
            this._children.put(str, objectNode);
            return objectNode;
        } else if (jsonNode instanceof ObjectNode) {
            return (ObjectNode) jsonNode;
        } else {
            throw new UnsupportedOperationException("Property '" + str + "' has value that is not of type ObjectNode (but " + jsonNode.getClass().getName() + ")");
        }
    }

    public ArrayNode withArray(String str) {
        JsonNode jsonNode = this._children.get(str);
        if (jsonNode == null) {
            ArrayNode arrayNode = arrayNode();
            this._children.put(str, arrayNode);
            return arrayNode;
        } else if (jsonNode instanceof ArrayNode) {
            return (ArrayNode) jsonNode;
        } else {
            throw new UnsupportedOperationException("Property '" + str + "' has value that is not of type ArrayNode (but " + jsonNode.getClass().getName() + ")");
        }
    }

    public JsonNode findValue(String str) {
        for (Entry next : this._children.entrySet()) {
            if (str.equals(next.getKey())) {
                return (JsonNode) next.getValue();
            }
            JsonNode findValue = ((JsonNode) next.getValue()).findValue(str);
            if (findValue != null) {
                return findValue;
            }
        }
        return null;
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=java.util.List<com.fasterxml.jackson.databind.JsonNode>, code=java.util.List, for r6v0, types: [java.util.List, java.util.List<com.fasterxml.jackson.databind.JsonNode>] */
    public List<JsonNode> findValues(String str, List list) {
        List list2 = list;
        for (Entry next : this._children.entrySet()) {
            if (str.equals(next.getKey())) {
                if (list2 == null) {
                    list2 = new ArrayList();
                }
                list2.add(next.getValue());
            } else {
                list2 = ((JsonNode) next.getValue()).findValues(str, list2);
            }
        }
        return list2;
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=java.util.List<java.lang.String>, code=java.util.List, for r6v0, types: [java.util.List, java.util.List<java.lang.String>] */
    public List<String> findValuesAsText(String str, List list) {
        List list2 = list;
        for (Entry next : this._children.entrySet()) {
            if (str.equals(next.getKey())) {
                if (list2 == null) {
                    list2 = new ArrayList();
                }
                list2.add(((JsonNode) next.getValue()).asText());
            } else {
                list2 = ((JsonNode) next.getValue()).findValuesAsText(str, list2);
            }
        }
        return list2;
    }

    public ObjectNode findParent(String str) {
        for (Entry next : this._children.entrySet()) {
            if (str.equals(next.getKey())) {
                return this;
            }
            JsonNode findParent = ((JsonNode) next.getValue()).findParent(str);
            if (findParent != null) {
                return (ObjectNode) findParent;
            }
        }
        return null;
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=java.util.List<com.fasterxml.jackson.databind.JsonNode>, code=java.util.List, for r6v0, types: [java.util.List, java.util.List<com.fasterxml.jackson.databind.JsonNode>] */
    public List<JsonNode> findParents(String str, List list) {
        List findParents;
        List list2 = list;
        for (Entry next : this._children.entrySet()) {
            if (str.equals(next.getKey())) {
                if (list2 == null) {
                    findParents = new ArrayList();
                } else {
                    findParents = list2;
                }
                findParents.add(this);
            } else {
                findParents = ((JsonNode) next.getValue()).findParents(str, list2);
            }
            list2 = findParents;
        }
        return list2;
    }

    public void serialize(JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonProcessingException {
        jsonGenerator.writeStartObject();
        for (Entry next : this._children.entrySet()) {
            jsonGenerator.writeFieldName((String) next.getKey());
            ((BaseJsonNode) next.getValue()).serialize(jsonGenerator, serializerProvider);
        }
        jsonGenerator.writeEndObject();
    }

    public void serializeWithType(JsonGenerator jsonGenerator, SerializerProvider serializerProvider, TypeSerializer typeSerializer) throws IOException, JsonProcessingException {
        typeSerializer.writeTypePrefixForObject(this, jsonGenerator);
        for (Entry next : this._children.entrySet()) {
            jsonGenerator.writeFieldName((String) next.getKey());
            ((BaseJsonNode) next.getValue()).serialize(jsonGenerator, serializerProvider);
        }
        typeSerializer.writeTypeSuffixForObject(this, jsonGenerator);
    }

    public JsonNode set(String str, JsonNode jsonNode) {
        if (jsonNode == null) {
            jsonNode = nullNode();
        }
        this._children.put(str, jsonNode);
        return this;
    }

    public JsonNode setAll(Map<String, JsonNode> map) {
        for (Entry next : map.entrySet()) {
            Object obj = (JsonNode) next.getValue();
            if (obj == null) {
                obj = nullNode();
            }
            this._children.put(next.getKey(), obj);
        }
        return this;
    }

    public JsonNode setAll(ObjectNode objectNode) {
        this._children.putAll(objectNode._children);
        return this;
    }

    public JsonNode replace(String str, JsonNode jsonNode) {
        if (jsonNode == null) {
            jsonNode = nullNode();
        }
        return this._children.put(str, jsonNode);
    }

    public JsonNode without(String str) {
        this._children.remove(str);
        return this;
    }

    public ObjectNode without(Collection<String> collection) {
        this._children.keySet().removeAll(collection);
        return this;
    }

    public JsonNode put(String str, JsonNode jsonNode) {
        if (jsonNode == null) {
            jsonNode = nullNode();
        }
        return this._children.put(str, jsonNode);
    }

    public JsonNode remove(String str) {
        return this._children.remove(str);
    }

    public ObjectNode remove(Collection<String> collection) {
        this._children.keySet().removeAll(collection);
        return this;
    }

    public ObjectNode removeAll() {
        this._children.clear();
        return this;
    }

    public JsonNode putAll(Map<String, JsonNode> map) {
        return setAll(map);
    }

    public JsonNode putAll(ObjectNode objectNode) {
        return setAll(objectNode);
    }

    public ObjectNode retain(Collection<String> collection) {
        this._children.keySet().retainAll(collection);
        return this;
    }

    public ObjectNode retain(String... strArr) {
        return retain((Collection<String>) Arrays.asList(strArr));
    }

    public ArrayNode putArray(String str) {
        ArrayNode arrayNode = arrayNode();
        _put(str, arrayNode);
        return arrayNode;
    }

    public ObjectNode putObject(String str) {
        ObjectNode objectNode = objectNode();
        _put(str, objectNode);
        return objectNode;
    }

    public ObjectNode putPOJO(String str, Object obj) {
        return _put(str, pojoNode(obj));
    }

    public ObjectNode putNull(String str) {
        this._children.put(str, nullNode());
        return this;
    }

    public ObjectNode put(String str, short s) {
        return _put(str, numberNode(s));
    }

    public ObjectNode put(String str, Short sh) {
        return _put(str, sh == null ? nullNode() : numberNode(sh.shortValue()));
    }

    public ObjectNode put(String str, int i) {
        return _put(str, numberNode(i));
    }

    public ObjectNode put(String str, Integer num) {
        return _put(str, num == null ? nullNode() : numberNode(num.intValue()));
    }

    public ObjectNode put(String str, long j) {
        return _put(str, numberNode(j));
    }

    public ObjectNode put(String str, Long l) {
        return _put(str, l == null ? nullNode() : numberNode(l.longValue()));
    }

    public ObjectNode put(String str, float f) {
        return _put(str, numberNode(f));
    }

    public ObjectNode put(String str, Float f) {
        return _put(str, f == null ? nullNode() : numberNode(f.floatValue()));
    }

    public ObjectNode put(String str, double d) {
        return _put(str, numberNode(d));
    }

    public ObjectNode put(String str, Double d) {
        return _put(str, d == null ? nullNode() : numberNode(d.doubleValue()));
    }

    public ObjectNode put(String str, BigDecimal bigDecimal) {
        return _put(str, bigDecimal == null ? nullNode() : numberNode(bigDecimal));
    }

    public ObjectNode put(String str, String str2) {
        return _put(str, str2 == null ? nullNode() : textNode(str2));
    }

    public ObjectNode put(String str, boolean z) {
        return _put(str, booleanNode(z));
    }

    public ObjectNode put(String str, Boolean bool) {
        return _put(str, bool == null ? nullNode() : booleanNode(bool.booleanValue()));
    }

    public ObjectNode put(String str, byte[] bArr) {
        return _put(str, bArr == null ? nullNode() : binaryNode(bArr));
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || !(obj instanceof ObjectNode)) {
            return false;
        }
        return _childrenEqual((ObjectNode) obj);
    }

    /* access modifiers changed from: protected */
    public boolean _childrenEqual(ObjectNode objectNode) {
        return this._children.equals(objectNode._children);
    }

    public int hashCode() {
        return this._children.hashCode();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder((size() << 4) + 32);
        sb.append("{");
        int i = 0;
        for (Entry next : this._children.entrySet()) {
            if (i > 0) {
                sb.append(",");
            }
            TextNode.appendQuoted(sb, (String) next.getKey());
            sb.append(':');
            sb.append(((JsonNode) next.getValue()).toString());
            i++;
        }
        sb.append("}");
        return sb.toString();
    }

    /* access modifiers changed from: protected */
    public ObjectNode _put(String str, JsonNode jsonNode) {
        this._children.put(str, jsonNode);
        return this;
    }
}