package com.igaworks.gson.internal.bind;

import com.igaworks.gson.Gson;
import com.igaworks.gson.JsonElement;
import com.igaworks.gson.JsonPrimitive;
import com.igaworks.gson.JsonSyntaxException;
import com.igaworks.gson.TypeAdapter;
import com.igaworks.gson.TypeAdapterFactory;
import com.igaworks.gson.internal.C$Gson$Types;
import com.igaworks.gson.internal.ConstructorConstructor;
import com.igaworks.gson.internal.JsonReaderInternalAccess;
import com.igaworks.gson.internal.ObjectConstructor;
import com.igaworks.gson.internal.Streams;
import com.igaworks.gson.reflect.TypeToken;
import com.igaworks.gson.stream.JsonReader;
import com.igaworks.gson.stream.JsonToken;
import com.igaworks.gson.stream.JsonWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public final class MapTypeAdapterFactory implements TypeAdapterFactory {
    /* access modifiers changed from: private */
    public final boolean complexMapKeySerialization;
    private final ConstructorConstructor constructorConstructor;

    private final class Adapter<K, V> extends TypeAdapter<Map<K, V>> {
        private final ObjectConstructor<? extends Map<K, V>> constructor;
        private final TypeAdapter<K> keyTypeAdapter;
        private final TypeAdapter<V> valueTypeAdapter;

        public Adapter(Gson context, Type keyType, TypeAdapter<K> keyTypeAdapter2, Type valueType, TypeAdapter<V> valueTypeAdapter2, ObjectConstructor<? extends Map<K, V>> constructor2) {
            this.keyTypeAdapter = new TypeAdapterRuntimeTypeWrapper(context, keyTypeAdapter2, keyType);
            this.valueTypeAdapter = new TypeAdapterRuntimeTypeWrapper(context, valueTypeAdapter2, valueType);
            this.constructor = constructor2;
        }

        public Map<K, V> read(JsonReader in) throws IOException {
            JsonToken peek = in.peek();
            if (peek == JsonToken.NULL) {
                in.nextNull();
                return null;
            }
            Map<K, V> map = (Map) this.constructor.construct();
            if (peek == JsonToken.BEGIN_ARRAY) {
                in.beginArray();
                while (in.hasNext()) {
                    in.beginArray();
                    K key = this.keyTypeAdapter.read(in);
                    if (map.put(key, this.valueTypeAdapter.read(in)) != null) {
                        throw new JsonSyntaxException("duplicate key: " + key);
                    }
                    in.endArray();
                }
                in.endArray();
                return map;
            }
            in.beginObject();
            while (in.hasNext()) {
                JsonReaderInternalAccess.INSTANCE.promoteNameToValue(in);
                K key2 = this.keyTypeAdapter.read(in);
                if (map.put(key2, this.valueTypeAdapter.read(in)) != null) {
                    throw new JsonSyntaxException("duplicate key: " + key2);
                }
            }
            in.endObject();
            return map;
        }

        public void write(JsonWriter out, Map<K, V> map) throws IOException {
            if (map == null) {
                out.nullValue();
            } else if (!MapTypeAdapterFactory.this.complexMapKeySerialization) {
                out.beginObject();
                for (Entry<K, V> entry : map.entrySet()) {
                    out.name(String.valueOf(entry.getKey()));
                    this.valueTypeAdapter.write(out, entry.getValue());
                }
                out.endObject();
            } else {
                boolean hasComplexKeys = false;
                List<JsonElement> keys = new ArrayList<>(map.size());
                List<V> values = new ArrayList<>(map.size());
                for (Entry<K, V> entry2 : map.entrySet()) {
                    JsonElement keyElement = this.keyTypeAdapter.toJsonTree(entry2.getKey());
                    keys.add(keyElement);
                    values.add(entry2.getValue());
                    hasComplexKeys |= keyElement.isJsonArray() || keyElement.isJsonObject();
                }
                if (hasComplexKeys) {
                    out.beginArray();
                    for (int i = 0; i < keys.size(); i++) {
                        out.beginArray();
                        Streams.write(keys.get(i), out);
                        this.valueTypeAdapter.write(out, values.get(i));
                        out.endArray();
                    }
                    out.endArray();
                    return;
                }
                out.beginObject();
                for (int i2 = 0; i2 < keys.size(); i2++) {
                    out.name(keyToString(keys.get(i2)));
                    this.valueTypeAdapter.write(out, values.get(i2));
                }
                out.endObject();
            }
        }

        private String keyToString(JsonElement keyElement) {
            if (keyElement.isJsonPrimitive()) {
                JsonPrimitive primitive = keyElement.getAsJsonPrimitive();
                if (primitive.isNumber()) {
                    return String.valueOf(primitive.getAsNumber());
                }
                if (primitive.isBoolean()) {
                    return Boolean.toString(primitive.getAsBoolean());
                }
                if (primitive.isString()) {
                    return primitive.getAsString();
                }
                throw new AssertionError();
            } else if (keyElement.isJsonNull()) {
                return "null";
            } else {
                throw new AssertionError();
            }
        }
    }

    public MapTypeAdapterFactory(ConstructorConstructor constructorConstructor2, boolean complexMapKeySerialization2) {
        this.constructorConstructor = constructorConstructor2;
        this.complexMapKeySerialization = complexMapKeySerialization2;
    }

    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> typeToken) {
        Type type = typeToken.getType();
        if (!Map.class.isAssignableFrom(typeToken.getRawType())) {
            return null;
        }
        Type[] keyAndValueTypes = C$Gson$Types.getMapKeyAndValueTypes(type, C$Gson$Types.getRawType(type));
        return new Adapter(gson, keyAndValueTypes[0], getKeyAdapter(gson, keyAndValueTypes[0]), keyAndValueTypes[1], gson.getAdapter(TypeToken.get(keyAndValueTypes[1])), this.constructorConstructor.get(typeToken));
    }

    private TypeAdapter<?> getKeyAdapter(Gson context, Type keyType) {
        if (keyType == Boolean.TYPE || keyType == Boolean.class) {
            return TypeAdapters.BOOLEAN_AS_STRING;
        }
        return context.getAdapter(TypeToken.get(keyType));
    }
}