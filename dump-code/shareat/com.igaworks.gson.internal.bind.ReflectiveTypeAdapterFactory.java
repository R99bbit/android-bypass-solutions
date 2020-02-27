package com.igaworks.gson.internal.bind;

import com.igaworks.gson.FieldNamingStrategy;
import com.igaworks.gson.Gson;
import com.igaworks.gson.JsonSyntaxException;
import com.igaworks.gson.TypeAdapter;
import com.igaworks.gson.TypeAdapterFactory;
import com.igaworks.gson.annotations.SerializedName;
import com.igaworks.gson.internal.C$Gson$Types;
import com.igaworks.gson.internal.ConstructorConstructor;
import com.igaworks.gson.internal.Excluder;
import com.igaworks.gson.internal.ObjectConstructor;
import com.igaworks.gson.internal.Primitives;
import com.igaworks.gson.reflect.TypeToken;
import com.igaworks.gson.stream.JsonReader;
import com.igaworks.gson.stream.JsonToken;
import com.igaworks.gson.stream.JsonWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ReflectiveTypeAdapterFactory implements TypeAdapterFactory {
    private final ConstructorConstructor constructorConstructor;
    private final Excluder excluder;
    private final FieldNamingStrategy fieldNamingPolicy;

    public static final class Adapter<T> extends TypeAdapter<T> {
        private final Map<String, BoundField> boundFields;
        private final ObjectConstructor<T> constructor;

        private Adapter(ObjectConstructor<T> constructor2, Map<String, BoundField> boundFields2) {
            this.constructor = constructor2;
            this.boundFields = boundFields2;
        }

        /* synthetic */ Adapter(ObjectConstructor objectConstructor, Map map, Adapter adapter) {
            this(objectConstructor, map);
        }

        public T read(JsonReader in) throws IOException {
            if (in.peek() == JsonToken.NULL) {
                in.nextNull();
                return null;
            }
            T instance = this.constructor.construct();
            try {
                in.beginObject();
                while (in.hasNext()) {
                    BoundField field = this.boundFields.get(in.nextName());
                    if (field == null || !field.deserialized) {
                        in.skipValue();
                    } else {
                        field.read(in, instance);
                    }
                }
                in.endObject();
                return instance;
            } catch (IllegalStateException e) {
                throw new JsonSyntaxException((Throwable) e);
            } catch (IllegalAccessException e2) {
                throw new AssertionError(e2);
            }
        }

        public void write(JsonWriter out, T value) throws IOException {
            if (value == null) {
                out.nullValue();
                return;
            }
            out.beginObject();
            try {
                for (BoundField boundField : this.boundFields.values()) {
                    if (boundField.serialized) {
                        out.name(boundField.name);
                        boundField.write(out, value);
                    }
                }
                out.endObject();
            } catch (IllegalAccessException e) {
                throw new AssertionError();
            }
        }
    }

    static abstract class BoundField {
        final boolean deserialized;
        final String name;
        final boolean serialized;

        /* access modifiers changed from: 0000 */
        public abstract void read(JsonReader jsonReader, Object obj) throws IOException, IllegalAccessException;

        /* access modifiers changed from: 0000 */
        public abstract void write(JsonWriter jsonWriter, Object obj) throws IOException, IllegalAccessException;

        protected BoundField(String name2, boolean serialized2, boolean deserialized2) {
            this.name = name2;
            this.serialized = serialized2;
            this.deserialized = deserialized2;
        }
    }

    public ReflectiveTypeAdapterFactory(ConstructorConstructor constructorConstructor2, FieldNamingStrategy fieldNamingPolicy2, Excluder excluder2) {
        this.constructorConstructor = constructorConstructor2;
        this.fieldNamingPolicy = fieldNamingPolicy2;
        this.excluder = excluder2;
    }

    public boolean excludeField(Field f, boolean serialize) {
        return !this.excluder.excludeClass(f.getType(), serialize) && !this.excluder.excludeField(f, serialize);
    }

    private String getFieldName(Field f) {
        SerializedName serializedName = (SerializedName) f.getAnnotation(SerializedName.class);
        return serializedName == null ? this.fieldNamingPolicy.translateName(f) : serializedName.value();
    }

    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
        Class rawType = type.getRawType();
        if (!Object.class.isAssignableFrom(rawType)) {
            return null;
        }
        return new Adapter(this.constructorConstructor.get(type), getBoundFields(gson, type, rawType), null);
    }

    private BoundField createBoundField(Gson context, Field field, String name, TypeToken<?> fieldType, boolean serialize, boolean deserialize) {
        return new BoundField(name, serialize, deserialize, context, fieldType, field, Primitives.isPrimitive(fieldType.getRawType())) {
            final TypeAdapter<?> typeAdapter;
            private final /* synthetic */ Gson val$context;
            private final /* synthetic */ Field val$field;
            private final /* synthetic */ TypeToken val$fieldType;
            private final /* synthetic */ boolean val$isPrimitive;

            {
                this.val$context = r6;
                this.val$fieldType = r7;
                this.val$field = r8;
                this.val$isPrimitive = r9;
                this.typeAdapter = r6.getAdapter(r7);
            }

            /* access modifiers changed from: 0000 */
            public void write(JsonWriter writer, Object value) throws IOException, IllegalAccessException {
                new TypeAdapterRuntimeTypeWrapper(this.val$context, this.typeAdapter, this.val$fieldType.getType()).write(writer, this.val$field.get(value));
            }

            /* access modifiers changed from: 0000 */
            public void read(JsonReader reader, Object value) throws IOException, IllegalAccessException {
                Object fieldValue = this.typeAdapter.read(reader);
                if (fieldValue != null || !this.val$isPrimitive) {
                    this.val$field.set(value, fieldValue);
                }
            }
        };
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=java.lang.Class<?>, code=java.lang.Class, for r19v0, types: [java.lang.Class<?>, java.lang.Class] */
    private Map<String, BoundField> getBoundFields(Gson context, TypeToken<?> type, Class raw) {
        Field[] fields;
        Map<String, BoundField> result = new LinkedHashMap<>();
        if (!raw.isInterface()) {
            Type declaredType = type.getType();
            while (raw != Object.class) {
                for (Field field : raw.getDeclaredFields()) {
                    boolean serialize = excludeField(field, true);
                    boolean deserialize = excludeField(field, false);
                    if (serialize || deserialize) {
                        field.setAccessible(true);
                        BoundField boundField = createBoundField(context, field, getFieldName(field), TypeToken.get(C$Gson$Types.resolve(type.getType(), raw, field.getGenericType())), serialize, deserialize);
                        BoundField previous = result.put(boundField.name, boundField);
                        if (previous != null) {
                            throw new IllegalArgumentException(declaredType + " declares multiple JSON fields named " + previous.name);
                        }
                    }
                }
                type = TypeToken.get(C$Gson$Types.resolve(type.getType(), raw, raw.getGenericSuperclass()));
                raw = type.getRawType();
            }
        }
        return result;
    }
}