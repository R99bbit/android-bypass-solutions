package com.igaworks.gson.internal.bind;

import com.igaworks.gson.Gson;
import com.igaworks.gson.TypeAdapter;
import com.igaworks.gson.TypeAdapterFactory;
import com.igaworks.gson.internal.LinkedTreeMap;
import com.igaworks.gson.reflect.TypeToken;
import com.igaworks.gson.stream.JsonReader;
import com.igaworks.gson.stream.JsonToken;
import com.igaworks.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class ObjectTypeAdapter extends TypeAdapter<Object> {
    private static /* synthetic */ int[] $SWITCH_TABLE$com$igaworks$gson$stream$JsonToken;
    public static final TypeAdapterFactory FACTORY = new TypeAdapterFactory() {
        public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
            if (type.getRawType() == Object.class) {
                return new ObjectTypeAdapter(gson, null);
            }
            return null;
        }
    };
    private final Gson gson;

    static /* synthetic */ int[] $SWITCH_TABLE$com$igaworks$gson$stream$JsonToken() {
        int[] iArr = $SWITCH_TABLE$com$igaworks$gson$stream$JsonToken;
        if (iArr == null) {
            iArr = new int[JsonToken.values().length];
            try {
                iArr[JsonToken.BEGIN_ARRAY.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                iArr[JsonToken.BEGIN_OBJECT.ordinal()] = 3;
            } catch (NoSuchFieldError e2) {
            }
            try {
                iArr[JsonToken.BOOLEAN.ordinal()] = 8;
            } catch (NoSuchFieldError e3) {
            }
            try {
                iArr[JsonToken.END_ARRAY.ordinal()] = 2;
            } catch (NoSuchFieldError e4) {
            }
            try {
                iArr[JsonToken.END_DOCUMENT.ordinal()] = 10;
            } catch (NoSuchFieldError e5) {
            }
            try {
                iArr[JsonToken.END_OBJECT.ordinal()] = 4;
            } catch (NoSuchFieldError e6) {
            }
            try {
                iArr[JsonToken.NAME.ordinal()] = 5;
            } catch (NoSuchFieldError e7) {
            }
            try {
                iArr[JsonToken.NULL.ordinal()] = 9;
            } catch (NoSuchFieldError e8) {
            }
            try {
                iArr[JsonToken.NUMBER.ordinal()] = 7;
            } catch (NoSuchFieldError e9) {
            }
            try {
                iArr[JsonToken.STRING.ordinal()] = 6;
            } catch (NoSuchFieldError e10) {
            }
            $SWITCH_TABLE$com$igaworks$gson$stream$JsonToken = iArr;
        }
        return iArr;
    }

    private ObjectTypeAdapter(Gson gson2) {
        this.gson = gson2;
    }

    /* synthetic */ ObjectTypeAdapter(Gson gson2, ObjectTypeAdapter objectTypeAdapter) {
        this(gson2);
    }

    public Object read(JsonReader in) throws IOException {
        switch ($SWITCH_TABLE$com$igaworks$gson$stream$JsonToken()[in.peek().ordinal()]) {
            case 1:
                List<Object> list = new ArrayList<>();
                in.beginArray();
                while (in.hasNext()) {
                    list.add(read(in));
                }
                in.endArray();
                return list;
            case 3:
                LinkedTreeMap linkedTreeMap = new LinkedTreeMap();
                in.beginObject();
                while (in.hasNext()) {
                    linkedTreeMap.put(in.nextName(), read(in));
                }
                in.endObject();
                return linkedTreeMap;
            case 6:
                return in.nextString();
            case 7:
                return Double.valueOf(in.nextDouble());
            case 8:
                return Boolean.valueOf(in.nextBoolean());
            case 9:
                in.nextNull();
                return null;
            default:
                throw new IllegalStateException();
        }
    }

    public void write(JsonWriter out, Object value) throws IOException {
        if (value == null) {
            out.nullValue();
            return;
        }
        TypeAdapter<Object> typeAdapter = this.gson.getAdapter(value.getClass());
        if (typeAdapter instanceof ObjectTypeAdapter) {
            out.beginObject();
            out.endObject();
            return;
        }
        typeAdapter.write(out, value);
    }
}