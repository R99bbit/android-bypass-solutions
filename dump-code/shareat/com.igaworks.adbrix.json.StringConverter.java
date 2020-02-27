package com.igaworks.adbrix.json;

import com.igaworks.gson.JsonDeserializationContext;
import com.igaworks.gson.JsonDeserializer;
import com.igaworks.gson.JsonElement;
import com.igaworks.gson.JsonParseException;
import com.igaworks.gson.JsonPrimitive;
import com.igaworks.gson.JsonSerializationContext;
import com.igaworks.gson.JsonSerializer;
import java.lang.reflect.Type;

public class StringConverter implements JsonSerializer<String>, JsonDeserializer<String> {
    public JsonElement serialize(String src, Type typeOfSrc, JsonSerializationContext context) {
        if (src == null) {
            return new JsonPrimitive((String) "");
        }
        return new JsonPrimitive(src.toString());
    }

    public String deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        if (json.isJsonNull()) {
            return null;
        }
        if (json.getAsString() == null || json.getAsString().length() != 0) {
            return json.getAsJsonPrimitive().getAsString();
        }
        return "";
    }
}