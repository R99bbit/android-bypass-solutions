package com.nuvent.shareat.model;

import com.google.gson.GsonBuilder;

public class JsonConvertable {
    public String toJson() {
        return new GsonBuilder().setPrettyPrinting().create().toJson((Object) this);
    }

    public JsonConvertable fromJson(String str) {
        if (str == null || str.length() == 0) {
            return this;
        }
        return (JsonConvertable) new GsonBuilder().setPrettyPrinting().create().fromJson(str, getClass());
    }

    public JsonConvertable getClone() {
        return fromJson(toJson());
    }
}