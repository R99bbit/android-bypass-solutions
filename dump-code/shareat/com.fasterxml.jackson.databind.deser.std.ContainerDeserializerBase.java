package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;

public abstract class ContainerDeserializerBase<T> extends StdDeserializer<T> {
    public abstract JsonDeserializer<Object> getContentDeserializer();

    public abstract JavaType getContentType();

    protected ContainerDeserializerBase(JavaType javaType) {
        super(javaType);
    }

    @Deprecated
    protected ContainerDeserializerBase(Class<?> cls) {
        super(cls);
    }

    public SettableBeanProperty findBackReference(String str) {
        JsonDeserializer<Object> contentDeserializer = getContentDeserializer();
        if (contentDeserializer != null) {
            return contentDeserializer.findBackReference(str);
        }
        throw new IllegalArgumentException("Can not handle managed/back reference '" + str + "': type: container deserializer of type " + getClass().getName() + " returned null for 'getContentDeserializer()'");
    }
}