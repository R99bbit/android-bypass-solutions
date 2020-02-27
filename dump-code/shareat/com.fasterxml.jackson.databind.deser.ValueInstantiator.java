package com.fasterxml.jackson.databind.deser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.introspect.AnnotatedParameter;
import com.fasterxml.jackson.databind.introspect.AnnotatedWithParams;
import java.io.IOException;

public abstract class ValueInstantiator {
    public abstract String getValueTypeDesc();

    public boolean canInstantiate() {
        return canCreateUsingDefault() || canCreateUsingDelegate() || canCreateFromObjectWith() || canCreateFromString() || canCreateFromInt() || canCreateFromLong() || canCreateFromDouble() || canCreateFromBoolean();
    }

    public boolean canCreateFromString() {
        return false;
    }

    public boolean canCreateFromInt() {
        return false;
    }

    public boolean canCreateFromLong() {
        return false;
    }

    public boolean canCreateFromDouble() {
        return false;
    }

    public boolean canCreateFromBoolean() {
        return false;
    }

    public boolean canCreateUsingDefault() {
        return getDefaultCreator() != null;
    }

    public boolean canCreateUsingDelegate() {
        return false;
    }

    public boolean canCreateFromObjectWith() {
        return false;
    }

    public SettableBeanProperty[] getFromObjectArguments(DeserializationConfig deserializationConfig) {
        return null;
    }

    public JavaType getDelegateType(DeserializationConfig deserializationConfig) {
        return null;
    }

    public Object createUsingDefault(DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        throw new JsonMappingException("Can not instantiate value of type " + getValueTypeDesc() + "; no default creator found");
    }

    public Object createFromObjectWith(DeserializationContext deserializationContext, Object[] objArr) throws IOException, JsonProcessingException {
        throw new JsonMappingException("Can not instantiate value of type " + getValueTypeDesc() + " with arguments");
    }

    public Object createUsingDelegate(DeserializationContext deserializationContext, Object obj) throws IOException, JsonProcessingException {
        throw new JsonMappingException("Can not instantiate value of type " + getValueTypeDesc() + " using delegate");
    }

    public Object createFromString(DeserializationContext deserializationContext, String str) throws IOException, JsonProcessingException {
        throw new JsonMappingException("Can not instantiate value of type " + getValueTypeDesc() + " from String value");
    }

    public Object createFromInt(DeserializationContext deserializationContext, int i) throws IOException, JsonProcessingException {
        throw new JsonMappingException("Can not instantiate value of type " + getValueTypeDesc() + " from Integer number (int)");
    }

    public Object createFromLong(DeserializationContext deserializationContext, long j) throws IOException, JsonProcessingException {
        throw new JsonMappingException("Can not instantiate value of type " + getValueTypeDesc() + " from Integer number (long)");
    }

    public Object createFromDouble(DeserializationContext deserializationContext, double d) throws IOException, JsonProcessingException {
        throw new JsonMappingException("Can not instantiate value of type " + getValueTypeDesc() + " from Floating-point number (double)");
    }

    public Object createFromBoolean(DeserializationContext deserializationContext, boolean z) throws IOException, JsonProcessingException {
        throw new JsonMappingException("Can not instantiate value of type " + getValueTypeDesc() + " from Boolean value");
    }

    public AnnotatedWithParams getDefaultCreator() {
        return null;
    }

    public AnnotatedWithParams getDelegateCreator() {
        return null;
    }

    public AnnotatedWithParams getWithArgsCreator() {
        return null;
    }

    public AnnotatedParameter getIncompleteParameter() {
        return null;
    }
}