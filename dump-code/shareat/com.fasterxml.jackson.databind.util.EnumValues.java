package com.fasterxml.jackson.databind.util;

import com.fasterxml.jackson.core.io.SerializedString;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import java.util.Collection;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

public final class EnumValues {
    private final Class<Enum<?>> _enumClass;
    private final EnumMap<?, SerializedString> _values;

    private EnumValues(Class<Enum<?>> cls, Map<Enum<?>, SerializedString> map) {
        this._enumClass = cls;
        this._values = new EnumMap<>(map);
    }

    public static EnumValues construct(Class<Enum<?>> cls, AnnotationIntrospector annotationIntrospector) {
        return constructFromName(cls, annotationIntrospector);
    }

    /* JADX WARNING: type inference failed for: r7v0, types: [java.lang.Class<java.lang.Enum<?>>, java.lang.Class] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public static EnumValues constructFromName(Class<Enum<?>> r7, AnnotationIntrospector annotationIntrospector) {
        Enum[] enumArr = (Enum[]) ClassUtil.findEnumType((Class<?>) r7).getEnumConstants();
        if (enumArr != null) {
            HashMap hashMap = new HashMap();
            for (Enum enumR : enumArr) {
                hashMap.put(enumR, new SerializedString(annotationIntrospector.findEnumValue(enumR)));
            }
            return new EnumValues(r7, hashMap);
        }
        throw new IllegalArgumentException("Can not determine enum constants for Class " + r7.getName());
    }

    /* JADX WARNING: type inference failed for: r7v0, types: [java.lang.Class<java.lang.Enum<?>>, java.lang.Class] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public static EnumValues constructFromToString(Class<Enum<?>> r7, AnnotationIntrospector annotationIntrospector) {
        Enum[] enumArr = (Enum[]) ClassUtil.findEnumType((Class<?>) r7).getEnumConstants();
        if (enumArr != null) {
            HashMap hashMap = new HashMap();
            for (Enum enumR : enumArr) {
                hashMap.put(enumR, new SerializedString(enumR.toString()));
            }
            return new EnumValues(r7, hashMap);
        }
        throw new IllegalArgumentException("Can not determine enum constants for Class " + r7.getName());
    }

    public SerializedString serializedValueFor(Enum<?> enumR) {
        return this._values.get(enumR);
    }

    public Collection<SerializedString> values() {
        return this._values.values();
    }

    public EnumMap<?, SerializedString> internalMap() {
        return this._values;
    }

    public Class<Enum<?>> getEnumClass() {
        return this._enumClass;
    }
}