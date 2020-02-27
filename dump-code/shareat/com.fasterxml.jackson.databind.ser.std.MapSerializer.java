package com.fasterxml.jackson.databind.ser.std;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JacksonStdImpl;
import com.fasterxml.jackson.databind.introspect.Annotated;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonFormatVisitorWrapper;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonMapFormatVisitor;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.ser.ContainerSerializer;
import com.fasterxml.jackson.databind.ser.ContextualSerializer;
import com.fasterxml.jackson.databind.ser.PropertyFilter;
import com.fasterxml.jackson.databind.ser.impl.PropertySerializerMap;
import com.fasterxml.jackson.databind.ser.impl.PropertySerializerMap.SerializerAndMapResult;
import com.fasterxml.jackson.databind.type.TypeFactory;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;

@JacksonStdImpl
public class MapSerializer extends ContainerSerializer<Map<?, ?>> implements ContextualSerializer {
    protected static final JavaType UNSPECIFIED_TYPE = TypeFactory.unknownType();
    protected PropertySerializerMap _dynamicValueSerializers;
    protected final Object _filterId;
    protected final HashSet<String> _ignoredEntries;
    protected JsonSerializer<Object> _keySerializer;
    protected final JavaType _keyType;
    protected final BeanProperty _property;
    protected JsonSerializer<Object> _valueSerializer;
    protected final JavaType _valueType;
    protected final boolean _valueTypeIsStatic;
    protected final TypeSerializer _valueTypeSerializer;

    protected MapSerializer(HashSet<String> hashSet, JavaType javaType, JavaType javaType2, boolean z, TypeSerializer typeSerializer, JsonSerializer<?> jsonSerializer, JsonSerializer<?> jsonSerializer2) {
        super(Map.class, false);
        this._ignoredEntries = hashSet;
        this._keyType = javaType;
        this._valueType = javaType2;
        this._valueTypeIsStatic = z;
        this._valueTypeSerializer = typeSerializer;
        this._keySerializer = jsonSerializer;
        this._valueSerializer = jsonSerializer2;
        this._dynamicValueSerializers = PropertySerializerMap.emptyMap();
        this._property = null;
        this._filterId = null;
    }

    protected MapSerializer(MapSerializer mapSerializer, BeanProperty beanProperty, JsonSerializer<?> jsonSerializer, JsonSerializer<?> jsonSerializer2, HashSet<String> hashSet) {
        super(Map.class, false);
        this._ignoredEntries = hashSet;
        this._keyType = mapSerializer._keyType;
        this._valueType = mapSerializer._valueType;
        this._valueTypeIsStatic = mapSerializer._valueTypeIsStatic;
        this._valueTypeSerializer = mapSerializer._valueTypeSerializer;
        this._keySerializer = jsonSerializer;
        this._valueSerializer = jsonSerializer2;
        this._dynamicValueSerializers = mapSerializer._dynamicValueSerializers;
        this._property = beanProperty;
        this._filterId = mapSerializer._filterId;
    }

    protected MapSerializer(MapSerializer mapSerializer, TypeSerializer typeSerializer) {
        super(Map.class, false);
        this._ignoredEntries = mapSerializer._ignoredEntries;
        this._keyType = mapSerializer._keyType;
        this._valueType = mapSerializer._valueType;
        this._valueTypeIsStatic = mapSerializer._valueTypeIsStatic;
        this._valueTypeSerializer = typeSerializer;
        this._keySerializer = mapSerializer._keySerializer;
        this._valueSerializer = mapSerializer._valueSerializer;
        this._dynamicValueSerializers = mapSerializer._dynamicValueSerializers;
        this._property = mapSerializer._property;
        this._filterId = mapSerializer._filterId;
    }

    protected MapSerializer(MapSerializer mapSerializer, Object obj) {
        super(Map.class, false);
        this._ignoredEntries = mapSerializer._ignoredEntries;
        this._keyType = mapSerializer._keyType;
        this._valueType = mapSerializer._valueType;
        this._valueTypeIsStatic = mapSerializer._valueTypeIsStatic;
        this._valueTypeSerializer = mapSerializer._valueTypeSerializer;
        this._keySerializer = mapSerializer._keySerializer;
        this._valueSerializer = mapSerializer._valueSerializer;
        this._dynamicValueSerializers = mapSerializer._dynamicValueSerializers;
        this._property = mapSerializer._property;
        this._filterId = obj;
    }

    public MapSerializer _withValueTypeSerializer(TypeSerializer typeSerializer) {
        return new MapSerializer(this, typeSerializer);
    }

    public MapSerializer withResolved(BeanProperty beanProperty, JsonSerializer<?> jsonSerializer, JsonSerializer<?> jsonSerializer2, HashSet<String> hashSet) {
        return new MapSerializer(this, beanProperty, jsonSerializer, jsonSerializer2, hashSet);
    }

    public MapSerializer withFilterId(Object obj) {
        return this._filterId == obj ? this : new MapSerializer(this, obj);
    }

    @Deprecated
    public static MapSerializer construct(String[] strArr, JavaType javaType, boolean z, TypeSerializer typeSerializer, JsonSerializer<Object> jsonSerializer, JsonSerializer<Object> jsonSerializer2) {
        return construct(strArr, javaType, z, typeSerializer, jsonSerializer, jsonSerializer2, null);
    }

    public static MapSerializer construct(String[] strArr, JavaType javaType, boolean z, TypeSerializer typeSerializer, JsonSerializer<Object> jsonSerializer, JsonSerializer<Object> jsonSerializer2, Object obj) {
        JavaType keyType;
        JavaType contentType;
        boolean z2;
        boolean z3 = false;
        HashSet<String> set = toSet(strArr);
        if (javaType == null) {
            contentType = UNSPECIFIED_TYPE;
            keyType = contentType;
        } else {
            keyType = javaType.getKeyType();
            contentType = javaType.getContentType();
        }
        if (!z) {
            if (contentType != null && contentType.isFinal()) {
                z3 = true;
            }
            z2 = z3;
        } else if (contentType.getRawClass() == Object.class) {
            z2 = false;
        } else {
            z2 = z;
        }
        MapSerializer mapSerializer = new MapSerializer(set, keyType, contentType, z2, typeSerializer, jsonSerializer, jsonSerializer2);
        if (obj != null) {
            return mapSerializer.withFilterId(obj);
        }
        return mapSerializer;
    }

    private static HashSet<String> toSet(String[] strArr) {
        if (strArr == null || strArr.length == 0) {
            return null;
        }
        HashSet<String> hashSet = new HashSet<>(strArr.length);
        for (String add : strArr) {
            hashSet.add(add);
        }
        return hashSet;
    }

    /* JADX WARNING: Removed duplicated region for block: B:11:0x0026  */
    /* JADX WARNING: Removed duplicated region for block: B:14:0x002e  */
    /* JADX WARNING: Removed duplicated region for block: B:22:0x004b  */
    /* JADX WARNING: Removed duplicated region for block: B:24:0x004f  */
    /* JADX WARNING: Removed duplicated region for block: B:30:0x0069  */
    /* JADX WARNING: Removed duplicated region for block: B:35:0x007c  */
    /* JADX WARNING: Removed duplicated region for block: B:36:0x0082  */
    /* JADX WARNING: Removed duplicated region for block: B:41:0x0094  */
    /* JADX WARNING: Removed duplicated region for block: B:44:0x00a3  */
    /* JADX WARNING: Removed duplicated region for block: B:51:? A[RETURN, SYNTHETIC] */
    public JsonSerializer<?> createContextual(SerializerProvider serializerProvider, BeanProperty beanProperty) throws JsonMappingException {
        JsonSerializer<Object> jsonSerializer;
        JsonSerializer findConvertingContentSerializer;
        JsonSerializer handleSecondaryContextualization;
        JsonSerializer<Object> jsonSerializer2;
        JsonSerializer handleSecondaryContextualization2;
        AnnotationIntrospector annotationIntrospector;
        HashSet<String> hashSet;
        String[] findPropertiesToIgnore;
        JsonSerializer<Object> jsonSerializer3;
        JsonSerializer<Object> jsonSerializer4 = null;
        if (beanProperty != null) {
            AnnotatedMember member = beanProperty.getMember();
            if (member != null) {
                AnnotationIntrospector annotationIntrospector2 = serializerProvider.getAnnotationIntrospector();
                Object findKeySerializer = annotationIntrospector2.findKeySerializer(member);
                if (findKeySerializer != null) {
                    jsonSerializer3 = serializerProvider.serializerInstance(member, findKeySerializer);
                } else {
                    jsonSerializer3 = null;
                }
                Object findContentSerializer = annotationIntrospector2.findContentSerializer(member);
                if (findContentSerializer != null) {
                    JsonSerializer<Object> jsonSerializer5 = jsonSerializer3;
                    jsonSerializer = serializerProvider.serializerInstance(member, findContentSerializer);
                    jsonSerializer4 = jsonSerializer5;
                } else {
                    JsonSerializer<Object> jsonSerializer6 = jsonSerializer3;
                    jsonSerializer = null;
                    jsonSerializer4 = jsonSerializer6;
                }
                if (jsonSerializer == null) {
                    jsonSerializer = this._valueSerializer;
                }
                findConvertingContentSerializer = findConvertingContentSerializer(serializerProvider, beanProperty, jsonSerializer);
                if (findConvertingContentSerializer == null) {
                    handleSecondaryContextualization = serializerProvider.handleSecondaryContextualization(findConvertingContentSerializer, beanProperty);
                } else if ((!this._valueTypeIsStatic || this._valueType.getRawClass() == Object.class) && !hasContentTypeAnnotation(serializerProvider, beanProperty)) {
                    handleSecondaryContextualization = findConvertingContentSerializer;
                } else {
                    handleSecondaryContextualization = serializerProvider.findValueSerializer(this._valueType, beanProperty);
                }
                if (jsonSerializer4 != null) {
                    jsonSerializer2 = this._keySerializer;
                } else {
                    jsonSerializer2 = jsonSerializer4;
                }
                if (jsonSerializer2 != null) {
                    handleSecondaryContextualization2 = serializerProvider.findKeySerializer(this._keyType, beanProperty);
                } else {
                    handleSecondaryContextualization2 = serializerProvider.handleSecondaryContextualization(jsonSerializer2, beanProperty);
                }
                HashSet<String> hashSet2 = this._ignoredEntries;
                annotationIntrospector = serializerProvider.getAnnotationIntrospector();
                if (!(annotationIntrospector == null || beanProperty == null)) {
                    findPropertiesToIgnore = annotationIntrospector.findPropertiesToIgnore(beanProperty.getMember());
                    if (findPropertiesToIgnore != null) {
                        hashSet = hashSet2 == null ? new HashSet<>() : new HashSet<>(hashSet2);
                        for (String add : findPropertiesToIgnore) {
                            hashSet.add(add);
                        }
                        MapSerializer withResolved = withResolved(beanProperty, handleSecondaryContextualization2, handleSecondaryContextualization, hashSet);
                        if (beanProperty == null) {
                            return withResolved;
                        }
                        Object findFilterId = annotationIntrospector.findFilterId((Annotated) beanProperty.getMember());
                        if (findFilterId != null) {
                            return withResolved.withFilterId(findFilterId);
                        }
                        return withResolved;
                    }
                }
                hashSet = hashSet2;
                MapSerializer withResolved2 = withResolved(beanProperty, handleSecondaryContextualization2, handleSecondaryContextualization, hashSet);
                if (beanProperty == null) {
                }
            }
        }
        jsonSerializer = null;
        if (jsonSerializer == null) {
        }
        findConvertingContentSerializer = findConvertingContentSerializer(serializerProvider, beanProperty, jsonSerializer);
        if (findConvertingContentSerializer == null) {
        }
        if (jsonSerializer4 != null) {
        }
        if (jsonSerializer2 != null) {
        }
        HashSet<String> hashSet22 = this._ignoredEntries;
        annotationIntrospector = serializerProvider.getAnnotationIntrospector();
        findPropertiesToIgnore = annotationIntrospector.findPropertiesToIgnore(beanProperty.getMember());
        if (findPropertiesToIgnore != null) {
        }
        hashSet = hashSet22;
        MapSerializer withResolved22 = withResolved(beanProperty, handleSecondaryContextualization2, handleSecondaryContextualization, hashSet);
        if (beanProperty == null) {
        }
    }

    public JavaType getContentType() {
        return this._valueType;
    }

    public JsonSerializer<?> getContentSerializer() {
        return this._valueSerializer;
    }

    public boolean isEmpty(Map<?, ?> map) {
        return map == null || map.isEmpty();
    }

    public boolean hasSingleElement(Map<?, ?> map) {
        return map.size() == 1;
    }

    public JsonSerializer<?> getKeySerializer() {
        return this._keySerializer;
    }

    public void serialize(Map<?, ?> map, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException {
        jsonGenerator.writeStartObject();
        if (!map.isEmpty()) {
            if (this._filterId != null) {
                serializeFilteredFields(map, jsonGenerator, serializerProvider, findPropertyFilter(serializerProvider, this._filterId, map));
                return;
            }
            if (serializerProvider.isEnabled(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)) {
                map = _orderEntries(map);
            }
            if (this._valueSerializer != null) {
                serializeFieldsUsing(map, jsonGenerator, serializerProvider, this._valueSerializer);
            } else {
                serializeFields(map, jsonGenerator, serializerProvider);
            }
        }
        jsonGenerator.writeEndObject();
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=java.util.Map<?, ?>, code=java.util.Map, for r2v0, types: [java.util.Map<?, ?>, java.util.Map, java.lang.Object] */
    public void serializeWithType(Map map, JsonGenerator jsonGenerator, SerializerProvider serializerProvider, TypeSerializer typeSerializer) throws IOException, JsonGenerationException {
        typeSerializer.writeTypePrefixForObject(map, jsonGenerator);
        if (!map.isEmpty()) {
            if (serializerProvider.isEnabled(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)) {
                map = _orderEntries(map);
            }
            if (this._valueSerializer != null) {
                serializeFieldsUsing(map, jsonGenerator, serializerProvider, this._valueSerializer);
            } else {
                serializeFields(map, jsonGenerator, serializerProvider);
            }
        }
        typeSerializer.writeTypeSuffixForObject(map, jsonGenerator);
    }

    public void serializeFields(Map<?, ?> map, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException {
        boolean z;
        PropertySerializerMap propertySerializerMap;
        JsonSerializer<Object> jsonSerializer;
        JsonSerializer<Object> _findAndAddDynamic;
        if (this._valueTypeSerializer != null) {
            serializeTypedFields(map, jsonGenerator, serializerProvider);
            return;
        }
        JsonSerializer<Object> jsonSerializer2 = this._keySerializer;
        HashSet<String> hashSet = this._ignoredEntries;
        if (!serializerProvider.isEnabled(SerializationFeature.WRITE_NULL_MAP_VALUES)) {
            z = true;
        } else {
            z = false;
        }
        PropertySerializerMap propertySerializerMap2 = this._dynamicValueSerializers;
        PropertySerializerMap propertySerializerMap3 = propertySerializerMap2;
        for (Entry next : map.entrySet()) {
            Object value = next.getValue();
            Object key = next.getKey();
            if (key == null) {
                serializerProvider.findNullKeySerializer(this._keyType, this._property).serialize(null, jsonGenerator, serializerProvider);
            } else if ((!z || value != null) && (hashSet == null || !hashSet.contains(key))) {
                jsonSerializer2.serialize(key, jsonGenerator, serializerProvider);
            }
            if (value == null) {
                serializerProvider.defaultSerializeNull(jsonGenerator);
                propertySerializerMap = propertySerializerMap3;
            } else {
                Class cls = value.getClass();
                JsonSerializer<Object> serializerFor = propertySerializerMap3.serializerFor(cls);
                if (serializerFor == null) {
                    if (this._valueType.hasGenericTypes()) {
                        _findAndAddDynamic = _findAndAddDynamic(propertySerializerMap3, serializerProvider.constructSpecializedType(this._valueType, cls), serializerProvider);
                    } else {
                        _findAndAddDynamic = _findAndAddDynamic(propertySerializerMap3, cls, serializerProvider);
                    }
                    JsonSerializer<Object> jsonSerializer3 = _findAndAddDynamic;
                    propertySerializerMap = this._dynamicValueSerializers;
                    jsonSerializer = jsonSerializer3;
                } else {
                    JsonSerializer<Object> jsonSerializer4 = serializerFor;
                    propertySerializerMap = propertySerializerMap3;
                    jsonSerializer = jsonSerializer4;
                }
                try {
                    jsonSerializer.serialize(value, jsonGenerator, serializerProvider);
                } catch (Exception e) {
                    wrapAndThrow(serializerProvider, (Throwable) e, (Object) map, "" + key);
                }
            }
            propertySerializerMap3 = propertySerializerMap;
        }
    }

    /* access modifiers changed from: protected */
    public void serializeFieldsUsing(Map<?, ?> map, JsonGenerator jsonGenerator, SerializerProvider serializerProvider, JsonSerializer<Object> jsonSerializer) throws IOException, JsonGenerationException {
        JsonSerializer<Object> jsonSerializer2 = this._keySerializer;
        HashSet<String> hashSet = this._ignoredEntries;
        TypeSerializer typeSerializer = this._valueTypeSerializer;
        boolean z = !serializerProvider.isEnabled(SerializationFeature.WRITE_NULL_MAP_VALUES);
        for (Entry next : map.entrySet()) {
            Object value = next.getValue();
            Object key = next.getKey();
            if (key == null) {
                serializerProvider.findNullKeySerializer(this._keyType, this._property).serialize(null, jsonGenerator, serializerProvider);
            } else if ((!z || value != null) && (hashSet == null || !hashSet.contains(key))) {
                jsonSerializer2.serialize(key, jsonGenerator, serializerProvider);
            }
            if (value == null) {
                serializerProvider.defaultSerializeNull(jsonGenerator);
            } else if (typeSerializer == null) {
                try {
                    jsonSerializer.serialize(value, jsonGenerator, serializerProvider);
                } catch (Exception e) {
                    wrapAndThrow(serializerProvider, (Throwable) e, (Object) map, "" + key);
                }
            } else {
                jsonSerializer.serializeWithType(value, jsonGenerator, serializerProvider, typeSerializer);
            }
        }
    }

    public void serializeFilteredFields(Map<?, ?> map, JsonGenerator jsonGenerator, SerializerProvider serializerProvider, PropertyFilter propertyFilter) throws IOException, JsonGenerationException {
        boolean z;
        JsonSerializer<Object> jsonSerializer;
        PropertySerializerMap propertySerializerMap;
        JsonSerializer<Object> jsonSerializer2;
        JsonSerializer<Object> _findAndAddDynamic;
        HashSet<String> hashSet = this._ignoredEntries;
        if (!serializerProvider.isEnabled(SerializationFeature.WRITE_NULL_MAP_VALUES)) {
            z = true;
        } else {
            z = false;
        }
        PropertySerializerMap propertySerializerMap2 = this._dynamicValueSerializers;
        MapProperty mapProperty = new MapProperty(this._valueTypeSerializer);
        PropertySerializerMap propertySerializerMap3 = propertySerializerMap2;
        for (Entry next : map.entrySet()) {
            Object key = next.getKey();
            Object value = next.getValue();
            if (key == null) {
                jsonSerializer = serializerProvider.findNullKeySerializer(this._keyType, this._property);
            } else if ((!z || value != null) && (hashSet == null || !hashSet.contains(key))) {
                jsonSerializer = this._keySerializer;
            }
            if (value == null) {
                propertySerializerMap = propertySerializerMap3;
                jsonSerializer2 = serializerProvider.getDefaultNullValueSerializer();
            } else {
                Class cls = value.getClass();
                JsonSerializer<Object> serializerFor = propertySerializerMap3.serializerFor(cls);
                if (serializerFor == null) {
                    if (this._valueType.hasGenericTypes()) {
                        _findAndAddDynamic = _findAndAddDynamic(propertySerializerMap3, serializerProvider.constructSpecializedType(this._valueType, cls), serializerProvider);
                    } else {
                        _findAndAddDynamic = _findAndAddDynamic(propertySerializerMap3, cls, serializerProvider);
                    }
                    JsonSerializer<Object> jsonSerializer3 = _findAndAddDynamic;
                    propertySerializerMap = this._dynamicValueSerializers;
                    jsonSerializer2 = jsonSerializer3;
                } else {
                    JsonSerializer<Object> jsonSerializer4 = serializerFor;
                    propertySerializerMap = propertySerializerMap3;
                    jsonSerializer2 = jsonSerializer4;
                }
            }
            mapProperty.reset(key, value, jsonSerializer, jsonSerializer2);
            try {
                propertyFilter.serializeAsField(map, jsonGenerator, serializerProvider, mapProperty);
            } catch (Exception e) {
                wrapAndThrow(serializerProvider, (Throwable) e, (Object) map, "" + key);
            }
            propertySerializerMap3 = propertySerializerMap;
        }
    }

    /* access modifiers changed from: protected */
    public void serializeTypedFields(Map<?, ?> map, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException {
        JsonSerializer<Object> findValueSerializer;
        JsonSerializer jsonSerializer;
        Class cls;
        JsonSerializer<Object> jsonSerializer2 = this._keySerializer;
        HashSet<String> hashSet = this._ignoredEntries;
        boolean z = !serializerProvider.isEnabled(SerializationFeature.WRITE_NULL_MAP_VALUES);
        Class cls2 = null;
        JsonSerializer jsonSerializer3 = null;
        for (Entry next : map.entrySet()) {
            Object value = next.getValue();
            Object key = next.getKey();
            if (key == null) {
                serializerProvider.findNullKeySerializer(this._keyType, this._property).serialize(null, jsonGenerator, serializerProvider);
            } else if ((!z || value != null) && (hashSet == null || !hashSet.contains(key))) {
                jsonSerializer2.serialize(key, jsonGenerator, serializerProvider);
            }
            if (value == null) {
                serializerProvider.defaultSerializeNull(jsonGenerator);
                cls = cls2;
                jsonSerializer = jsonSerializer3;
            } else {
                Class cls3 = value.getClass();
                if (cls3 == cls2) {
                    cls = cls2;
                    jsonSerializer = jsonSerializer3;
                } else {
                    if (this._valueType.hasGenericTypes()) {
                        findValueSerializer = serializerProvider.findValueSerializer(serializerProvider.constructSpecializedType(this._valueType, cls3), this._property);
                    } else {
                        findValueSerializer = serializerProvider.findValueSerializer(cls3, this._property);
                    }
                    jsonSerializer3 = findValueSerializer;
                    jsonSerializer = findValueSerializer;
                    cls = cls3;
                }
                try {
                    jsonSerializer3.serializeWithType(value, jsonGenerator, serializerProvider, this._valueTypeSerializer);
                } catch (Exception e) {
                    wrapAndThrow(serializerProvider, (Throwable) e, (Object) map, "" + key);
                }
            }
            jsonSerializer3 = jsonSerializer;
            cls2 = cls;
        }
    }

    public JsonNode getSchema(SerializerProvider serializerProvider, Type type) {
        return createSchemaNode("object", true);
    }

    public void acceptJsonFormatVisitor(JsonFormatVisitorWrapper jsonFormatVisitorWrapper, JavaType javaType) throws JsonMappingException {
        JsonMapFormatVisitor expectMapFormat = jsonFormatVisitorWrapper == null ? null : jsonFormatVisitorWrapper.expectMapFormat(javaType);
        if (expectMapFormat != null) {
            expectMapFormat.keyFormat(this._keySerializer, this._keyType);
            JsonSerializer<Object> jsonSerializer = this._valueSerializer;
            if (jsonSerializer == null) {
                jsonSerializer = _findAndAddDynamic(this._dynamicValueSerializers, this._valueType, jsonFormatVisitorWrapper.getProvider());
            }
            expectMapFormat.valueFormat(jsonSerializer, this._valueType);
        }
    }

    /* access modifiers changed from: protected */
    public final JsonSerializer<Object> _findAndAddDynamic(PropertySerializerMap propertySerializerMap, Class<?> cls, SerializerProvider serializerProvider) throws JsonMappingException {
        SerializerAndMapResult findAndAddSecondarySerializer = propertySerializerMap.findAndAddSecondarySerializer(cls, serializerProvider, this._property);
        if (propertySerializerMap != findAndAddSecondarySerializer.map) {
            this._dynamicValueSerializers = findAndAddSecondarySerializer.map;
        }
        return findAndAddSecondarySerializer.serializer;
    }

    /* access modifiers changed from: protected */
    public final JsonSerializer<Object> _findAndAddDynamic(PropertySerializerMap propertySerializerMap, JavaType javaType, SerializerProvider serializerProvider) throws JsonMappingException {
        SerializerAndMapResult findAndAddSecondarySerializer = propertySerializerMap.findAndAddSecondarySerializer(javaType, serializerProvider, this._property);
        if (propertySerializerMap != findAndAddSecondarySerializer.map) {
            this._dynamicValueSerializers = findAndAddSecondarySerializer.map;
        }
        return findAndAddSecondarySerializer.serializer;
    }

    /* access modifiers changed from: protected */
    public Map<?, ?> _orderEntries(Map<?, ?> map) {
        return map instanceof SortedMap ? map : new TreeMap(map);
    }
}