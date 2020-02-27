package com.fasterxml.jackson.databind.ser.std;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.core.io.SerializedString;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JacksonStdImpl;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonFormatVisitorWrapper;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonObjectFormatVisitor;
import com.fasterxml.jackson.databind.jsonschema.JsonSchema;
import com.fasterxml.jackson.databind.jsonschema.SchemaAware;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ser.ContainerSerializer;
import com.fasterxml.jackson.databind.ser.ContextualSerializer;
import com.fasterxml.jackson.databind.util.EnumValues;
import com.kakao.auth.helper.ServerProtocol;
import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.EnumMap;
import java.util.Map.Entry;

@JacksonStdImpl
public class EnumMapSerializer extends ContainerSerializer<EnumMap<? extends Enum<?>, ?>> implements ContextualSerializer {
    protected final EnumValues _keyEnums;
    protected final BeanProperty _property;
    protected final boolean _staticTyping;
    protected final JsonSerializer<Object> _valueSerializer;
    protected final JavaType _valueType;
    protected final TypeSerializer _valueTypeSerializer;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    /*  JADX ERROR: IF instruction can be used only in fallback mode
        jadx.core.utils.exceptions.CodegenException: IF instruction can be used only in fallback mode
        	at jadx.core.codegen.InsnGen.fallbackOnlyInsn(InsnGen.java:571)
        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:477)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:242)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:213)
        	at jadx.core.codegen.RegionGen.makeSimpleBlock(RegionGen.java:109)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:55)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:92)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:58)
        	at jadx.core.codegen.MethodGen.addRegionInsns(MethodGen.java:210)
        	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:203)
        	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:315)
        	at jadx.core.codegen.ClassGen.addMethods(ClassGen.java:261)
        	at jadx.core.codegen.ClassGen.addClassBody(ClassGen.java:224)
        	at jadx.core.codegen.ClassGen.addClassCode(ClassGen.java:109)
        	at jadx.core.codegen.ClassGen.makeClass(ClassGen.java:75)
        	at jadx.core.codegen.CodeGen.wrapCodeGen(CodeGen.java:44)
        	at jadx.core.codegen.CodeGen.generateJavaCode(CodeGen.java:32)
        	at jadx.core.codegen.CodeGen.generate(CodeGen.java:20)
        	at jadx.core.ProcessClass.process(ProcessClass.java:36)
        	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
        	at jadx.api.JavaClass.decompile(JavaClass.java:62)
        */
    /* JADX WARNING: Code restructure failed: missing block: B:5:0x0013, code lost:
        r0 = true;
     */
    public EnumMapSerializer(com.fasterxml.jackson.databind.JavaType r3, boolean r4, com.fasterxml.jackson.databind.util.EnumValues r5, com.fasterxml.jackson.databind.jsontype.TypeSerializer r6, com.fasterxml.jackson.databind.JsonSerializer<java.lang.Object> r7) {
        /*
            r2 = this;
            r0 = 0
            java.lang.Class<java.util.EnumMap> r1 = java.util.EnumMap.class
            r2.<init>(r1, r0)
            r1 = 0
            r2._property = r1
            if (r4 != 0) goto L_0x0013
            if (r3 == 0) goto L_0x0014
            boolean r1 = r3.isFinal()
            if (r1 == 0) goto L_0x0014
        L_0x0013:
            r0 = 1
        L_0x0014:
            r2._staticTyping = r0
            r2._valueType = r3
            r2._keyEnums = r5
            r2._valueTypeSerializer = r6
            r2._valueSerializer = r7
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.ser.std.EnumMapSerializer.<init>(com.fasterxml.jackson.databind.JavaType, boolean, com.fasterxml.jackson.databind.util.EnumValues, com.fasterxml.jackson.databind.jsontype.TypeSerializer, com.fasterxml.jackson.databind.JsonSerializer):void");
    }

    public EnumMapSerializer(EnumMapSerializer enumMapSerializer, BeanProperty beanProperty, JsonSerializer<?> jsonSerializer) {
        super((ContainerSerializer<?>) enumMapSerializer);
        this._property = beanProperty;
        this._staticTyping = enumMapSerializer._staticTyping;
        this._valueType = enumMapSerializer._valueType;
        this._keyEnums = enumMapSerializer._keyEnums;
        this._valueTypeSerializer = enumMapSerializer._valueTypeSerializer;
        this._valueSerializer = jsonSerializer;
    }

    public EnumMapSerializer _withValueTypeSerializer(TypeSerializer typeSerializer) {
        return new EnumMapSerializer(this._valueType, this._staticTyping, this._keyEnums, typeSerializer, this._valueSerializer);
    }

    public EnumMapSerializer withValueSerializer(BeanProperty beanProperty, JsonSerializer<?> jsonSerializer) {
        return (this._property == beanProperty && jsonSerializer == this._valueSerializer) ? this : new EnumMapSerializer(this, beanProperty, jsonSerializer);
    }

    public JsonSerializer<?> createContextual(SerializerProvider serializerProvider, BeanProperty beanProperty) throws JsonMappingException {
        JsonSerializer<Object> jsonSerializer = null;
        if (beanProperty != null) {
            AnnotatedMember member = beanProperty.getMember();
            if (member != null) {
                Object findContentSerializer = serializerProvider.getAnnotationIntrospector().findContentSerializer(member);
                if (findContentSerializer != null) {
                    jsonSerializer = serializerProvider.serializerInstance(member, findContentSerializer);
                }
            }
        }
        if (jsonSerializer == null) {
            jsonSerializer = this._valueSerializer;
        }
        JsonSerializer<?> findConvertingContentSerializer = findConvertingContentSerializer(serializerProvider, beanProperty, jsonSerializer);
        if (findConvertingContentSerializer != null) {
            findConvertingContentSerializer = serializerProvider.handleSecondaryContextualization(findConvertingContentSerializer, beanProperty);
        } else if (this._staticTyping) {
            return withValueSerializer(beanProperty, serializerProvider.findValueSerializer(this._valueType, beanProperty));
        }
        if (findConvertingContentSerializer != this._valueSerializer) {
            return withValueSerializer(beanProperty, findConvertingContentSerializer);
        }
        return this;
    }

    public JavaType getContentType() {
        return this._valueType;
    }

    public JsonSerializer<?> getContentSerializer() {
        return this._valueSerializer;
    }

    public boolean isEmpty(EnumMap<? extends Enum<?>, ?> enumMap) {
        return enumMap == null || enumMap.isEmpty();
    }

    public boolean hasSingleElement(EnumMap<? extends Enum<?>, ?> enumMap) {
        return enumMap.size() == 1;
    }

    public void serialize(EnumMap<? extends Enum<?>, ?> enumMap, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException {
        jsonGenerator.writeStartObject();
        if (!enumMap.isEmpty()) {
            serializeContents(enumMap, jsonGenerator, serializerProvider);
        }
        jsonGenerator.writeEndObject();
    }

    public void serializeWithType(EnumMap<? extends Enum<?>, ?> enumMap, JsonGenerator jsonGenerator, SerializerProvider serializerProvider, TypeSerializer typeSerializer) throws IOException, JsonGenerationException {
        typeSerializer.writeTypePrefixForObject(enumMap, jsonGenerator);
        if (!enumMap.isEmpty()) {
            serializeContents(enumMap, jsonGenerator, serializerProvider);
        }
        typeSerializer.writeTypeSuffixForObject(enumMap, jsonGenerator);
    }

    /* access modifiers changed from: protected */
    public void serializeContents(EnumMap<? extends Enum<?>, ?> enumMap, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException {
        boolean z;
        JsonSerializer<Object> jsonSerializer;
        if (this._valueSerializer != null) {
            serializeContentsUsing(enumMap, jsonGenerator, serializerProvider, this._valueSerializer);
            return;
        }
        EnumValues enumValues = this._keyEnums;
        if (!serializerProvider.isEnabled(SerializationFeature.WRITE_NULL_MAP_VALUES)) {
            z = true;
        } else {
            z = false;
        }
        TypeSerializer typeSerializer = this._valueTypeSerializer;
        Class cls = null;
        JsonSerializer<Object> jsonSerializer2 = null;
        EnumValues enumValues2 = enumValues;
        for (Entry next : enumMap.entrySet()) {
            Object value = next.getValue();
            if (!z || value != null) {
                Enum enumR = (Enum) next.getKey();
                if (enumValues2 == null) {
                    enumValues2 = ((EnumSerializer) ((StdSerializer) serializerProvider.findValueSerializer(enumR.getDeclaringClass(), this._property))).getEnumValues();
                }
                jsonGenerator.writeFieldName((SerializableString) enumValues2.serializedValueFor(enumR));
                if (value == null) {
                    serializerProvider.defaultSerializeNull(jsonGenerator);
                } else {
                    Class cls2 = value.getClass();
                    if (cls2 == cls) {
                        cls2 = cls;
                        jsonSerializer = jsonSerializer2;
                    } else {
                        jsonSerializer2 = serializerProvider.findValueSerializer(cls2, this._property);
                        jsonSerializer = jsonSerializer2;
                    }
                    if (typeSerializer == null) {
                        try {
                            jsonSerializer2.serialize(value, jsonGenerator, serializerProvider);
                        } catch (Exception e) {
                            wrapAndThrow(serializerProvider, (Throwable) e, (Object) enumMap, ((Enum) next.getKey()).name());
                        }
                    } else {
                        jsonSerializer2.serializeWithType(value, jsonGenerator, serializerProvider, typeSerializer);
                    }
                    jsonSerializer2 = jsonSerializer;
                    cls = cls2;
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public void serializeContentsUsing(EnumMap<? extends Enum<?>, ?> enumMap, JsonGenerator jsonGenerator, SerializerProvider serializerProvider, JsonSerializer<Object> jsonSerializer) throws IOException, JsonGenerationException {
        boolean z;
        EnumValues enumValues = this._keyEnums;
        if (!serializerProvider.isEnabled(SerializationFeature.WRITE_NULL_MAP_VALUES)) {
            z = true;
        } else {
            z = false;
        }
        TypeSerializer typeSerializer = this._valueTypeSerializer;
        EnumValues enumValues2 = enumValues;
        for (Entry next : enumMap.entrySet()) {
            Object value = next.getValue();
            if (!z || value != null) {
                Enum enumR = (Enum) next.getKey();
                if (enumValues2 == null) {
                    enumValues2 = ((EnumSerializer) ((StdSerializer) serializerProvider.findValueSerializer(enumR.getDeclaringClass(), this._property))).getEnumValues();
                }
                jsonGenerator.writeFieldName((SerializableString) enumValues2.serializedValueFor(enumR));
                if (value == null) {
                    serializerProvider.defaultSerializeNull(jsonGenerator);
                } else if (typeSerializer == null) {
                    try {
                        jsonSerializer.serialize(value, jsonGenerator, serializerProvider);
                    } catch (Exception e) {
                        wrapAndThrow(serializerProvider, (Throwable) e, (Object) enumMap, ((Enum) next.getKey()).name());
                    }
                } else {
                    jsonSerializer.serializeWithType(value, jsonGenerator, serializerProvider, typeSerializer);
                }
            }
        }
    }

    public JsonNode getSchema(SerializerProvider serializerProvider, Type type) throws JsonMappingException {
        Enum[] enumArr;
        ObjectNode createSchemaNode = createSchemaNode("object", true);
        if (type instanceof ParameterizedType) {
            Type[] actualTypeArguments = ((ParameterizedType) type).getActualTypeArguments();
            if (actualTypeArguments.length == 2) {
                JavaType constructType = serializerProvider.constructType(actualTypeArguments[0]);
                JavaType constructType2 = serializerProvider.constructType(actualTypeArguments[1]);
                ObjectNode objectNode = JsonNodeFactory.instance.objectNode();
                for (Enum enumR : (Enum[]) constructType.getRawClass().getEnumConstants()) {
                    JsonSerializer<Object> findValueSerializer = serializerProvider.findValueSerializer(constructType2.getRawClass(), this._property);
                    objectNode.put(serializerProvider.getConfig().getAnnotationIntrospector().findEnumValue(enumR), findValueSerializer instanceof SchemaAware ? ((SchemaAware) findValueSerializer).getSchema(serializerProvider, null) : JsonSchema.getDefaultSchemaNode());
                }
                createSchemaNode.put((String) ServerProtocol.PROPERTIES_KEY, (JsonNode) objectNode);
            }
        }
        return createSchemaNode;
    }

    public void acceptJsonFormatVisitor(JsonFormatVisitorWrapper jsonFormatVisitorWrapper, JavaType javaType) throws JsonMappingException {
        JavaType javaType2;
        JsonSerializer<Object> jsonSerializer;
        if (jsonFormatVisitorWrapper != null) {
            JsonObjectFormatVisitor expectObjectFormat = jsonFormatVisitorWrapper.expectObjectFormat(javaType);
            if (expectObjectFormat != null) {
                JavaType containedType = javaType.containedType(1);
                JsonSerializer<Object> jsonSerializer2 = this._valueSerializer;
                if (jsonSerializer2 == null && containedType != null) {
                    jsonSerializer2 = jsonFormatVisitorWrapper.getProvider().findValueSerializer(containedType, this._property);
                }
                if (containedType == null) {
                    javaType2 = jsonFormatVisitorWrapper.getProvider().constructType(Object.class);
                } else {
                    javaType2 = containedType;
                }
                EnumValues enumValues = this._keyEnums;
                if (enumValues == null) {
                    JavaType containedType2 = javaType.containedType(0);
                    if (containedType2 == null) {
                        throw new IllegalStateException("Can not resolve Enum type of EnumMap: " + javaType);
                    }
                    JsonSerializer<Object> findValueSerializer = jsonFormatVisitorWrapper.getProvider().findValueSerializer(containedType2, this._property);
                    if (!(findValueSerializer instanceof EnumSerializer)) {
                        throw new IllegalStateException("Can not resolve Enum type of EnumMap: " + javaType);
                    }
                    enumValues = ((EnumSerializer) findValueSerializer).getEnumValues();
                }
                JsonSerializer<Object> jsonSerializer3 = jsonSerializer2;
                for (Entry next : enumValues.internalMap().entrySet()) {
                    String value = ((SerializedString) next.getValue()).getValue();
                    if (jsonSerializer3 == null) {
                        jsonSerializer = jsonFormatVisitorWrapper.getProvider().findValueSerializer(next.getKey().getClass(), this._property);
                    } else {
                        jsonSerializer = jsonSerializer3;
                    }
                    expectObjectFormat.property(value, jsonSerializer, javaType2);
                    jsonSerializer3 = jsonSerializer;
                }
            }
        }
    }
}