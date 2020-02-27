package com.fasterxml.jackson.databind.ser.std;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonArrayFormatVisitor;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonFormatVisitorWrapper;
import com.fasterxml.jackson.databind.jsonschema.JsonSchema;
import com.fasterxml.jackson.databind.jsonschema.SchemaAware;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ser.ContainerSerializer;
import com.fasterxml.jackson.databind.ser.ContextualSerializer;
import com.fasterxml.jackson.databind.ser.impl.PropertySerializerMap;
import com.fasterxml.jackson.databind.ser.impl.PropertySerializerMap.SerializerAndMapResult;
import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

public abstract class AsArraySerializerBase<T> extends ContainerSerializer<T> implements ContextualSerializer {
    protected PropertySerializerMap _dynamicSerializers;
    protected final JsonSerializer<Object> _elementSerializer;
    protected final JavaType _elementType;
    protected final BeanProperty _property;
    protected final boolean _staticTyping;
    protected final TypeSerializer _valueTypeSerializer;

    /* access modifiers changed from: protected */
    public abstract void serializeContents(
/*
Method generation error in method: com.fasterxml.jackson.databind.ser.std.AsArraySerializerBase.serializeContents(java.lang.Object, com.fasterxml.jackson.core.JsonGenerator, com.fasterxml.jackson.databind.SerializerProvider):void, dex: classes.dex
    jadx.core.utils.exceptions.JadxRuntimeException: Code variable not set in r1v0 ?
    	at jadx.core.dex.instructions.args.SSAVar.getCodeVar(SSAVar.java:168)
    	at jadx.core.codegen.MethodGen.addMethodArguments(MethodGen.java:157)
    	at jadx.core.codegen.MethodGen.addDefinition(MethodGen.java:129)
    	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:295)
    	at jadx.core.codegen.ClassGen.addMethods(ClassGen.java:261)
    	at jadx.core.codegen.ClassGen.addClassBody(ClassGen.java:224)
    	at jadx.core.codegen.ClassGen.addClassCode(ClassGen.java:109)
    	at jadx.core.codegen.ClassGen.makeClass(ClassGen.java:75)
    	at jadx.core.codegen.CodeGen.wrapCodeGen(CodeGen.java:49)
    	at jadx.core.codegen.CodeGen.generateJavaCode(CodeGen.java:32)
    	at jadx.core.codegen.CodeGen.generate(CodeGen.java:20)
    	at jadx.core.ProcessClass.process(ProcessClass.java:36)
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
    
*/

    public abstract AsArraySerializerBase<T> withResolved(
/*
Method generation error in method: com.fasterxml.jackson.databind.ser.std.AsArraySerializerBase.withResolved(com.fasterxml.jackson.databind.BeanProperty, com.fasterxml.jackson.databind.jsontype.TypeSerializer, com.fasterxml.jackson.databind.JsonSerializer):com.fasterxml.jackson.databind.ser.std.AsArraySerializerBase<T>, dex: classes.dex
    jadx.core.utils.exceptions.JadxRuntimeException: Code variable not set in r1v0 ?
    	at jadx.core.dex.instructions.args.SSAVar.getCodeVar(SSAVar.java:168)
    	at jadx.core.codegen.MethodGen.addMethodArguments(MethodGen.java:157)
    	at jadx.core.codegen.MethodGen.addDefinition(MethodGen.java:129)
    	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:295)
    	at jadx.core.codegen.ClassGen.addMethods(ClassGen.java:261)
    	at jadx.core.codegen.ClassGen.addClassBody(ClassGen.java:224)
    	at jadx.core.codegen.ClassGen.addClassCode(ClassGen.java:109)
    	at jadx.core.codegen.ClassGen.makeClass(ClassGen.java:75)
    	at jadx.core.codegen.CodeGen.wrapCodeGen(CodeGen.java:49)
    	at jadx.core.codegen.CodeGen.generateJavaCode(CodeGen.java:32)
    	at jadx.core.codegen.CodeGen.generate(CodeGen.java:20)
    	at jadx.core.ProcessClass.process(ProcessClass.java:36)
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
    
*/

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
    /* JADX WARNING: Code restructure failed: missing block: B:5:0x0010, code lost:
        r0 = true;
     */
    protected AsArraySerializerBase(java.lang.Class<?> r3, com.fasterxml.jackson.databind.JavaType r4, boolean r5, com.fasterxml.jackson.databind.jsontype.TypeSerializer r6, com.fasterxml.jackson.databind.BeanProperty r7, com.fasterxml.jackson.databind.JsonSerializer<java.lang.Object> r8) {
        /*
            r2 = this;
            r0 = 0
            r2.<init>(r3, r0)
            r2._elementType = r4
            if (r5 != 0) goto L_0x0010
            if (r4 == 0) goto L_0x0011
            boolean r1 = r4.isFinal()
            if (r1 == 0) goto L_0x0011
        L_0x0010:
            r0 = 1
        L_0x0011:
            r2._staticTyping = r0
            r2._valueTypeSerializer = r6
            r2._property = r7
            r2._elementSerializer = r8
            com.fasterxml.jackson.databind.ser.impl.PropertySerializerMap r0 = com.fasterxml.jackson.databind.ser.impl.PropertySerializerMap.emptyMap()
            r2._dynamicSerializers = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.ser.std.AsArraySerializerBase.<init>(java.lang.Class, com.fasterxml.jackson.databind.JavaType, boolean, com.fasterxml.jackson.databind.jsontype.TypeSerializer, com.fasterxml.jackson.databind.BeanProperty, com.fasterxml.jackson.databind.JsonSerializer):void");
    }

    protected AsArraySerializerBase(AsArraySerializerBase<?> asArraySerializerBase, BeanProperty beanProperty, TypeSerializer typeSerializer, JsonSerializer<?> jsonSerializer) {
        super((ContainerSerializer<?>) asArraySerializerBase);
        this._elementType = asArraySerializerBase._elementType;
        this._staticTyping = asArraySerializerBase._staticTyping;
        this._valueTypeSerializer = typeSerializer;
        this._property = beanProperty;
        this._elementSerializer = jsonSerializer;
        this._dynamicSerializers = asArraySerializerBase._dynamicSerializers;
    }

    public JsonSerializer<?> createContextual(SerializerProvider serializerProvider, BeanProperty beanProperty) throws JsonMappingException {
        TypeSerializer typeSerializer;
        TypeSerializer typeSerializer2 = this._valueTypeSerializer;
        if (typeSerializer2 != null) {
            typeSerializer = typeSerializer2.forProperty(beanProperty);
        } else {
            typeSerializer = typeSerializer2;
        }
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
            jsonSerializer = this._elementSerializer;
        }
        JsonSerializer findConvertingContentSerializer = findConvertingContentSerializer(serializerProvider, beanProperty, jsonSerializer);
        if (findConvertingContentSerializer != null) {
            findConvertingContentSerializer = serializerProvider.handleSecondaryContextualization(findConvertingContentSerializer, beanProperty);
        } else if (this._elementType != null && ((this._staticTyping && this._elementType.getRawClass() != Object.class) || hasContentTypeAnnotation(serializerProvider, beanProperty))) {
            findConvertingContentSerializer = serializerProvider.findValueSerializer(this._elementType, beanProperty);
        }
        if (findConvertingContentSerializer == this._elementSerializer && beanProperty == this._property && this._valueTypeSerializer == typeSerializer) {
            return this;
        }
        return withResolved(beanProperty, typeSerializer, findConvertingContentSerializer);
    }

    public JavaType getContentType() {
        return this._elementType;
    }

    public JsonSerializer<?> getContentSerializer() {
        return this._elementSerializer;
    }

    public final void serialize(T t, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException {
        if (!serializerProvider.isEnabled(SerializationFeature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED) || !hasSingleElement(t)) {
            jsonGenerator.writeStartArray();
            serializeContents(t, jsonGenerator, serializerProvider);
            jsonGenerator.writeEndArray();
            return;
        }
        serializeContents(t, jsonGenerator, serializerProvider);
    }

    public void serializeWithType(T t, JsonGenerator jsonGenerator, SerializerProvider serializerProvider, TypeSerializer typeSerializer) throws IOException, JsonGenerationException {
        typeSerializer.writeTypePrefixForArray(t, jsonGenerator);
        serializeContents(t, jsonGenerator, serializerProvider);
        typeSerializer.writeTypeSuffixForArray(t, jsonGenerator);
    }

    /* JADX WARNING: Removed duplicated region for block: B:20:0x004d  */
    public JsonNode getSchema(SerializerProvider serializerProvider, Type type) throws JsonMappingException {
        JavaType javaType;
        JsonNode jsonNode;
        ObjectNode createSchemaNode = createSchemaNode("array", true);
        if (type != null) {
            javaType = serializerProvider.constructType(type).getContentType();
            if (javaType == null && (type instanceof ParameterizedType)) {
                Type[] actualTypeArguments = ((ParameterizedType) type).getActualTypeArguments();
                if (actualTypeArguments.length == 1) {
                    javaType = serializerProvider.constructType(actualTypeArguments[0]);
                }
            }
        } else {
            javaType = null;
        }
        if (javaType == null && this._elementType != null) {
            javaType = this._elementType;
        }
        if (javaType != null) {
            if (javaType.getRawClass() != Object.class) {
                JsonSerializer<Object> findValueSerializer = serializerProvider.findValueSerializer(javaType, this._property);
                if (findValueSerializer instanceof SchemaAware) {
                    jsonNode = ((SchemaAware) findValueSerializer).getSchema(serializerProvider, null);
                    if (jsonNode == null) {
                        jsonNode = JsonSchema.getDefaultSchemaNode();
                    }
                    createSchemaNode.put((String) "items", jsonNode);
                }
            }
            jsonNode = null;
            if (jsonNode == null) {
            }
            createSchemaNode.put((String) "items", jsonNode);
        }
        return createSchemaNode;
    }

    public void acceptJsonFormatVisitor(JsonFormatVisitorWrapper jsonFormatVisitorWrapper, JavaType javaType) throws JsonMappingException {
        JsonArrayFormatVisitor expectArrayFormat = jsonFormatVisitorWrapper == null ? null : jsonFormatVisitorWrapper.expectArrayFormat(javaType);
        if (expectArrayFormat != null) {
            JavaType moreSpecificType = jsonFormatVisitorWrapper.getProvider().getTypeFactory().moreSpecificType(this._elementType, javaType.getContentType());
            if (moreSpecificType == null) {
                throw new JsonMappingException("Could not resolve type");
            }
            JsonSerializer<Object> jsonSerializer = this._elementSerializer;
            if (jsonSerializer == null) {
                jsonSerializer = jsonFormatVisitorWrapper.getProvider().findValueSerializer(moreSpecificType, this._property);
            }
            expectArrayFormat.itemsFormat(jsonSerializer, moreSpecificType);
        }
    }

    /* access modifiers changed from: protected */
    public final JsonSerializer<Object> _findAndAddDynamic(PropertySerializerMap propertySerializerMap, Class<?> cls, SerializerProvider serializerProvider) throws JsonMappingException {
        SerializerAndMapResult findAndAddSecondarySerializer = propertySerializerMap.findAndAddSecondarySerializer(cls, serializerProvider, this._property);
        if (propertySerializerMap != findAndAddSecondarySerializer.map) {
            this._dynamicSerializers = findAndAddSecondarySerializer.map;
        }
        return findAndAddSecondarySerializer.serializer;
    }

    /* access modifiers changed from: protected */
    public final JsonSerializer<Object> _findAndAddDynamic(PropertySerializerMap propertySerializerMap, JavaType javaType, SerializerProvider serializerProvider) throws JsonMappingException {
        SerializerAndMapResult findAndAddSecondarySerializer = propertySerializerMap.findAndAddSecondarySerializer(javaType, serializerProvider, this._property);
        if (propertySerializerMap != findAndAddSecondarySerializer.map) {
            this._dynamicSerializers = findAndAddSecondarySerializer.map;
        }
        return findAndAddSecondarySerializer.serializer;
    }
}