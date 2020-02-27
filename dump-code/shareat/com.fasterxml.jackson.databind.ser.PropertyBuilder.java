package com.fasterxml.jackson.databind.ser;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize.Typing;
import com.fasterxml.jackson.databind.introspect.Annotated;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.util.Annotations;
import com.fasterxml.jackson.databind.util.ArrayBuilders;
import com.fasterxml.jackson.databind.util.NameTransformer;

public class PropertyBuilder {
    protected final AnnotationIntrospector _annotationIntrospector = this._config.getAnnotationIntrospector();
    protected final BeanDescription _beanDesc;
    protected final SerializationConfig _config;
    protected Object _defaultBean;
    protected final Include _outputProps;

    public PropertyBuilder(SerializationConfig serializationConfig, BeanDescription beanDescription) {
        this._config = serializationConfig;
        this._beanDesc = beanDescription;
        this._outputProps = beanDescription.findSerializationInclusion(serializationConfig.getSerializationInclusion());
    }

    public Annotations getClassAnnotations() {
        return this._beanDesc.getClassAnnotations();
    }

    /* access modifiers changed from: protected */
    @Deprecated
    public final BeanPropertyWriter buildWriter(BeanPropertyDefinition beanPropertyDefinition, JavaType javaType, JsonSerializer<?> jsonSerializer, TypeSerializer typeSerializer, TypeSerializer typeSerializer2, AnnotatedMember annotatedMember, boolean z) {
        throw new IllegalStateException();
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Removed duplicated region for block: B:16:0x0094  */
    /* JADX WARNING: Removed duplicated region for block: B:19:0x00a7  */
    /* JADX WARNING: Removed duplicated region for block: B:35:? A[RETURN, SYNTHETIC] */
    public BeanPropertyWriter buildWriter(SerializerProvider serializerProvider, BeanPropertyDefinition beanPropertyDefinition, JavaType javaType, JsonSerializer<?> jsonSerializer, TypeSerializer typeSerializer, TypeSerializer typeSerializer2, AnnotatedMember annotatedMember, boolean z) throws JsonMappingException {
        JavaType javaType2;
        boolean z2;
        Object findNullSerializer;
        NameTransformer findUnwrappingNameTransformer;
        JavaType findSerializationType = findSerializationType(annotatedMember, z, javaType);
        if (typeSerializer2 != null) {
            if (findSerializationType == null) {
                findSerializationType = javaType;
            }
            if (findSerializationType.getContentType() == null) {
                throw new IllegalStateException("Problem trying to create BeanPropertyWriter for property '" + beanPropertyDefinition.getName() + "' (of type " + this._beanDesc.getType() + "); serialization type " + findSerializationType + " has no content");
            }
            javaType2 = findSerializationType.withContentTypeHandler(typeSerializer2);
            javaType2.getContentType();
        } else {
            javaType2 = findSerializationType;
        }
        Object obj = null;
        boolean z3 = false;
        Include findSerializationInclusion = this._annotationIntrospector.findSerializationInclusion(annotatedMember, this._outputProps);
        if (findSerializationInclusion != null) {
            switch (findSerializationInclusion) {
                case NON_DEFAULT:
                    obj = getDefaultValue(beanPropertyDefinition.getName(), annotatedMember);
                    if (obj != null) {
                        if (obj.getClass().isArray()) {
                            obj = ArrayBuilders.getArrayComparator(obj);
                            z2 = false;
                            break;
                        }
                    } else {
                        z2 = true;
                        break;
                    }
                case NON_EMPTY:
                    obj = BeanPropertyWriter.MARKER_FOR_EMPTY;
                    z2 = true;
                    break;
                case NON_NULL:
                    z3 = true;
                    break;
                case ALWAYS:
                    break;
            }
            if (javaType.isContainerType() && !this._config.isEnabled(SerializationFeature.WRITE_EMPTY_JSON_ARRAYS)) {
                obj = BeanPropertyWriter.MARKER_FOR_EMPTY;
                z2 = z3;
                BeanPropertyWriter beanPropertyWriter = new BeanPropertyWriter(beanPropertyDefinition, annotatedMember, this._beanDesc.getClassAnnotations(), javaType, jsonSerializer, typeSerializer, javaType2, z2, obj);
                findNullSerializer = this._annotationIntrospector.findNullSerializer(annotatedMember);
                if (findNullSerializer != null) {
                    beanPropertyWriter.assignNullSerializer(serializerProvider.serializerInstance(annotatedMember, findNullSerializer));
                }
                findUnwrappingNameTransformer = this._annotationIntrospector.findUnwrappingNameTransformer(annotatedMember);
                if (findUnwrappingNameTransformer == null) {
                    return beanPropertyWriter.unwrappingWriter(findUnwrappingNameTransformer);
                }
                return beanPropertyWriter;
            }
        }
        z2 = z3;
        BeanPropertyWriter beanPropertyWriter2 = new BeanPropertyWriter(beanPropertyDefinition, annotatedMember, this._beanDesc.getClassAnnotations(), javaType, jsonSerializer, typeSerializer, javaType2, z2, obj);
        findNullSerializer = this._annotationIntrospector.findNullSerializer(annotatedMember);
        if (findNullSerializer != null) {
        }
        findUnwrappingNameTransformer = this._annotationIntrospector.findUnwrappingNameTransformer(annotatedMember);
        if (findUnwrappingNameTransformer == null) {
        }
    }

    /* access modifiers changed from: protected */
    public JavaType findSerializationType(Annotated annotated, boolean z, JavaType javaType) {
        JavaType javaType2;
        boolean z2 = true;
        Class<?> findSerializationType = this._annotationIntrospector.findSerializationType(annotated);
        if (findSerializationType != null) {
            Class<?> rawClass = javaType.getRawClass();
            if (findSerializationType.isAssignableFrom(rawClass)) {
                javaType2 = javaType.widenBy(findSerializationType);
            } else if (!rawClass.isAssignableFrom(findSerializationType)) {
                throw new IllegalArgumentException("Illegal concrete-type annotation for method '" + annotated.getName() + "': class " + findSerializationType.getName() + " not a super-type of (declared) class " + rawClass.getName());
            } else {
                javaType2 = this._config.constructSpecializedType(javaType, findSerializationType);
            }
            z = true;
        } else {
            javaType2 = javaType;
        }
        JavaType modifySecondaryTypesByAnnotation = BeanSerializerFactory.modifySecondaryTypesByAnnotation(this._config, annotated, javaType2);
        if (modifySecondaryTypesByAnnotation != javaType2) {
            javaType2 = modifySecondaryTypesByAnnotation;
            z = true;
        }
        Typing findSerializationTyping = this._annotationIntrospector.findSerializationTyping(annotated);
        if (!(findSerializationTyping == null || findSerializationTyping == Typing.DEFAULT_TYPING)) {
            if (findSerializationTyping != Typing.STATIC) {
                z2 = false;
            }
            z = z2;
        }
        if (z) {
            return javaType2;
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public Object getDefaultBean() {
        if (this._defaultBean == null) {
            this._defaultBean = this._beanDesc.instantiateBean(this._config.canOverrideAccessModifiers());
            if (this._defaultBean == null) {
                throw new IllegalArgumentException("Class " + this._beanDesc.getClassInfo().getAnnotated().getName() + " has no default constructor; can not instantiate default bean value to support 'properties=JsonSerialize.Inclusion.NON_DEFAULT' annotation");
            }
        }
        return this._defaultBean;
    }

    /* access modifiers changed from: protected */
    public Object getDefaultValue(String str, AnnotatedMember annotatedMember) {
        Object defaultBean = getDefaultBean();
        try {
            return annotatedMember.getValue(defaultBean);
        } catch (Exception e) {
            return _throwWrapped(e, str, defaultBean);
        }
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Incorrect type for immutable var: ssa=java.lang.Exception, code=java.lang.Throwable, for r4v0, types: [java.lang.Throwable, java.lang.Exception] */
    public Object _throwWrapped(Throwable th, String str, Object obj) {
        Throwable th2 = th;
        while (th2.getCause() != null) {
            th2 = th2.getCause();
        }
        if (th2 instanceof Error) {
            throw ((Error) th2);
        } else if (th2 instanceof RuntimeException) {
            throw ((RuntimeException) th2);
        } else {
            throw new IllegalArgumentException("Failed to get property '" + str + "' of default " + obj.getClass().getName() + " instance");
        }
    }
}