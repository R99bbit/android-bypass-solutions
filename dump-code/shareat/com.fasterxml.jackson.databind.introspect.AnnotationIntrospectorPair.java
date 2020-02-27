package com.fasterxml.jackson.databind.introspect;

import com.fasterxml.jackson.annotation.JsonFormat.Value;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.AnnotationIntrospector.ReferenceProperty;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer.None;
import com.fasterxml.jackson.databind.KeyDeserializer;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize.Typing;
import com.fasterxml.jackson.databind.annotation.NoClass;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.jsontype.TypeResolverBuilder;
import com.fasterxml.jackson.databind.util.NameTransformer;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AnnotationIntrospectorPair extends AnnotationIntrospector implements Serializable {
    private static final long serialVersionUID = 1;
    protected final AnnotationIntrospector _primary;
    protected final AnnotationIntrospector _secondary;

    public AnnotationIntrospectorPair(AnnotationIntrospector annotationIntrospector, AnnotationIntrospector annotationIntrospector2) {
        this._primary = annotationIntrospector;
        this._secondary = annotationIntrospector2;
    }

    public Version version() {
        return this._primary.version();
    }

    public static AnnotationIntrospector create(AnnotationIntrospector annotationIntrospector, AnnotationIntrospector annotationIntrospector2) {
        if (annotationIntrospector == null) {
            return annotationIntrospector2;
        }
        if (annotationIntrospector2 == null) {
            return annotationIntrospector;
        }
        return new AnnotationIntrospectorPair(annotationIntrospector, annotationIntrospector2);
    }

    public Collection<AnnotationIntrospector> allIntrospectors() {
        return allIntrospectors(new ArrayList());
    }

    public Collection<AnnotationIntrospector> allIntrospectors(Collection<AnnotationIntrospector> collection) {
        this._primary.allIntrospectors(collection);
        this._secondary.allIntrospectors(collection);
        return collection;
    }

    public boolean isAnnotationBundle(Annotation annotation) {
        return this._primary.isAnnotationBundle(annotation) || this._secondary.isAnnotationBundle(annotation);
    }

    public PropertyName findRootName(AnnotatedClass annotatedClass) {
        PropertyName findRootName = this._primary.findRootName(annotatedClass);
        if (findRootName == null) {
            return this._secondary.findRootName(annotatedClass);
        }
        if (findRootName.hasSimpleName()) {
            return findRootName;
        }
        PropertyName findRootName2 = this._secondary.findRootName(annotatedClass);
        return findRootName2 != null ? findRootName2 : findRootName;
    }

    public String[] findPropertiesToIgnore(Annotated annotated) {
        String[] findPropertiesToIgnore = this._primary.findPropertiesToIgnore(annotated);
        if (findPropertiesToIgnore == null) {
            return this._secondary.findPropertiesToIgnore(annotated);
        }
        return findPropertiesToIgnore;
    }

    public Boolean findIgnoreUnknownProperties(AnnotatedClass annotatedClass) {
        Boolean findIgnoreUnknownProperties = this._primary.findIgnoreUnknownProperties(annotatedClass);
        if (findIgnoreUnknownProperties == null) {
            return this._secondary.findIgnoreUnknownProperties(annotatedClass);
        }
        return findIgnoreUnknownProperties;
    }

    public Boolean isIgnorableType(AnnotatedClass annotatedClass) {
        Boolean isIgnorableType = this._primary.isIgnorableType(annotatedClass);
        if (isIgnorableType == null) {
            return this._secondary.isIgnorableType(annotatedClass);
        }
        return isIgnorableType;
    }

    @Deprecated
    public Object findFilterId(AnnotatedClass annotatedClass) {
        Object findFilterId = this._primary.findFilterId(annotatedClass);
        if (findFilterId == null) {
            return this._secondary.findFilterId(annotatedClass);
        }
        return findFilterId;
    }

    public Object findFilterId(Annotated annotated) {
        Object findFilterId = this._primary.findFilterId(annotated);
        if (findFilterId == null) {
            return this._secondary.findFilterId(annotated);
        }
        return findFilterId;
    }

    public Object findNamingStrategy(AnnotatedClass annotatedClass) {
        Object findNamingStrategy = this._primary.findNamingStrategy(annotatedClass);
        if (findNamingStrategy == null) {
            return this._secondary.findNamingStrategy(annotatedClass);
        }
        return findNamingStrategy;
    }

    public VisibilityChecker<?> findAutoDetectVisibility(AnnotatedClass annotatedClass, VisibilityChecker<?> visibilityChecker) {
        return this._primary.findAutoDetectVisibility(annotatedClass, this._secondary.findAutoDetectVisibility(annotatedClass, visibilityChecker));
    }

    public TypeResolverBuilder<?> findTypeResolver(MapperConfig<?> mapperConfig, AnnotatedClass annotatedClass, JavaType javaType) {
        TypeResolverBuilder<?> findTypeResolver = this._primary.findTypeResolver(mapperConfig, annotatedClass, javaType);
        if (findTypeResolver == null) {
            return this._secondary.findTypeResolver(mapperConfig, annotatedClass, javaType);
        }
        return findTypeResolver;
    }

    public TypeResolverBuilder<?> findPropertyTypeResolver(MapperConfig<?> mapperConfig, AnnotatedMember annotatedMember, JavaType javaType) {
        TypeResolverBuilder<?> findPropertyTypeResolver = this._primary.findPropertyTypeResolver(mapperConfig, annotatedMember, javaType);
        if (findPropertyTypeResolver == null) {
            return this._secondary.findPropertyTypeResolver(mapperConfig, annotatedMember, javaType);
        }
        return findPropertyTypeResolver;
    }

    public TypeResolverBuilder<?> findPropertyContentTypeResolver(MapperConfig<?> mapperConfig, AnnotatedMember annotatedMember, JavaType javaType) {
        TypeResolverBuilder<?> findPropertyContentTypeResolver = this._primary.findPropertyContentTypeResolver(mapperConfig, annotatedMember, javaType);
        if (findPropertyContentTypeResolver == null) {
            return this._secondary.findPropertyContentTypeResolver(mapperConfig, annotatedMember, javaType);
        }
        return findPropertyContentTypeResolver;
    }

    public List<NamedType> findSubtypes(Annotated annotated) {
        List<NamedType> findSubtypes = this._primary.findSubtypes(annotated);
        List<NamedType> findSubtypes2 = this._secondary.findSubtypes(annotated);
        if (findSubtypes == null || findSubtypes.isEmpty()) {
            return findSubtypes2;
        }
        if (findSubtypes2 == null || findSubtypes2.isEmpty()) {
            return findSubtypes;
        }
        ArrayList arrayList = new ArrayList(findSubtypes.size() + findSubtypes2.size());
        arrayList.addAll(findSubtypes);
        arrayList.addAll(findSubtypes2);
        return arrayList;
    }

    public String findTypeName(AnnotatedClass annotatedClass) {
        String findTypeName = this._primary.findTypeName(annotatedClass);
        if (findTypeName == null || findTypeName.length() == 0) {
            return this._secondary.findTypeName(annotatedClass);
        }
        return findTypeName;
    }

    public ReferenceProperty findReferenceType(AnnotatedMember annotatedMember) {
        ReferenceProperty findReferenceType = this._primary.findReferenceType(annotatedMember);
        if (findReferenceType == null) {
            return this._secondary.findReferenceType(annotatedMember);
        }
        return findReferenceType;
    }

    public NameTransformer findUnwrappingNameTransformer(AnnotatedMember annotatedMember) {
        NameTransformer findUnwrappingNameTransformer = this._primary.findUnwrappingNameTransformer(annotatedMember);
        if (findUnwrappingNameTransformer == null) {
            return this._secondary.findUnwrappingNameTransformer(annotatedMember);
        }
        return findUnwrappingNameTransformer;
    }

    public Object findInjectableValueId(AnnotatedMember annotatedMember) {
        Object findInjectableValueId = this._primary.findInjectableValueId(annotatedMember);
        if (findInjectableValueId == null) {
            return this._secondary.findInjectableValueId(annotatedMember);
        }
        return findInjectableValueId;
    }

    public boolean hasIgnoreMarker(AnnotatedMember annotatedMember) {
        return this._primary.hasIgnoreMarker(annotatedMember) || this._secondary.hasIgnoreMarker(annotatedMember);
    }

    public Boolean hasRequiredMarker(AnnotatedMember annotatedMember) {
        Boolean hasRequiredMarker = this._primary.hasRequiredMarker(annotatedMember);
        if (hasRequiredMarker == null) {
            return this._secondary.hasRequiredMarker(annotatedMember);
        }
        return hasRequiredMarker;
    }

    public Object findSerializer(Annotated annotated) {
        Object findSerializer = this._primary.findSerializer(annotated);
        if (findSerializer == null) {
            return this._secondary.findSerializer(annotated);
        }
        return findSerializer;
    }

    public Object findKeySerializer(Annotated annotated) {
        Object findKeySerializer = this._primary.findKeySerializer(annotated);
        if (findKeySerializer == null || findKeySerializer == None.class || findKeySerializer == NoClass.class) {
            return this._secondary.findKeySerializer(annotated);
        }
        return findKeySerializer;
    }

    public Object findContentSerializer(Annotated annotated) {
        Object findContentSerializer = this._primary.findContentSerializer(annotated);
        if (findContentSerializer == null || findContentSerializer == None.class || findContentSerializer == NoClass.class) {
            return this._secondary.findContentSerializer(annotated);
        }
        return findContentSerializer;
    }

    public Object findNullSerializer(Annotated annotated) {
        Object findNullSerializer = this._primary.findNullSerializer(annotated);
        if (findNullSerializer == null || findNullSerializer == None.class || findNullSerializer == NoClass.class) {
            return this._secondary.findNullSerializer(annotated);
        }
        return findNullSerializer;
    }

    public Include findSerializationInclusion(Annotated annotated, Include include) {
        return this._primary.findSerializationInclusion(annotated, this._secondary.findSerializationInclusion(annotated, include));
    }

    public Class<?> findSerializationType(Annotated annotated) {
        Class<?> findSerializationType = this._primary.findSerializationType(annotated);
        if (findSerializationType == null) {
            return this._secondary.findSerializationType(annotated);
        }
        return findSerializationType;
    }

    public Class<?> findSerializationKeyType(Annotated annotated, JavaType javaType) {
        Class<?> findSerializationKeyType = this._primary.findSerializationKeyType(annotated, javaType);
        if (findSerializationKeyType == null) {
            return this._secondary.findSerializationKeyType(annotated, javaType);
        }
        return findSerializationKeyType;
    }

    public Class<?> findSerializationContentType(Annotated annotated, JavaType javaType) {
        Class<?> findSerializationContentType = this._primary.findSerializationContentType(annotated, javaType);
        if (findSerializationContentType == null) {
            return this._secondary.findSerializationContentType(annotated, javaType);
        }
        return findSerializationContentType;
    }

    public Typing findSerializationTyping(Annotated annotated) {
        Typing findSerializationTyping = this._primary.findSerializationTyping(annotated);
        if (findSerializationTyping == null) {
            return this._secondary.findSerializationTyping(annotated);
        }
        return findSerializationTyping;
    }

    public Object findSerializationConverter(Annotated annotated) {
        Object findSerializationConverter = this._primary.findSerializationConverter(annotated);
        if (findSerializationConverter == null) {
            return this._secondary.findSerializationConverter(annotated);
        }
        return findSerializationConverter;
    }

    public Object findSerializationContentConverter(AnnotatedMember annotatedMember) {
        Object findSerializationContentConverter = this._primary.findSerializationContentConverter(annotatedMember);
        if (findSerializationContentConverter == null) {
            return this._secondary.findSerializationContentConverter(annotatedMember);
        }
        return findSerializationContentConverter;
    }

    public Class<?>[] findViews(Annotated annotated) {
        Class<?>[] findViews = this._primary.findViews(annotated);
        if (findViews == null) {
            return this._secondary.findViews(annotated);
        }
        return findViews;
    }

    public Boolean isTypeId(AnnotatedMember annotatedMember) {
        Boolean isTypeId = this._primary.isTypeId(annotatedMember);
        if (isTypeId == null) {
            return this._secondary.isTypeId(annotatedMember);
        }
        return isTypeId;
    }

    public ObjectIdInfo findObjectIdInfo(Annotated annotated) {
        ObjectIdInfo findObjectIdInfo = this._primary.findObjectIdInfo(annotated);
        if (findObjectIdInfo == null) {
            return this._secondary.findObjectIdInfo(annotated);
        }
        return findObjectIdInfo;
    }

    public ObjectIdInfo findObjectReferenceInfo(Annotated annotated, ObjectIdInfo objectIdInfo) {
        return this._primary.findObjectReferenceInfo(annotated, this._secondary.findObjectReferenceInfo(annotated, objectIdInfo));
    }

    public Value findFormat(Annotated annotated) {
        Value findFormat = this._primary.findFormat(annotated);
        if (findFormat == null) {
            return this._secondary.findFormat(annotated);
        }
        return findFormat;
    }

    public PropertyName findWrapperName(Annotated annotated) {
        PropertyName findWrapperName = this._primary.findWrapperName(annotated);
        if (findWrapperName == null) {
            return this._secondary.findWrapperName(annotated);
        }
        if (findWrapperName == PropertyName.USE_DEFAULT) {
            PropertyName findWrapperName2 = this._secondary.findWrapperName(annotated);
            if (findWrapperName2 != null) {
                return findWrapperName2;
            }
        }
        return findWrapperName;
    }

    public String findPropertyDescription(Annotated annotated) {
        String findPropertyDescription = this._primary.findPropertyDescription(annotated);
        if (findPropertyDescription == null) {
            return this._secondary.findPropertyDescription(annotated);
        }
        return findPropertyDescription;
    }

    public String[] findSerializationPropertyOrder(AnnotatedClass annotatedClass) {
        String[] findSerializationPropertyOrder = this._primary.findSerializationPropertyOrder(annotatedClass);
        if (findSerializationPropertyOrder == null) {
            return this._secondary.findSerializationPropertyOrder(annotatedClass);
        }
        return findSerializationPropertyOrder;
    }

    public Boolean findSerializationSortAlphabetically(AnnotatedClass annotatedClass) {
        Boolean findSerializationSortAlphabetically = this._primary.findSerializationSortAlphabetically(annotatedClass);
        if (findSerializationSortAlphabetically == null) {
            return this._secondary.findSerializationSortAlphabetically(annotatedClass);
        }
        return findSerializationSortAlphabetically;
    }

    public PropertyName findNameForSerialization(Annotated annotated) {
        PropertyName findNameForSerialization = this._primary.findNameForSerialization(annotated);
        if (findNameForSerialization == null) {
            return this._secondary.findNameForSerialization(annotated);
        }
        if (findNameForSerialization == PropertyName.USE_DEFAULT) {
            PropertyName findNameForSerialization2 = this._secondary.findNameForSerialization(annotated);
            if (findNameForSerialization2 != null) {
                return findNameForSerialization2;
            }
        }
        return findNameForSerialization;
    }

    public boolean hasAsValueAnnotation(AnnotatedMethod annotatedMethod) {
        return this._primary.hasAsValueAnnotation(annotatedMethod) || this._secondary.hasAsValueAnnotation(annotatedMethod);
    }

    public String findEnumValue(Enum<?> enumR) {
        String findEnumValue = this._primary.findEnumValue(enumR);
        if (findEnumValue == null) {
            return this._secondary.findEnumValue(enumR);
        }
        return findEnumValue;
    }

    public Object findDeserializer(Annotated annotated) {
        Object findDeserializer = this._primary.findDeserializer(annotated);
        if (findDeserializer == null) {
            return this._secondary.findDeserializer(annotated);
        }
        return findDeserializer;
    }

    public Object findKeyDeserializer(Annotated annotated) {
        Object findKeyDeserializer = this._primary.findKeyDeserializer(annotated);
        if (findKeyDeserializer == null || findKeyDeserializer == KeyDeserializer.None.class || findKeyDeserializer == NoClass.class) {
            return this._secondary.findKeyDeserializer(annotated);
        }
        return findKeyDeserializer;
    }

    public Object findContentDeserializer(Annotated annotated) {
        Object findContentDeserializer = this._primary.findContentDeserializer(annotated);
        if (findContentDeserializer == null || findContentDeserializer == JsonDeserializer.None.class || findContentDeserializer == NoClass.class) {
            return this._secondary.findContentDeserializer(annotated);
        }
        return findContentDeserializer;
    }

    public Class<?> findDeserializationType(Annotated annotated, JavaType javaType) {
        Class<?> findDeserializationType = this._primary.findDeserializationType(annotated, javaType);
        if (findDeserializationType == null) {
            return this._secondary.findDeserializationType(annotated, javaType);
        }
        return findDeserializationType;
    }

    public Class<?> findDeserializationKeyType(Annotated annotated, JavaType javaType) {
        Class<?> findDeserializationKeyType = this._primary.findDeserializationKeyType(annotated, javaType);
        if (findDeserializationKeyType == null) {
            return this._secondary.findDeserializationKeyType(annotated, javaType);
        }
        return findDeserializationKeyType;
    }

    public Class<?> findDeserializationContentType(Annotated annotated, JavaType javaType) {
        Class<?> findDeserializationContentType = this._primary.findDeserializationContentType(annotated, javaType);
        if (findDeserializationContentType == null) {
            return this._secondary.findDeserializationContentType(annotated, javaType);
        }
        return findDeserializationContentType;
    }

    public Object findDeserializationConverter(Annotated annotated) {
        Object findDeserializationConverter = this._primary.findDeserializationConverter(annotated);
        if (findDeserializationConverter == null) {
            return this._secondary.findDeserializationConverter(annotated);
        }
        return findDeserializationConverter;
    }

    public Object findDeserializationContentConverter(AnnotatedMember annotatedMember) {
        Object findDeserializationContentConverter = this._primary.findDeserializationContentConverter(annotatedMember);
        if (findDeserializationContentConverter == null) {
            return this._secondary.findDeserializationContentConverter(annotatedMember);
        }
        return findDeserializationContentConverter;
    }

    public Object findValueInstantiator(AnnotatedClass annotatedClass) {
        Object findValueInstantiator = this._primary.findValueInstantiator(annotatedClass);
        if (findValueInstantiator == null) {
            return this._secondary.findValueInstantiator(annotatedClass);
        }
        return findValueInstantiator;
    }

    public Class<?> findPOJOBuilder(AnnotatedClass annotatedClass) {
        Class<?> findPOJOBuilder = this._primary.findPOJOBuilder(annotatedClass);
        if (findPOJOBuilder == null) {
            return this._secondary.findPOJOBuilder(annotatedClass);
        }
        return findPOJOBuilder;
    }

    public JsonPOJOBuilder.Value findPOJOBuilderConfig(AnnotatedClass annotatedClass) {
        JsonPOJOBuilder.Value findPOJOBuilderConfig = this._primary.findPOJOBuilderConfig(annotatedClass);
        if (findPOJOBuilderConfig == null) {
            return this._secondary.findPOJOBuilderConfig(annotatedClass);
        }
        return findPOJOBuilderConfig;
    }

    public PropertyName findNameForDeserialization(Annotated annotated) {
        PropertyName findNameForDeserialization = this._primary.findNameForDeserialization(annotated);
        if (findNameForDeserialization == null) {
            return this._secondary.findNameForDeserialization(annotated);
        }
        if (findNameForDeserialization == PropertyName.USE_DEFAULT) {
            PropertyName findNameForDeserialization2 = this._secondary.findNameForDeserialization(annotated);
            if (findNameForDeserialization2 != null) {
                return findNameForDeserialization2;
            }
        }
        return findNameForDeserialization;
    }

    public boolean hasAnySetterAnnotation(AnnotatedMethod annotatedMethod) {
        return this._primary.hasAnySetterAnnotation(annotatedMethod) || this._secondary.hasAnySetterAnnotation(annotatedMethod);
    }

    public boolean hasAnyGetterAnnotation(AnnotatedMethod annotatedMethod) {
        return this._primary.hasAnyGetterAnnotation(annotatedMethod) || this._secondary.hasAnyGetterAnnotation(annotatedMethod);
    }

    public boolean hasCreatorAnnotation(Annotated annotated) {
        return this._primary.hasCreatorAnnotation(annotated) || this._secondary.hasCreatorAnnotation(annotated);
    }

    @Deprecated
    public String findDeserializationName(AnnotatedMethod annotatedMethod) {
        String findDeserializationName = this._primary.findDeserializationName(annotatedMethod);
        if (findDeserializationName == null) {
            return this._secondary.findDeserializationName(annotatedMethod);
        }
        if (findDeserializationName.length() == 0) {
            String findDeserializationName2 = this._secondary.findDeserializationName(annotatedMethod);
            if (findDeserializationName2 != null) {
                return findDeserializationName2;
            }
        }
        return findDeserializationName;
    }

    @Deprecated
    public String findDeserializationName(AnnotatedField annotatedField) {
        String findDeserializationName = this._primary.findDeserializationName(annotatedField);
        if (findDeserializationName == null) {
            return this._secondary.findDeserializationName(annotatedField);
        }
        if (findDeserializationName.length() == 0) {
            String findDeserializationName2 = this._secondary.findDeserializationName(annotatedField);
            if (findDeserializationName2 != null) {
                return findDeserializationName2;
            }
        }
        return findDeserializationName;
    }

    @Deprecated
    public String findDeserializationName(AnnotatedParameter annotatedParameter) {
        String findDeserializationName = this._primary.findDeserializationName(annotatedParameter);
        if (findDeserializationName == null) {
            return this._secondary.findDeserializationName(annotatedParameter);
        }
        return findDeserializationName;
    }

    @Deprecated
    public String findSerializationName(AnnotatedMethod annotatedMethod) {
        String findSerializationName = this._primary.findSerializationName(annotatedMethod);
        if (findSerializationName == null) {
            return this._secondary.findSerializationName(annotatedMethod);
        }
        if (findSerializationName.length() == 0) {
            String findSerializationName2 = this._secondary.findSerializationName(annotatedMethod);
            if (findSerializationName2 != null) {
                return findSerializationName2;
            }
        }
        return findSerializationName;
    }

    @Deprecated
    public String findSerializationName(AnnotatedField annotatedField) {
        String findSerializationName = this._primary.findSerializationName(annotatedField);
        if (findSerializationName == null) {
            return this._secondary.findSerializationName(annotatedField);
        }
        if (findSerializationName.length() == 0) {
            String findSerializationName2 = this._secondary.findSerializationName(annotatedField);
            if (findSerializationName2 != null) {
                return findSerializationName2;
            }
        }
        return findSerializationName;
    }
}