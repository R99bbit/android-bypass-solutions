package com.fasterxml.jackson.databind.util;

import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.PropertyMetadata;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.introspect.AnnotatedField;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.introspect.AnnotatedMethod;
import com.fasterxml.jackson.databind.introspect.AnnotatedParameter;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;

public class SimpleBeanPropertyDefinition extends BeanPropertyDefinition {
    protected final AnnotationIntrospector _introspector;
    protected final AnnotatedMember _member;
    protected final String _name;

    @Deprecated
    public SimpleBeanPropertyDefinition(AnnotatedMember annotatedMember) {
        this(annotatedMember, annotatedMember.getName(), null);
    }

    @Deprecated
    public SimpleBeanPropertyDefinition(AnnotatedMember annotatedMember, String str) {
        this(annotatedMember, str, null);
    }

    private SimpleBeanPropertyDefinition(AnnotatedMember annotatedMember, String str, AnnotationIntrospector annotationIntrospector) {
        this._introspector = annotationIntrospector;
        this._member = annotatedMember;
        this._name = str;
    }

    public static SimpleBeanPropertyDefinition construct(MapperConfig<?> mapperConfig, AnnotatedMember annotatedMember) {
        return new SimpleBeanPropertyDefinition(annotatedMember, annotatedMember.getName(), mapperConfig == null ? null : mapperConfig.getAnnotationIntrospector());
    }

    public static SimpleBeanPropertyDefinition construct(MapperConfig<?> mapperConfig, AnnotatedMember annotatedMember, String str) {
        return new SimpleBeanPropertyDefinition(annotatedMember, str, mapperConfig == null ? null : mapperConfig.getAnnotationIntrospector());
    }

    @Deprecated
    public SimpleBeanPropertyDefinition withName(String str) {
        return withSimpleName(str);
    }

    public SimpleBeanPropertyDefinition withSimpleName(String str) {
        return this._name.equals(str) ? this : new SimpleBeanPropertyDefinition(this._member, str, this._introspector);
    }

    public SimpleBeanPropertyDefinition withName(PropertyName propertyName) {
        return withSimpleName(propertyName.getSimpleName());
    }

    public String getName() {
        return this._name;
    }

    public PropertyName getFullName() {
        return new PropertyName(this._name);
    }

    public String getInternalName() {
        return getName();
    }

    public PropertyName getWrapperName() {
        if (this._introspector == null) {
            return null;
        }
        return this._introspector.findWrapperName(this._member);
    }

    public boolean isExplicitlyIncluded() {
        return false;
    }

    public PropertyMetadata getMetadata() {
        return PropertyMetadata.STD_OPTIONAL;
    }

    public boolean hasGetter() {
        return getGetter() != null;
    }

    public boolean hasSetter() {
        return getSetter() != null;
    }

    public boolean hasField() {
        return this._member instanceof AnnotatedField;
    }

    public boolean hasConstructorParameter() {
        return this._member instanceof AnnotatedParameter;
    }

    public AnnotatedMethod getGetter() {
        if (!(this._member instanceof AnnotatedMethod) || ((AnnotatedMethod) this._member).getParameterCount() != 0) {
            return null;
        }
        return (AnnotatedMethod) this._member;
    }

    public AnnotatedMethod getSetter() {
        if (!(this._member instanceof AnnotatedMethod) || ((AnnotatedMethod) this._member).getParameterCount() != 1) {
            return null;
        }
        return (AnnotatedMethod) this._member;
    }

    public AnnotatedField getField() {
        if (this._member instanceof AnnotatedField) {
            return (AnnotatedField) this._member;
        }
        return null;
    }

    public AnnotatedParameter getConstructorParameter() {
        if (this._member instanceof AnnotatedParameter) {
            return (AnnotatedParameter) this._member;
        }
        return null;
    }

    public AnnotatedMember getAccessor() {
        AnnotatedMethod getter = getGetter();
        if (getter == null) {
            return getField();
        }
        return getter;
    }

    public AnnotatedMember getMutator() {
        AnnotatedParameter constructorParameter = getConstructorParameter();
        if (constructorParameter != null) {
            return constructorParameter;
        }
        AnnotatedMethod setter = getSetter();
        if (setter == null) {
            return getField();
        }
        return setter;
    }

    public AnnotatedMember getNonConstructorMutator() {
        AnnotatedMethod setter = getSetter();
        if (setter == null) {
            return getField();
        }
        return setter;
    }

    public AnnotatedMember getPrimaryMember() {
        return this._member;
    }
}