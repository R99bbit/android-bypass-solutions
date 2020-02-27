package com.fasterxml.jackson.databind.introspect;

import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.AnnotationIntrospector.ReferenceProperty;
import com.fasterxml.jackson.databind.PropertyMetadata;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.util.BeanUtil;

public class POJOPropertyBuilder extends BeanPropertyDefinition implements Comparable<POJOPropertyBuilder> {
    protected final AnnotationIntrospector _annotationIntrospector;
    protected Linked<AnnotatedParameter> _ctorParameters;
    protected Linked<AnnotatedField> _fields;
    protected final boolean _forSerialization;
    protected Linked<AnnotatedMethod> _getters;
    protected final PropertyName _internalName;
    protected final PropertyName _name;
    protected Linked<AnnotatedMethod> _setters;

    private static final class Linked<T> {
        public final String explicitName;
        public final boolean isMarkedIgnored;
        public final boolean isVisible;
        public final Linked<T> next;
        public final T value;

        public Linked(T t, Linked<T> linked, String str, boolean z, boolean z2) {
            this.value = t;
            this.next = linked;
            if (str == null) {
                this.explicitName = null;
            } else {
                this.explicitName = str.length() == 0 ? null : str;
            }
            this.isVisible = z;
            this.isMarkedIgnored = z2;
        }

        public Linked<T> withValue(T t) {
            if (t == this.value) {
                return this;
            }
            return new Linked(t, this.next, this.explicitName, this.isVisible, this.isMarkedIgnored);
        }

        public Linked<T> withNext(Linked<T> linked) {
            if (linked == this.next) {
                return this;
            }
            return new Linked(this.value, linked, this.explicitName, this.isVisible, this.isMarkedIgnored);
        }

        public Linked<T> withoutIgnored() {
            if (!this.isMarkedIgnored) {
                if (this.next != null) {
                    Linked<T> withoutIgnored = this.next.withoutIgnored();
                    if (withoutIgnored != this.next) {
                        return withNext(withoutIgnored);
                    }
                }
                return this;
            } else if (this.next == null) {
                return null;
            } else {
                return this.next.withoutIgnored();
            }
        }

        public Linked<T> withoutNonVisible() {
            Linked<T> withoutNonVisible = this.next == null ? null : this.next.withoutNonVisible();
            return this.isVisible ? withNext(withoutNonVisible) : withoutNonVisible;
        }

        /* access modifiers changed from: private */
        public Linked<T> append(Linked<T> linked) {
            if (this.next == null) {
                return withNext(linked);
            }
            return withNext(this.next.append(linked));
        }

        public Linked<T> trimByVisibility() {
            if (this.next == null) {
                return this;
            }
            Linked<T> trimByVisibility = this.next.trimByVisibility();
            if (this.explicitName != null) {
                if (trimByVisibility.explicitName == null) {
                    return withNext(null);
                }
                return withNext(trimByVisibility);
            } else if (trimByVisibility.explicitName != null) {
                return trimByVisibility;
            } else {
                if (this.isVisible == trimByVisibility.isVisible) {
                    return withNext(trimByVisibility);
                }
                return this.isVisible ? withNext(null) : trimByVisibility;
            }
        }

        public String toString() {
            String str = this.value.toString() + "[visible=" + this.isVisible + "]";
            if (this.next != null) {
                return str + ", " + this.next.toString();
            }
            return str;
        }
    }

    private interface WithMember<T> {
        T withMember(AnnotatedMember annotatedMember);
    }

    public POJOPropertyBuilder(PropertyName propertyName, AnnotationIntrospector annotationIntrospector, boolean z) {
        this._internalName = propertyName;
        this._name = propertyName;
        this._annotationIntrospector = annotationIntrospector;
        this._forSerialization = z;
    }

    @Deprecated
    public POJOPropertyBuilder(String str, AnnotationIntrospector annotationIntrospector, boolean z) {
        this(new PropertyName(str), annotationIntrospector, z);
    }

    public POJOPropertyBuilder(POJOPropertyBuilder pOJOPropertyBuilder, PropertyName propertyName) {
        this._internalName = pOJOPropertyBuilder._internalName;
        this._name = propertyName;
        this._annotationIntrospector = pOJOPropertyBuilder._annotationIntrospector;
        this._fields = pOJOPropertyBuilder._fields;
        this._ctorParameters = pOJOPropertyBuilder._ctorParameters;
        this._getters = pOJOPropertyBuilder._getters;
        this._setters = pOJOPropertyBuilder._setters;
        this._forSerialization = pOJOPropertyBuilder._forSerialization;
    }

    @Deprecated
    public POJOPropertyBuilder withName(String str) {
        return withSimpleName(str);
    }

    public POJOPropertyBuilder withName(PropertyName propertyName) {
        return new POJOPropertyBuilder(this, propertyName);
    }

    public POJOPropertyBuilder withSimpleName(String str) {
        PropertyName withSimpleName = this._name.withSimpleName(str);
        return withSimpleName == this._name ? this : new POJOPropertyBuilder(this, withSimpleName);
    }

    public int compareTo(POJOPropertyBuilder pOJOPropertyBuilder) {
        if (this._ctorParameters != null) {
            if (pOJOPropertyBuilder._ctorParameters == null) {
                return -1;
            }
        } else if (pOJOPropertyBuilder._ctorParameters != null) {
            return 1;
        }
        return getName().compareTo(pOJOPropertyBuilder.getName());
    }

    public String getName() {
        if (this._name == null) {
            return null;
        }
        return this._name.getSimpleName();
    }

    public PropertyName getFullName() {
        return this._name;
    }

    public String getInternalName() {
        return this._internalName.getSimpleName();
    }

    public PropertyName getWrapperName() {
        AnnotatedMember primaryMember = getPrimaryMember();
        if (primaryMember == null || this._annotationIntrospector == null) {
            return null;
        }
        return this._annotationIntrospector.findWrapperName(primaryMember);
    }

    public boolean isExplicitlyIncluded() {
        return _anyExplicitNames(this._fields) || _anyExplicitNames(this._getters) || _anyExplicitNames(this._setters) || _anyExplicitNames(this._ctorParameters);
    }

    public boolean hasGetter() {
        return this._getters != null;
    }

    public boolean hasSetter() {
        return this._setters != null;
    }

    public boolean hasField() {
        return this._fields != null;
    }

    public boolean hasConstructorParameter() {
        return this._ctorParameters != null;
    }

    public boolean couldSerialize() {
        return (this._getters == null && this._fields == null) ? false : true;
    }

    public AnnotatedMethod getGetter() {
        boolean z;
        boolean z2;
        if (this._getters == null) {
            return null;
        }
        Linked<T> linked = this._getters.next;
        AnnotatedMethod annotatedMethod = (AnnotatedMethod) this._getters.value;
        while (linked != null) {
            AnnotatedMethod annotatedMethod2 = (AnnotatedMethod) linked.value;
            Class<?> declaringClass = annotatedMethod.getDeclaringClass();
            Class<?> declaringClass2 = annotatedMethod2.getDeclaringClass();
            if (declaringClass != declaringClass2) {
                if (declaringClass.isAssignableFrom(declaringClass2)) {
                    continue;
                } else if (declaringClass2.isAssignableFrom(declaringClass)) {
                    annotatedMethod2 = annotatedMethod;
                }
                linked = linked.next;
                annotatedMethod = annotatedMethod2;
            }
            if (BeanUtil.okNameForIsGetter(annotatedMethod, annotatedMethod.getName()) != null) {
                z = true;
            } else {
                z = false;
            }
            if (BeanUtil.okNameForIsGetter(annotatedMethod2, annotatedMethod2.getName()) != null) {
                z2 = true;
            } else {
                z2 = false;
            }
            if (z != z2) {
                if (!z) {
                    annotatedMethod2 = annotatedMethod;
                }
                linked = linked.next;
                annotatedMethod = annotatedMethod2;
            } else {
                throw new IllegalArgumentException("Conflicting getter definitions for property \"" + getName() + "\": " + annotatedMethod.getFullName() + " vs " + annotatedMethod2.getFullName());
            }
        }
        return annotatedMethod;
    }

    public AnnotatedMethod getSetter() {
        if (this._setters == null) {
            return null;
        }
        Linked<T> linked = this._setters.next;
        AnnotatedMethod annotatedMethod = (AnnotatedMethod) this._setters.value;
        while (linked != null) {
            AnnotatedMethod annotatedMethod2 = (AnnotatedMethod) linked.value;
            Class<?> declaringClass = annotatedMethod.getDeclaringClass();
            Class<?> declaringClass2 = annotatedMethod2.getDeclaringClass();
            if (declaringClass != declaringClass2) {
                if (!declaringClass.isAssignableFrom(declaringClass2)) {
                    if (declaringClass2.isAssignableFrom(declaringClass)) {
                        annotatedMethod2 = annotatedMethod;
                    }
                }
                linked = linked.next;
                annotatedMethod = annotatedMethod2;
            }
            throw new IllegalArgumentException("Conflicting setter definitions for property \"" + getName() + "\": " + annotatedMethod.getFullName() + " vs " + annotatedMethod2.getFullName());
        }
        return annotatedMethod;
    }

    public AnnotatedField getField() {
        if (this._fields == null) {
            return null;
        }
        Linked<T> linked = this._fields.next;
        AnnotatedField annotatedField = (AnnotatedField) this._fields.value;
        while (linked != null) {
            AnnotatedField annotatedField2 = (AnnotatedField) linked.value;
            Class<?> declaringClass = annotatedField.getDeclaringClass();
            Class<?> declaringClass2 = annotatedField2.getDeclaringClass();
            if (declaringClass != declaringClass2) {
                if (!declaringClass.isAssignableFrom(declaringClass2)) {
                    if (declaringClass2.isAssignableFrom(declaringClass)) {
                        annotatedField2 = annotatedField;
                    }
                }
                linked = linked.next;
                annotatedField = annotatedField2;
            }
            throw new IllegalArgumentException("Multiple fields representing property \"" + getName() + "\": " + annotatedField.getFullName() + " vs " + annotatedField2.getFullName());
        }
        return annotatedField;
    }

    public AnnotatedParameter getConstructorParameter() {
        if (this._ctorParameters == null) {
            return null;
        }
        Linked linked = this._ctorParameters;
        while (true) {
            Linked linked2 = linked;
            if (((AnnotatedParameter) linked2.value).getOwner() instanceof AnnotatedConstructor) {
                return (AnnotatedParameter) linked2.value;
            }
            linked = linked2.next;
            if (linked == null) {
                return (AnnotatedParameter) this._ctorParameters.value;
            }
        }
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
        if (this._forSerialization) {
            return getAccessor();
        }
        return getMutator();
    }

    public Class<?>[] findViews() {
        return (Class[]) fromMemberAnnotations(new WithMember<Class<?>[]>() {
            public Class<?>[] withMember(AnnotatedMember annotatedMember) {
                return POJOPropertyBuilder.this._annotationIntrospector.findViews(annotatedMember);
            }
        });
    }

    public ReferenceProperty findReferenceType() {
        return (ReferenceProperty) fromMemberAnnotations(new WithMember<ReferenceProperty>() {
            public ReferenceProperty withMember(AnnotatedMember annotatedMember) {
                return POJOPropertyBuilder.this._annotationIntrospector.findReferenceType(annotatedMember);
            }
        });
    }

    public boolean isTypeId() {
        Boolean bool = (Boolean) fromMemberAnnotations(new WithMember<Boolean>() {
            public Boolean withMember(AnnotatedMember annotatedMember) {
                return POJOPropertyBuilder.this._annotationIntrospector.isTypeId(annotatedMember);
            }
        });
        return bool != null && bool.booleanValue();
    }

    public PropertyMetadata getMetadata() {
        Boolean _findRequired = _findRequired();
        String _findDescription = _findDescription();
        if (_findRequired == null) {
            return _findDescription == null ? PropertyMetadata.STD_REQUIRED_OR_OPTIONAL : PropertyMetadata.STD_REQUIRED_OR_OPTIONAL.withDescription(_findDescription);
        }
        return PropertyMetadata.construct(_findRequired.booleanValue(), _findDescription());
    }

    /* access modifiers changed from: protected */
    public Boolean _findRequired() {
        return (Boolean) fromMemberAnnotations(new WithMember<Boolean>() {
            public Boolean withMember(AnnotatedMember annotatedMember) {
                return POJOPropertyBuilder.this._annotationIntrospector.hasRequiredMarker(annotatedMember);
            }
        });
    }

    /* access modifiers changed from: protected */
    public String _findDescription() {
        return (String) fromMemberAnnotations(new WithMember<String>() {
            public String withMember(AnnotatedMember annotatedMember) {
                return POJOPropertyBuilder.this._annotationIntrospector.findPropertyDescription(annotatedMember);
            }
        });
    }

    public ObjectIdInfo findObjectIdInfo() {
        return (ObjectIdInfo) fromMemberAnnotations(new WithMember<ObjectIdInfo>() {
            public ObjectIdInfo withMember(AnnotatedMember annotatedMember) {
                ObjectIdInfo findObjectIdInfo = POJOPropertyBuilder.this._annotationIntrospector.findObjectIdInfo(annotatedMember);
                if (findObjectIdInfo != null) {
                    return POJOPropertyBuilder.this._annotationIntrospector.findObjectReferenceInfo(annotatedMember, findObjectIdInfo);
                }
                return findObjectIdInfo;
            }
        });
    }

    public void addField(AnnotatedField annotatedField, String str, boolean z, boolean z2) {
        this._fields = new Linked<>(annotatedField, this._fields, str, z, z2);
    }

    public void addCtor(AnnotatedParameter annotatedParameter, String str, boolean z, boolean z2) {
        this._ctorParameters = new Linked<>(annotatedParameter, this._ctorParameters, str, z, z2);
    }

    public void addGetter(AnnotatedMethod annotatedMethod, String str, boolean z, boolean z2) {
        this._getters = new Linked<>(annotatedMethod, this._getters, str, z, z2);
    }

    public void addSetter(AnnotatedMethod annotatedMethod, String str, boolean z, boolean z2) {
        this._setters = new Linked<>(annotatedMethod, this._setters, str, z, z2);
    }

    public void addAll(POJOPropertyBuilder pOJOPropertyBuilder) {
        this._fields = merge(this._fields, pOJOPropertyBuilder._fields);
        this._ctorParameters = merge(this._ctorParameters, pOJOPropertyBuilder._ctorParameters);
        this._getters = merge(this._getters, pOJOPropertyBuilder._getters);
        this._setters = merge(this._setters, pOJOPropertyBuilder._setters);
    }

    private static <T> Linked<T> merge(Linked<T> linked, Linked<T> linked2) {
        if (linked == null) {
            return linked2;
        }
        if (linked2 == null) {
            return linked;
        }
        return linked.append(linked2);
    }

    public void removeIgnored() {
        this._fields = _removeIgnored(this._fields);
        this._getters = _removeIgnored(this._getters);
        this._setters = _removeIgnored(this._setters);
        this._ctorParameters = _removeIgnored(this._ctorParameters);
    }

    @Deprecated
    public void removeNonVisible() {
        removeNonVisible(false);
    }

    public void removeNonVisible(boolean z) {
        this._getters = _removeNonVisible(this._getters);
        this._ctorParameters = _removeNonVisible(this._ctorParameters);
        if (z || this._getters == null) {
            this._fields = _removeNonVisible(this._fields);
            this._setters = _removeNonVisible(this._setters);
        }
    }

    public void trimByVisibility() {
        this._fields = _trimByVisibility(this._fields);
        this._getters = _trimByVisibility(this._getters);
        this._setters = _trimByVisibility(this._setters);
        this._ctorParameters = _trimByVisibility(this._ctorParameters);
    }

    public void mergeAnnotations(boolean z) {
        if (z) {
            if (this._getters != null) {
                this._getters = this._getters.withValue(((AnnotatedMethod) this._getters.value).withAnnotations(_mergeAnnotations(0, this._getters, this._fields, this._ctorParameters, this._setters)));
            } else if (this._fields != null) {
                this._fields = this._fields.withValue(((AnnotatedField) this._fields.value).withAnnotations(_mergeAnnotations(0, this._fields, this._ctorParameters, this._setters)));
            }
        } else if (this._ctorParameters != null) {
            this._ctorParameters = this._ctorParameters.withValue(((AnnotatedParameter) this._ctorParameters.value).withAnnotations(_mergeAnnotations(0, this._ctorParameters, this._setters, this._fields, this._getters)));
        } else if (this._setters != null) {
            this._setters = this._setters.withValue(((AnnotatedMethod) this._setters.value).withAnnotations(_mergeAnnotations(0, this._setters, this._fields, this._getters)));
        } else if (this._fields != null) {
            this._fields = this._fields.withValue(((AnnotatedField) this._fields.value).withAnnotations(_mergeAnnotations(0, this._fields, this._getters)));
        }
    }

    private AnnotationMap _mergeAnnotations(int i, Linked<? extends AnnotatedMember>... linkedArr) {
        AnnotationMap allAnnotations = ((AnnotatedMember) linkedArr[i].value).getAllAnnotations();
        for (int i2 = i + 1; i2 < linkedArr.length; i2++) {
            if (linkedArr[i2] != null) {
                return AnnotationMap.merge(allAnnotations, _mergeAnnotations(i2, linkedArr));
            }
        }
        return allAnnotations;
    }

    private <T> Linked<T> _removeIgnored(Linked<T> linked) {
        return linked == null ? linked : linked.withoutIgnored();
    }

    private <T> Linked<T> _removeNonVisible(Linked<T> linked) {
        return linked == null ? linked : linked.withoutNonVisible();
    }

    private <T> Linked<T> _trimByVisibility(Linked<T> linked) {
        return linked == null ? linked : linked.trimByVisibility();
    }

    private <T> boolean _anyExplicitNames(Linked<T> linked) {
        while (linked != null) {
            if (linked.explicitName != null && linked.explicitName.length() > 0) {
                return true;
            }
            linked = linked.next;
        }
        return false;
    }

    public boolean anyVisible() {
        return _anyVisible(this._fields) || _anyVisible(this._getters) || _anyVisible(this._setters) || _anyVisible(this._ctorParameters);
    }

    private <T> boolean _anyVisible(Linked<T> linked) {
        while (linked != null) {
            if (linked.isVisible) {
                return true;
            }
            linked = linked.next;
        }
        return false;
    }

    public boolean anyIgnorals() {
        return _anyIgnorals(this._fields) || _anyIgnorals(this._getters) || _anyIgnorals(this._setters) || _anyIgnorals(this._ctorParameters);
    }

    private <T> boolean _anyIgnorals(Linked<T> linked) {
        while (linked != null) {
            if (linked.isMarkedIgnored) {
                return true;
            }
            linked = linked.next;
        }
        return false;
    }

    public String findNewName() {
        Linked<? extends AnnotatedMember> findRenamed = findRenamed(this._ctorParameters, findRenamed(this._setters, findRenamed(this._getters, findRenamed(this._fields, null))));
        if (findRenamed == null) {
            return null;
        }
        return findRenamed.explicitName;
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=com.fasterxml.jackson.databind.introspect.POJOPropertyBuilder$Linked<? extends com.fasterxml.jackson.databind.introspect.AnnotatedMember>, code=com.fasterxml.jackson.databind.introspect.POJOPropertyBuilder$Linked, for r6v0, types: [com.fasterxml.jackson.databind.introspect.POJOPropertyBuilder$Linked<? extends com.fasterxml.jackson.databind.introspect.AnnotatedMember>, com.fasterxml.jackson.databind.introspect.POJOPropertyBuilder$Linked] */
    /* JADX WARNING: Incorrect type for immutable var: ssa=com.fasterxml.jackson.databind.introspect.POJOPropertyBuilder$Linked<? extends com.fasterxml.jackson.databind.introspect.AnnotatedMember>, code=com.fasterxml.jackson.databind.introspect.POJOPropertyBuilder$Linked, for r7v0, types: [com.fasterxml.jackson.databind.introspect.POJOPropertyBuilder$Linked<? extends com.fasterxml.jackson.databind.introspect.AnnotatedMember>, com.fasterxml.jackson.databind.introspect.POJOPropertyBuilder$Linked] */
    private Linked<? extends AnnotatedMember> findRenamed(Linked linked, Linked linked2) {
        Linked linked3 = linked2;
        for (Linked linked4 = linked; linked4 != null; linked4 = linked4.next) {
            String str = linked4.explicitName;
            if (str != null && !str.equals(this._name)) {
                if (linked3 == null) {
                    linked3 = linked4;
                } else if (!str.equals(linked3.explicitName)) {
                    throw new IllegalStateException("Conflicting property name definitions: '" + linked3.explicitName + "' (for " + linked3.value + ") vs '" + linked4.explicitName + "' (for " + linked4.value + ")");
                }
            }
        }
        return linked3;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[Property '").append(this._name).append("'; ctors: ").append(this._ctorParameters).append(", field(s): ").append(this._fields).append(", getter(s): ").append(this._getters).append(", setter(s): ").append(this._setters);
        sb.append("]");
        return sb.toString();
    }

    /* access modifiers changed from: protected */
    public <T> T fromMemberAnnotations(WithMember<T> withMember) {
        T t = null;
        if (this._annotationIntrospector == null) {
            return null;
        }
        if (!this._forSerialization) {
            if (this._ctorParameters != null) {
                t = withMember.withMember((AnnotatedMember) this._ctorParameters.value);
            }
            if (t == null && this._setters != null) {
                t = withMember.withMember((AnnotatedMember) this._setters.value);
            }
        } else if (this._getters != null) {
            t = withMember.withMember((AnnotatedMember) this._getters.value);
        }
        if (t != null || this._fields == null) {
            return t;
        }
        return withMember.withMember((AnnotatedMember) this._fields.value);
    }
}