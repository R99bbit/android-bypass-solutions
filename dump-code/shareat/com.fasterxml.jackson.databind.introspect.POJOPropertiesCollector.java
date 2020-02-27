package com.fasterxml.jackson.databind.introspect;

import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.cfg.HandlerInstantiator;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.util.BeanUtil;
import com.fasterxml.jackson.databind.util.ClassUtil;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

public class POJOPropertiesCollector {
    protected final AnnotationIntrospector _annotationIntrospector;
    protected LinkedList<AnnotatedMember> _anyGetters = null;
    protected LinkedList<AnnotatedMethod> _anySetters = null;
    protected final AnnotatedClass _classDef;
    protected final MapperConfig<?> _config;
    protected LinkedList<POJOPropertyBuilder> _creatorProperties = null;
    protected final boolean _forSerialization;
    protected HashSet<String> _ignoredPropertyNames;
    protected LinkedHashMap<Object, AnnotatedMember> _injectables;
    protected LinkedList<AnnotatedMethod> _jsonValueGetters = null;
    protected final String _mutatorPrefix;
    protected final LinkedHashMap<String, POJOPropertyBuilder> _properties = new LinkedHashMap<>();
    protected final JavaType _type;
    protected final VisibilityChecker<?> _visibilityChecker;

    protected POJOPropertiesCollector(MapperConfig<?> mapperConfig, boolean z, JavaType javaType, AnnotatedClass annotatedClass, String str) {
        AnnotationIntrospector annotationIntrospector = null;
        this._config = mapperConfig;
        this._forSerialization = z;
        this._type = javaType;
        this._classDef = annotatedClass;
        this._mutatorPrefix = str == null ? "set" : str;
        this._annotationIntrospector = mapperConfig.isAnnotationProcessingEnabled() ? this._config.getAnnotationIntrospector() : annotationIntrospector;
        if (this._annotationIntrospector == null) {
            this._visibilityChecker = this._config.getDefaultVisibilityChecker();
        } else {
            this._visibilityChecker = this._annotationIntrospector.findAutoDetectVisibility(annotatedClass, this._config.getDefaultVisibilityChecker());
        }
    }

    public MapperConfig<?> getConfig() {
        return this._config;
    }

    public JavaType getType() {
        return this._type;
    }

    public AnnotatedClass getClassDef() {
        return this._classDef;
    }

    public AnnotationIntrospector getAnnotationIntrospector() {
        return this._annotationIntrospector;
    }

    public List<BeanPropertyDefinition> getProperties() {
        return new ArrayList(this._properties.values());
    }

    public Map<Object, AnnotatedMember> getInjectables() {
        return this._injectables;
    }

    public AnnotatedMethod getJsonValueMethod() {
        if (this._jsonValueGetters == null) {
            return null;
        }
        if (this._jsonValueGetters.size() > 1) {
            reportProblem("Multiple value properties defined (" + this._jsonValueGetters.get(0) + " vs " + this._jsonValueGetters.get(1) + ")");
        }
        return this._jsonValueGetters.get(0);
    }

    public AnnotatedMember getAnyGetter() {
        if (this._anyGetters == null) {
            return null;
        }
        if (this._anyGetters.size() > 1) {
            reportProblem("Multiple 'any-getters' defined (" + this._anyGetters.get(0) + " vs " + this._anyGetters.get(1) + ")");
        }
        return this._anyGetters.getFirst();
    }

    public AnnotatedMethod getAnySetterMethod() {
        if (this._anySetters == null) {
            return null;
        }
        if (this._anySetters.size() > 1) {
            reportProblem("Multiple 'any-setters' defined (" + this._anySetters.get(0) + " vs " + this._anySetters.get(1) + ")");
        }
        return this._anySetters.getFirst();
    }

    public Set<String> getIgnoredPropertyNames() {
        return this._ignoredPropertyNames;
    }

    public ObjectIdInfo getObjectIdInfo() {
        if (this._annotationIntrospector == null) {
            return null;
        }
        ObjectIdInfo findObjectIdInfo = this._annotationIntrospector.findObjectIdInfo(this._classDef);
        if (findObjectIdInfo != null) {
            return this._annotationIntrospector.findObjectReferenceInfo(this._classDef, findObjectIdInfo);
        }
        return findObjectIdInfo;
    }

    public Class<?> findPOJOBuilderClass() {
        return this._annotationIntrospector.findPOJOBuilder(this._classDef);
    }

    /* access modifiers changed from: protected */
    public Map<String, POJOPropertyBuilder> getPropertyMap() {
        return this._properties;
    }

    public POJOPropertiesCollector collect() {
        this._properties.clear();
        _addFields();
        _addMethods();
        _addCreators();
        _addInjectables();
        _removeUnwantedProperties();
        _renameProperties();
        PropertyNamingStrategy _findNamingStrategy = _findNamingStrategy();
        if (_findNamingStrategy != null) {
            _renameUsing(_findNamingStrategy);
        }
        for (POJOPropertyBuilder trimByVisibility : this._properties.values()) {
            trimByVisibility.trimByVisibility();
        }
        for (POJOPropertyBuilder mergeAnnotations : this._properties.values()) {
            mergeAnnotations.mergeAnnotations(this._forSerialization);
        }
        if (this._config.isEnabled(MapperFeature.USE_WRAPPER_NAME_AS_PROPERTY_NAME)) {
            _renameWithWrappers();
        }
        _sortProperties();
        return this;
    }

    /* access modifiers changed from: protected */
    public void _sortProperties() {
        boolean booleanValue;
        Map linkedHashMap;
        Collection<POJOPropertyBuilder> collection;
        String str;
        AnnotationIntrospector annotationIntrospector = this._annotationIntrospector;
        Boolean findSerializationSortAlphabetically = annotationIntrospector == null ? null : annotationIntrospector.findSerializationSortAlphabetically(this._classDef);
        if (findSerializationSortAlphabetically == null) {
            booleanValue = this._config.shouldSortPropertiesAlphabetically();
        } else {
            booleanValue = findSerializationSortAlphabetically.booleanValue();
        }
        String[] findSerializationPropertyOrder = annotationIntrospector == null ? null : annotationIntrospector.findSerializationPropertyOrder(this._classDef);
        if (booleanValue || this._creatorProperties != null || findSerializationPropertyOrder != null) {
            int size = this._properties.size();
            if (booleanValue) {
                linkedHashMap = new TreeMap();
            } else {
                linkedHashMap = new LinkedHashMap(size + size);
            }
            for (POJOPropertyBuilder next : this._properties.values()) {
                linkedHashMap.put(next.getName(), next);
            }
            LinkedHashMap linkedHashMap2 = new LinkedHashMap(size + size);
            if (findSerializationPropertyOrder != null) {
                for (String str2 : findSerializationPropertyOrder) {
                    POJOPropertyBuilder pOJOPropertyBuilder = (POJOPropertyBuilder) linkedHashMap.get(str2);
                    if (pOJOPropertyBuilder == null) {
                        Iterator<POJOPropertyBuilder> it = this._properties.values().iterator();
                        while (true) {
                            if (!it.hasNext()) {
                                break;
                            }
                            POJOPropertyBuilder next2 = it.next();
                            if (str2.equals(next2.getInternalName())) {
                                POJOPropertyBuilder pOJOPropertyBuilder2 = next2;
                                str = next2.getName();
                                pOJOPropertyBuilder = pOJOPropertyBuilder2;
                                break;
                            }
                        }
                    }
                    str = str2;
                    if (pOJOPropertyBuilder != null) {
                        linkedHashMap2.put(str, pOJOPropertyBuilder);
                    }
                }
            }
            if (this._creatorProperties != null) {
                if (booleanValue) {
                    TreeMap treeMap = new TreeMap();
                    Iterator it2 = this._creatorProperties.iterator();
                    while (it2.hasNext()) {
                        POJOPropertyBuilder pOJOPropertyBuilder3 = (POJOPropertyBuilder) it2.next();
                        treeMap.put(pOJOPropertyBuilder3.getName(), pOJOPropertyBuilder3);
                    }
                    collection = treeMap.values();
                } else {
                    collection = this._creatorProperties;
                }
                for (POJOPropertyBuilder pOJOPropertyBuilder4 : collection) {
                    linkedHashMap2.put(pOJOPropertyBuilder4.getName(), pOJOPropertyBuilder4);
                }
            }
            linkedHashMap2.putAll(linkedHashMap);
            this._properties.clear();
            this._properties.putAll(linkedHashMap2);
        }
    }

    /* access modifiers changed from: protected */
    public void _addFields() {
        String simpleName;
        String str;
        boolean z;
        boolean z2;
        boolean z3;
        AnnotationIntrospector annotationIntrospector = this._annotationIntrospector;
        boolean z4 = !this._forSerialization && !this._config.isEnabled(MapperFeature.ALLOW_FINAL_FIELDS_AS_MUTATORS);
        for (AnnotatedField next : this._classDef.fields()) {
            String name = next.getName();
            if (annotationIntrospector == null) {
                simpleName = null;
            } else if (this._forSerialization) {
                PropertyName findNameForSerialization = annotationIntrospector.findNameForSerialization(next);
                simpleName = findNameForSerialization == null ? null : findNameForSerialization.getSimpleName();
            } else {
                PropertyName findNameForDeserialization = annotationIntrospector.findNameForDeserialization(next);
                simpleName = findNameForDeserialization == null ? null : findNameForDeserialization.getSimpleName();
            }
            if ("".equals(simpleName)) {
                str = name;
            } else {
                str = simpleName;
            }
            if (str != null) {
                z = true;
            } else {
                z = false;
            }
            if (!z) {
                z2 = this._visibilityChecker.isFieldVisible(next);
            } else {
                z2 = z;
            }
            if (annotationIntrospector == null || !annotationIntrospector.hasIgnoreMarker(next)) {
                z3 = false;
            } else {
                z3 = true;
            }
            if (!z4 || str != null || z3 || !Modifier.isFinal(next.getModifiers())) {
                _property(name).addField(next, str, z2, z3);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void _addCreators() {
        AnnotationIntrospector annotationIntrospector = this._annotationIntrospector;
        if (annotationIntrospector != null) {
            for (AnnotatedConstructor next : this._classDef.getConstructors()) {
                if (this._creatorProperties == null) {
                    this._creatorProperties = new LinkedList<>();
                }
                int parameterCount = next.getParameterCount();
                for (int i = 0; i < parameterCount; i++) {
                    AnnotatedParameter parameter = next.getParameter(i);
                    PropertyName findNameForDeserialization = annotationIntrospector.findNameForDeserialization(parameter);
                    String simpleName = findNameForDeserialization == null ? null : findNameForDeserialization.getSimpleName();
                    if (simpleName != null) {
                        POJOPropertyBuilder _property = _property(simpleName);
                        _property.addCtor(parameter, simpleName, true, false);
                        this._creatorProperties.add(_property);
                    }
                }
            }
            for (AnnotatedMethod next2 : this._classDef.getStaticMethods()) {
                if (this._creatorProperties == null) {
                    this._creatorProperties = new LinkedList<>();
                }
                int parameterCount2 = next2.getParameterCount();
                for (int i2 = 0; i2 < parameterCount2; i2++) {
                    AnnotatedParameter parameter2 = next2.getParameter(i2);
                    PropertyName findNameForDeserialization2 = annotationIntrospector.findNameForDeserialization(parameter2);
                    String simpleName2 = findNameForDeserialization2 == null ? null : findNameForDeserialization2.getSimpleName();
                    if (simpleName2 != null) {
                        POJOPropertyBuilder _property2 = _property(simpleName2);
                        _property2.addCtor(parameter2, simpleName2, true, false);
                        this._creatorProperties.add(_property2);
                    }
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public void _addMethods() {
        AnnotationIntrospector annotationIntrospector = this._annotationIntrospector;
        for (AnnotatedMethod next : this._classDef.memberMethods()) {
            int parameterCount = next.getParameterCount();
            if (parameterCount == 0) {
                _addGetterMethod(next, annotationIntrospector);
            } else if (parameterCount == 1) {
                _addSetterMethod(next, annotationIntrospector);
            } else if (parameterCount == 2 && annotationIntrospector != null && annotationIntrospector.hasAnySetterAnnotation(next)) {
                if (this._anySetters == null) {
                    this._anySetters = new LinkedList<>();
                }
                this._anySetters.add(next);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void _addGetterMethod(AnnotatedMethod annotatedMethod, AnnotationIntrospector annotationIntrospector) {
        boolean z;
        String str;
        String str2 = null;
        if (annotationIntrospector != null) {
            if (annotationIntrospector.hasAnyGetterAnnotation(annotatedMethod)) {
                if (this._anyGetters == null) {
                    this._anyGetters = new LinkedList<>();
                }
                this._anyGetters.add(annotatedMethod);
                return;
            } else if (annotationIntrospector.hasAsValueAnnotation(annotatedMethod)) {
                if (this._jsonValueGetters == null) {
                    this._jsonValueGetters = new LinkedList<>();
                }
                this._jsonValueGetters.add(annotatedMethod);
                return;
            }
        }
        PropertyName findNameForSerialization = annotationIntrospector == null ? null : annotationIntrospector.findNameForSerialization(annotatedMethod);
        if (findNameForSerialization != null) {
            str2 = findNameForSerialization.getSimpleName();
        }
        if (str2 == null) {
            String okNameForRegularGetter = BeanUtil.okNameForRegularGetter(annotatedMethod, annotatedMethod.getName());
            if (okNameForRegularGetter == null) {
                String okNameForIsGetter = BeanUtil.okNameForIsGetter(annotatedMethod, annotatedMethod.getName());
                if (okNameForIsGetter != null) {
                    str = okNameForIsGetter;
                    z = this._visibilityChecker.isIsGetterVisible(annotatedMethod);
                } else {
                    return;
                }
            } else {
                str = okNameForRegularGetter;
                z = this._visibilityChecker.isGetterVisible(annotatedMethod);
            }
        } else {
            String okNameForGetter = BeanUtil.okNameForGetter(annotatedMethod);
            if (okNameForGetter == null) {
                okNameForGetter = annotatedMethod.getName();
            }
            if (str2.length() == 0) {
                str2 = okNameForGetter;
            }
            z = true;
            str = okNameForGetter;
        }
        _property(str).addGetter(annotatedMethod, str2, z, annotationIntrospector == null ? false : annotationIntrospector.hasIgnoreMarker(annotatedMethod));
    }

    /* access modifiers changed from: protected */
    public void _addSetterMethod(AnnotatedMethod annotatedMethod, AnnotationIntrospector annotationIntrospector) {
        boolean z;
        String str;
        String str2 = null;
        PropertyName findNameForDeserialization = annotationIntrospector == null ? null : annotationIntrospector.findNameForDeserialization(annotatedMethod);
        if (findNameForDeserialization != null) {
            str2 = findNameForDeserialization.getSimpleName();
        }
        if (str2 == null) {
            String okNameForMutator = BeanUtil.okNameForMutator(annotatedMethod, this._mutatorPrefix);
            if (okNameForMutator != null) {
                str = okNameForMutator;
                z = this._visibilityChecker.isSetterVisible(annotatedMethod);
            } else {
                return;
            }
        } else {
            String okNameForMutator2 = BeanUtil.okNameForMutator(annotatedMethod, this._mutatorPrefix);
            if (okNameForMutator2 == null) {
                okNameForMutator2 = annotatedMethod.getName();
            }
            if (str2.length() == 0) {
                str2 = okNameForMutator2;
            }
            z = true;
            str = okNameForMutator2;
        }
        _property(str).addSetter(annotatedMethod, str2, z, annotationIntrospector == null ? false : annotationIntrospector.hasIgnoreMarker(annotatedMethod));
    }

    /* access modifiers changed from: protected */
    public void _addInjectables() {
        AnnotationIntrospector annotationIntrospector = this._annotationIntrospector;
        if (annotationIntrospector != null) {
            for (AnnotatedField next : this._classDef.fields()) {
                _doAddInjectable(annotationIntrospector.findInjectableValueId(next), next);
            }
            for (AnnotatedMethod next2 : this._classDef.memberMethods()) {
                if (next2.getParameterCount() == 1) {
                    _doAddInjectable(annotationIntrospector.findInjectableValueId(next2), next2);
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public void _doAddInjectable(Object obj, AnnotatedMember annotatedMember) {
        if (obj != null) {
            if (this._injectables == null) {
                this._injectables = new LinkedHashMap<>();
            }
            if (((AnnotatedMember) this._injectables.put(obj, annotatedMember)) != null) {
                throw new IllegalArgumentException("Duplicate injectable value with id '" + String.valueOf(obj) + "' (of type " + obj.getClass().getName() + ")");
            }
        }
    }

    /* access modifiers changed from: protected */
    public void _removeUnwantedProperties() {
        boolean z;
        Iterator<Entry<String, POJOPropertyBuilder>> it = this._properties.entrySet().iterator();
        if (!this._config.isEnabled(MapperFeature.INFER_PROPERTY_MUTATORS)) {
            z = true;
        } else {
            z = false;
        }
        while (it.hasNext()) {
            POJOPropertyBuilder pOJOPropertyBuilder = (POJOPropertyBuilder) it.next().getValue();
            if (!pOJOPropertyBuilder.anyVisible()) {
                it.remove();
            } else {
                if (pOJOPropertyBuilder.anyIgnorals()) {
                    if (!pOJOPropertyBuilder.isExplicitlyIncluded()) {
                        it.remove();
                        _addIgnored(pOJOPropertyBuilder.getName());
                    } else {
                        pOJOPropertyBuilder.removeIgnored();
                        if (!this._forSerialization && !pOJOPropertyBuilder.couldDeserialize()) {
                            _addIgnored(pOJOPropertyBuilder.getName());
                        }
                    }
                }
                pOJOPropertyBuilder.removeNonVisible(z);
            }
        }
    }

    private void _addIgnored(String str) {
        if (!this._forSerialization) {
            if (this._ignoredPropertyNames == null) {
                this._ignoredPropertyNames = new HashSet<>();
            }
            this._ignoredPropertyNames.add(str);
        }
    }

    /* access modifiers changed from: protected */
    public void _renameProperties() {
        Iterator<Entry<String, POJOPropertyBuilder>> it = this._properties.entrySet().iterator();
        LinkedList linkedList = null;
        while (it.hasNext()) {
            POJOPropertyBuilder pOJOPropertyBuilder = (POJOPropertyBuilder) it.next().getValue();
            String findNewName = pOJOPropertyBuilder.findNewName();
            if (findNewName != null) {
                if (linkedList == null) {
                    linkedList = new LinkedList();
                }
                linkedList.add(pOJOPropertyBuilder.withSimpleName(findNewName));
                it.remove();
            }
        }
        if (linkedList != null) {
            Iterator it2 = linkedList.iterator();
            while (it2.hasNext()) {
                POJOPropertyBuilder pOJOPropertyBuilder2 = (POJOPropertyBuilder) it2.next();
                String name = pOJOPropertyBuilder2.getName();
                POJOPropertyBuilder pOJOPropertyBuilder3 = this._properties.get(name);
                if (pOJOPropertyBuilder3 == null) {
                    this._properties.put(name, pOJOPropertyBuilder2);
                } else {
                    pOJOPropertyBuilder3.addAll(pOJOPropertyBuilder2);
                }
                if (this._creatorProperties != null) {
                    int i = 0;
                    while (true) {
                        int i2 = i;
                        if (i2 >= this._creatorProperties.size()) {
                            break;
                        } else if (this._creatorProperties.get(i2).getInternalName().equals(pOJOPropertyBuilder2.getInternalName())) {
                            this._creatorProperties.set(i2, pOJOPropertyBuilder2);
                            break;
                        } else {
                            i = i2 + 1;
                        }
                    }
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public void _renameUsing(PropertyNamingStrategy propertyNamingStrategy) {
        POJOPropertyBuilder[] pOJOPropertyBuilderArr;
        POJOPropertyBuilder pOJOPropertyBuilder;
        String str;
        this._properties.clear();
        for (POJOPropertyBuilder pOJOPropertyBuilder2 : (POJOPropertyBuilder[]) this._properties.values().toArray(new POJOPropertyBuilder[this._properties.size()])) {
            PropertyName fullName = pOJOPropertyBuilder2.getFullName();
            String str2 = null;
            if (this._forSerialization) {
                if (pOJOPropertyBuilder2.hasGetter()) {
                    str2 = propertyNamingStrategy.nameForGetterMethod(this._config, pOJOPropertyBuilder2.getGetter(), fullName.getSimpleName());
                } else if (pOJOPropertyBuilder2.hasField()) {
                    str2 = propertyNamingStrategy.nameForField(this._config, pOJOPropertyBuilder2.getField(), fullName.getSimpleName());
                }
            } else if (pOJOPropertyBuilder2.hasSetter()) {
                str2 = propertyNamingStrategy.nameForSetterMethod(this._config, pOJOPropertyBuilder2.getSetter(), fullName.getSimpleName());
            } else if (pOJOPropertyBuilder2.hasConstructorParameter()) {
                str2 = propertyNamingStrategy.nameForConstructorParameter(this._config, pOJOPropertyBuilder2.getConstructorParameter(), fullName.getSimpleName());
            } else if (pOJOPropertyBuilder2.hasField()) {
                str2 = propertyNamingStrategy.nameForField(this._config, pOJOPropertyBuilder2.getField(), fullName.getSimpleName());
            } else if (pOJOPropertyBuilder2.hasGetter()) {
                str2 = propertyNamingStrategy.nameForGetterMethod(this._config, pOJOPropertyBuilder2.getGetter(), fullName.getSimpleName());
            }
            if (str2 == null || fullName.hasSimpleName(str2)) {
                String simpleName = fullName.getSimpleName();
                pOJOPropertyBuilder = pOJOPropertyBuilder2;
                str = simpleName;
            } else {
                pOJOPropertyBuilder = pOJOPropertyBuilder2.withSimpleName(str2);
                str = str2;
            }
            POJOPropertyBuilder pOJOPropertyBuilder3 = this._properties.get(str);
            if (pOJOPropertyBuilder3 == null) {
                this._properties.put(str, pOJOPropertyBuilder);
            } else {
                pOJOPropertyBuilder3.addAll(pOJOPropertyBuilder);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void _renameWithWrappers() {
        Iterator<Entry<String, POJOPropertyBuilder>> it = this._properties.entrySet().iterator();
        LinkedList linkedList = null;
        while (it.hasNext()) {
            POJOPropertyBuilder pOJOPropertyBuilder = (POJOPropertyBuilder) it.next().getValue();
            AnnotatedMember primaryMember = pOJOPropertyBuilder.getPrimaryMember();
            if (primaryMember != null) {
                PropertyName findWrapperName = this._annotationIntrospector.findWrapperName(primaryMember);
                if (findWrapperName != null && findWrapperName.hasSimpleName() && !findWrapperName.equals(pOJOPropertyBuilder.getFullName())) {
                    if (linkedList == null) {
                        linkedList = new LinkedList();
                    }
                    linkedList.add(pOJOPropertyBuilder.withName(findWrapperName));
                    it.remove();
                }
            }
        }
        if (linkedList != null) {
            Iterator it2 = linkedList.iterator();
            while (it2.hasNext()) {
                POJOPropertyBuilder pOJOPropertyBuilder2 = (POJOPropertyBuilder) it2.next();
                String name = pOJOPropertyBuilder2.getName();
                POJOPropertyBuilder pOJOPropertyBuilder3 = this._properties.get(name);
                if (pOJOPropertyBuilder3 == null) {
                    this._properties.put(name, pOJOPropertyBuilder2);
                } else {
                    pOJOPropertyBuilder3.addAll(pOJOPropertyBuilder2);
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public void reportProblem(String str) {
        throw new IllegalArgumentException("Problem with definition of " + this._classDef + ": " + str);
    }

    /* access modifiers changed from: protected */
    public POJOPropertyBuilder _property(String str) {
        POJOPropertyBuilder pOJOPropertyBuilder = this._properties.get(str);
        if (pOJOPropertyBuilder != null) {
            return pOJOPropertyBuilder;
        }
        POJOPropertyBuilder pOJOPropertyBuilder2 = new POJOPropertyBuilder(new PropertyName(str), this._annotationIntrospector, this._forSerialization);
        this._properties.put(str, pOJOPropertyBuilder2);
        return pOJOPropertyBuilder2;
    }

    private PropertyNamingStrategy _findNamingStrategy() {
        Object findNamingStrategy = this._annotationIntrospector == null ? null : this._annotationIntrospector.findNamingStrategy(this._classDef);
        if (findNamingStrategy == null) {
            return this._config.getPropertyNamingStrategy();
        }
        if (findNamingStrategy instanceof PropertyNamingStrategy) {
            return (PropertyNamingStrategy) findNamingStrategy;
        }
        if (!(findNamingStrategy instanceof Class)) {
            throw new IllegalStateException("AnnotationIntrospector returned PropertyNamingStrategy definition of type " + findNamingStrategy.getClass().getName() + "; expected type PropertyNamingStrategy or Class<PropertyNamingStrategy> instead");
        }
        Class cls = (Class) findNamingStrategy;
        if (!PropertyNamingStrategy.class.isAssignableFrom(cls)) {
            throw new IllegalStateException("AnnotationIntrospector returned Class " + cls.getName() + "; expected Class<PropertyNamingStrategy>");
        }
        HandlerInstantiator handlerInstantiator = this._config.getHandlerInstantiator();
        if (handlerInstantiator != null) {
            PropertyNamingStrategy namingStrategyInstance = handlerInstantiator.namingStrategyInstance(this._config, this._classDef, cls);
            if (namingStrategyInstance != null) {
                return namingStrategyInstance;
            }
        }
        return (PropertyNamingStrategy) ClassUtil.createInstance(cls, this._config.canOverrideAccessModifiers());
    }
}