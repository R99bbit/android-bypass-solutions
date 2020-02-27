package com.fasterxml.jackson.databind.deser;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.databind.AbstractTypeResolver;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.BeanProperty.Std;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.KeyDeserializer;
import com.fasterxml.jackson.databind.PropertyMetadata;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.annotation.NoClass;
import com.fasterxml.jackson.databind.cfg.DeserializerFactoryConfig;
import com.fasterxml.jackson.databind.cfg.HandlerInstantiator;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.deser.impl.CreatorCollector;
import com.fasterxml.jackson.databind.deser.std.ArrayBlockingQueueDeserializer;
import com.fasterxml.jackson.databind.deser.std.CollectionDeserializer;
import com.fasterxml.jackson.databind.deser.std.DateDeserializers;
import com.fasterxml.jackson.databind.deser.std.EnumDeserializer;
import com.fasterxml.jackson.databind.deser.std.EnumMapDeserializer;
import com.fasterxml.jackson.databind.deser.std.EnumSetDeserializer;
import com.fasterxml.jackson.databind.deser.std.JavaTypeDeserializer;
import com.fasterxml.jackson.databind.deser.std.JdkDeserializers;
import com.fasterxml.jackson.databind.deser.std.JsonLocationInstantiator;
import com.fasterxml.jackson.databind.deser.std.JsonNodeDeserializer;
import com.fasterxml.jackson.databind.deser.std.MapDeserializer;
import com.fasterxml.jackson.databind.deser.std.NumberDeserializers;
import com.fasterxml.jackson.databind.deser.std.ObjectArrayDeserializer;
import com.fasterxml.jackson.databind.deser.std.PrimitiveArrayDeserializers;
import com.fasterxml.jackson.databind.deser.std.StdKeyDeserializers;
import com.fasterxml.jackson.databind.deser.std.StringArrayDeserializer;
import com.fasterxml.jackson.databind.deser.std.StringCollectionDeserializer;
import com.fasterxml.jackson.databind.deser.std.StringDeserializer;
import com.fasterxml.jackson.databind.deser.std.TokenBufferDeserializer;
import com.fasterxml.jackson.databind.deser.std.UntypedObjectDeserializer;
import com.fasterxml.jackson.databind.introspect.Annotated;
import com.fasterxml.jackson.databind.introspect.AnnotatedClass;
import com.fasterxml.jackson.databind.introspect.AnnotatedConstructor;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.introspect.AnnotatedMethod;
import com.fasterxml.jackson.databind.introspect.AnnotatedParameter;
import com.fasterxml.jackson.databind.introspect.AnnotatedWithParams;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import com.fasterxml.jackson.databind.jsontype.TypeResolverBuilder;
import com.fasterxml.jackson.databind.type.ArrayType;
import com.fasterxml.jackson.databind.type.CollectionLikeType;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.databind.type.MapLikeType;
import com.fasterxml.jackson.databind.type.MapType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.databind.util.ClassUtil;
import com.fasterxml.jackson.databind.util.EnumResolver;
import com.fasterxml.jackson.databind.util.TokenBuffer;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;

public abstract class BasicDeserializerFactory extends DeserializerFactory implements Serializable {
    private static final Class<?> CLASS_CHAR_BUFFER = CharSequence.class;
    private static final Class<?> CLASS_ITERABLE = Iterable.class;
    private static final Class<?> CLASS_OBJECT = Object.class;
    private static final Class<?> CLASS_STRING = String.class;
    protected static final PropertyName UNWRAPPED_CREATOR_PARAM_NAME = new PropertyName("@JsonUnwrapped");
    static final HashMap<String, Class<? extends Collection>> _collectionFallbacks = new HashMap<>();
    static final HashMap<String, Class<? extends Map>> _mapFallbacks = new HashMap<>();
    protected final DeserializerFactoryConfig _factoryConfig;

    /* access modifiers changed from: protected */
    public abstract DeserializerFactory withConfig(DeserializerFactoryConfig deserializerFactoryConfig);

    static {
        _mapFallbacks.put(Map.class.getName(), LinkedHashMap.class);
        _mapFallbacks.put(ConcurrentMap.class.getName(), ConcurrentHashMap.class);
        _mapFallbacks.put(SortedMap.class.getName(), TreeMap.class);
        _mapFallbacks.put("java.util.NavigableMap", TreeMap.class);
        try {
            _mapFallbacks.put(ConcurrentNavigableMap.class.getName(), ConcurrentSkipListMap.class);
        } catch (Throwable th) {
            System.err.println("Problems with (optional) types: " + th);
        }
        _collectionFallbacks.put(Collection.class.getName(), ArrayList.class);
        _collectionFallbacks.put(List.class.getName(), ArrayList.class);
        _collectionFallbacks.put(Set.class.getName(), HashSet.class);
        _collectionFallbacks.put(SortedSet.class.getName(), TreeSet.class);
        _collectionFallbacks.put(Queue.class.getName(), LinkedList.class);
        _collectionFallbacks.put("java.util.Deque", LinkedList.class);
        _collectionFallbacks.put("java.util.NavigableSet", TreeSet.class);
    }

    protected BasicDeserializerFactory(DeserializerFactoryConfig deserializerFactoryConfig) {
        this._factoryConfig = deserializerFactoryConfig;
    }

    public DeserializerFactoryConfig getFactoryConfig() {
        return this._factoryConfig;
    }

    public final DeserializerFactory withAdditionalDeserializers(Deserializers deserializers) {
        return withConfig(this._factoryConfig.withAdditionalDeserializers(deserializers));
    }

    public final DeserializerFactory withAdditionalKeyDeserializers(KeyDeserializers keyDeserializers) {
        return withConfig(this._factoryConfig.withAdditionalKeyDeserializers(keyDeserializers));
    }

    public final DeserializerFactory withDeserializerModifier(BeanDeserializerModifier beanDeserializerModifier) {
        return withConfig(this._factoryConfig.withDeserializerModifier(beanDeserializerModifier));
    }

    public final DeserializerFactory withAbstractTypeResolver(AbstractTypeResolver abstractTypeResolver) {
        return withConfig(this._factoryConfig.withAbstractTypeResolver(abstractTypeResolver));
    }

    public final DeserializerFactory withValueInstantiators(ValueInstantiators valueInstantiators) {
        return withConfig(this._factoryConfig.withValueInstantiators(valueInstantiators));
    }

    public JavaType mapAbstractType(DeserializationConfig deserializationConfig, JavaType javaType) throws JsonMappingException {
        JavaType _mapAbstractType2;
        while (true) {
            _mapAbstractType2 = _mapAbstractType2(deserializationConfig, javaType);
            if (_mapAbstractType2 == null) {
                return javaType;
            }
            Class<?> rawClass = javaType.getRawClass();
            Class<?> rawClass2 = _mapAbstractType2.getRawClass();
            if (rawClass != rawClass2 && rawClass.isAssignableFrom(rawClass2)) {
                javaType = _mapAbstractType2;
            }
        }
        throw new IllegalArgumentException("Invalid abstract type resolution from " + javaType + " to " + _mapAbstractType2 + ": latter is not a subtype of former");
    }

    private JavaType _mapAbstractType2(DeserializationConfig deserializationConfig, JavaType javaType) throws JsonMappingException {
        Class<?> rawClass = javaType.getRawClass();
        if (this._factoryConfig.hasAbstractTypeResolvers()) {
            for (AbstractTypeResolver findTypeMapping : this._factoryConfig.abstractTypeResolvers()) {
                JavaType findTypeMapping2 = findTypeMapping.findTypeMapping(deserializationConfig, javaType);
                if (findTypeMapping2 != null && findTypeMapping2.getRawClass() != rawClass) {
                    return findTypeMapping2;
                }
            }
        }
        return null;
    }

    public ValueInstantiator findValueInstantiator(DeserializationContext deserializationContext, BeanDescription beanDescription) throws JsonMappingException {
        ValueInstantiator valueInstantiator;
        DeserializationConfig config = deserializationContext.getConfig();
        ValueInstantiator valueInstantiator2 = null;
        AnnotatedClass classInfo = beanDescription.getClassInfo();
        Object findValueInstantiator = deserializationContext.getAnnotationIntrospector().findValueInstantiator(classInfo);
        if (findValueInstantiator != null) {
            valueInstantiator2 = _valueInstantiatorInstance(config, classInfo, findValueInstantiator);
        }
        if (valueInstantiator2 == null) {
            valueInstantiator2 = _findStdValueInstantiator(config, beanDescription);
            if (valueInstantiator2 == null) {
                valueInstantiator2 = _constructDefaultValueInstantiator(deserializationContext, beanDescription);
            }
        }
        if (this._factoryConfig.hasValueInstantiators()) {
            valueInstantiator = valueInstantiator2;
            for (ValueInstantiators next : this._factoryConfig.valueInstantiators()) {
                valueInstantiator = next.findValueInstantiator(config, beanDescription, valueInstantiator);
                if (valueInstantiator == null) {
                    throw new JsonMappingException("Broken registered ValueInstantiators (of type " + next.getClass().getName() + "): returned null ValueInstantiator");
                }
            }
        } else {
            valueInstantiator = valueInstantiator2;
        }
        if (valueInstantiator.getIncompleteParameter() == null) {
            return valueInstantiator;
        }
        AnnotatedParameter incompleteParameter = valueInstantiator.getIncompleteParameter();
        throw new IllegalArgumentException("Argument #" + incompleteParameter.getIndex() + " of constructor " + incompleteParameter.getOwner() + " has no property name annotation; must have name when multiple-paramater constructor annotated as Creator");
    }

    private ValueInstantiator _findStdValueInstantiator(DeserializationConfig deserializationConfig, BeanDescription beanDescription) throws JsonMappingException {
        if (beanDescription.getBeanClass() == JsonLocation.class) {
            return JsonLocationInstantiator.instance;
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public ValueInstantiator _constructDefaultValueInstantiator(DeserializationContext deserializationContext, BeanDescription beanDescription) throws JsonMappingException {
        CreatorCollector creatorCollector = new CreatorCollector(beanDescription, deserializationContext.canOverrideAccessModifiers());
        AnnotationIntrospector annotationIntrospector = deserializationContext.getAnnotationIntrospector();
        DeserializationConfig config = deserializationContext.getConfig();
        VisibilityChecker<?> findAutoDetectVisibility = annotationIntrospector.findAutoDetectVisibility(beanDescription.getClassInfo(), config.getDefaultVisibilityChecker());
        _addDeserializerFactoryMethods(deserializationContext, beanDescription, findAutoDetectVisibility, annotationIntrospector, creatorCollector);
        if (beanDescription.getType().isConcrete()) {
            _addDeserializerConstructors(deserializationContext, beanDescription, findAutoDetectVisibility, annotationIntrospector, creatorCollector);
        }
        return creatorCollector.constructValueInstantiator(config);
    }

    public ValueInstantiator _valueInstantiatorInstance(DeserializationConfig deserializationConfig, Annotated annotated, Object obj) throws JsonMappingException {
        if (obj == null) {
            return null;
        }
        if (obj instanceof ValueInstantiator) {
            return (ValueInstantiator) obj;
        }
        if (!(obj instanceof Class)) {
            throw new IllegalStateException("AnnotationIntrospector returned key deserializer definition of type " + obj.getClass().getName() + "; expected type KeyDeserializer or Class<KeyDeserializer> instead");
        }
        Class<NoClass> cls = (Class) obj;
        if (cls == NoClass.class) {
            return null;
        }
        if (!ValueInstantiator.class.isAssignableFrom(cls)) {
            throw new IllegalStateException("AnnotationIntrospector returned Class " + cls.getName() + "; expected Class<ValueInstantiator>");
        }
        HandlerInstantiator handlerInstantiator = deserializationConfig.getHandlerInstantiator();
        if (handlerInstantiator != null) {
            ValueInstantiator valueInstantiatorInstance = handlerInstantiator.valueInstantiatorInstance(deserializationConfig, annotated, cls);
            if (valueInstantiatorInstance != null) {
                return valueInstantiatorInstance;
            }
        }
        return (ValueInstantiator) ClassUtil.createInstance(cls, deserializationConfig.canOverrideAccessModifiers());
    }

    /* access modifiers changed from: protected */
    public void _addDeserializerConstructors(DeserializationContext deserializationContext, BeanDescription beanDescription, VisibilityChecker<?> visibilityChecker, AnnotationIntrospector annotationIntrospector, CreatorCollector creatorCollector) throws JsonMappingException {
        AnnotatedConstructor annotatedConstructor;
        PropertyName[] propertyNameArr;
        AnnotatedConstructor findDefaultConstructor = beanDescription.findDefaultConstructor();
        if (findDefaultConstructor != null && (!creatorCollector.hasDefaultCreator() || annotationIntrospector.hasCreatorAnnotation(findDefaultConstructor))) {
            creatorCollector.setDefaultCreator(findDefaultConstructor);
        }
        PropertyName[] propertyNameArr2 = null;
        AnnotatedConstructor annotatedConstructor2 = null;
        for (BeanPropertyDefinition next : beanDescription.findProperties()) {
            if (next.getConstructorParameter() != null) {
                AnnotatedParameter constructorParameter = next.getConstructorParameter();
                AnnotatedWithParams owner = constructorParameter.getOwner();
                if (owner instanceof AnnotatedConstructor) {
                    if (annotatedConstructor2 == null) {
                        annotatedConstructor = (AnnotatedConstructor) owner;
                        propertyNameArr = new PropertyName[annotatedConstructor.getParameterCount()];
                    } else {
                        annotatedConstructor = annotatedConstructor2;
                        propertyNameArr = propertyNameArr2;
                    }
                    propertyNameArr[constructorParameter.getIndex()] = next.getFullName();
                    annotatedConstructor2 = annotatedConstructor;
                    propertyNameArr2 = propertyNameArr;
                }
            }
        }
        for (AnnotatedConstructor next2 : beanDescription.getConstructors()) {
            int parameterCount = next2.getParameterCount();
            boolean z = annotationIntrospector.hasCreatorAnnotation(next2) || next2 == annotatedConstructor2;
            boolean isCreatorVisible = visibilityChecker.isCreatorVisible((AnnotatedMember) next2);
            if (parameterCount == 1) {
                _handleSingleArgumentConstructor(deserializationContext, beanDescription, visibilityChecker, annotationIntrospector, creatorCollector, next2, z, isCreatorVisible, next2 == annotatedConstructor2 ? propertyNameArr2[0] : null);
            } else if (z || isCreatorVisible) {
                AnnotatedParameter annotatedParameter = null;
                int i = 0;
                int i2 = 0;
                CreatorProperty[] creatorPropertyArr = new CreatorProperty[parameterCount];
                int i3 = 0;
                while (i3 < parameterCount) {
                    AnnotatedParameter parameter = next2.getParameter(i3);
                    PropertyName propertyName = null;
                    if (next2 == annotatedConstructor2) {
                        propertyName = propertyNameArr2[i3];
                    }
                    if (propertyName == null) {
                        propertyName = parameter == null ? null : annotationIntrospector.findNameForDeserialization(parameter);
                    }
                    Object findInjectableValueId = annotationIntrospector.findInjectableValueId(parameter);
                    if (propertyName != null && propertyName.hasSimpleName()) {
                        i++;
                        creatorPropertyArr[i3] = constructCreatorProperty(deserializationContext, beanDescription, propertyName, i3, parameter, findInjectableValueId);
                        parameter = annotatedParameter;
                    } else if (findInjectableValueId != null) {
                        i2++;
                        creatorPropertyArr[i3] = constructCreatorProperty(deserializationContext, beanDescription, propertyName, i3, parameter, findInjectableValueId);
                        parameter = annotatedParameter;
                    } else if (annotationIntrospector.findUnwrappingNameTransformer(parameter) != null) {
                        creatorPropertyArr[i3] = constructCreatorProperty(deserializationContext, beanDescription, UNWRAPPED_CREATOR_PARAM_NAME, i3, parameter, null);
                        i++;
                        parameter = annotatedParameter;
                    } else if (annotatedParameter != null) {
                        parameter = annotatedParameter;
                    }
                    i3++;
                    annotatedParameter = parameter;
                }
                if (z || i > 0 || i2 > 0) {
                    if (i + i2 == parameterCount) {
                        creatorCollector.addPropertyCreator(next2, creatorPropertyArr);
                    } else if (i == 0 && i2 + 1 == parameterCount) {
                        creatorCollector.addDelegatingCreator(next2, creatorPropertyArr);
                    } else {
                        creatorCollector.addIncompeteParameter(annotatedParameter);
                    }
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public boolean _handleSingleArgumentConstructor(DeserializationContext deserializationContext, BeanDescription beanDescription, VisibilityChecker<?> visibilityChecker, AnnotationIntrospector annotationIntrospector, CreatorCollector creatorCollector, AnnotatedConstructor annotatedConstructor, boolean z, boolean z2, PropertyName propertyName) throws JsonMappingException {
        PropertyName propertyName2;
        AnnotatedParameter parameter = annotatedConstructor.getParameter(0);
        if (propertyName == null) {
            propertyName2 = parameter == null ? null : annotationIntrospector.findNameForDeserialization(parameter);
        } else {
            propertyName2 = propertyName;
        }
        Object findInjectableValueId = annotationIntrospector.findInjectableValueId(parameter);
        if (findInjectableValueId != null || (propertyName2 != null && propertyName2.hasSimpleName())) {
            creatorCollector.addPropertyCreator(annotatedConstructor, new CreatorProperty[]{constructCreatorProperty(deserializationContext, beanDescription, propertyName2, 0, parameter, findInjectableValueId)});
            return true;
        }
        Class<?> rawParameterType = annotatedConstructor.getRawParameterType(0);
        if (rawParameterType == String.class) {
            if (z || z2) {
                creatorCollector.addStringCreator(annotatedConstructor);
            }
            return true;
        } else if (rawParameterType == Integer.TYPE || rawParameterType == Integer.class) {
            if (z || z2) {
                creatorCollector.addIntCreator(annotatedConstructor);
            }
            return true;
        } else if (rawParameterType == Long.TYPE || rawParameterType == Long.class) {
            if (z || z2) {
                creatorCollector.addLongCreator(annotatedConstructor);
            }
            return true;
        } else if (rawParameterType == Double.TYPE || rawParameterType == Double.class) {
            if (z || z2) {
                creatorCollector.addDoubleCreator(annotatedConstructor);
            }
            return true;
        } else if (!z) {
            return false;
        } else {
            creatorCollector.addDelegatingCreator(annotatedConstructor, null);
            return true;
        }
    }

    /* access modifiers changed from: protected */
    public void _addDeserializerFactoryMethods(DeserializationContext deserializationContext, BeanDescription beanDescription, VisibilityChecker<?> visibilityChecker, AnnotationIntrospector annotationIntrospector, CreatorCollector creatorCollector) throws JsonMappingException {
        DeserializationConfig config = deserializationContext.getConfig();
        for (AnnotatedMethod next : beanDescription.getFactoryMethods()) {
            boolean hasCreatorAnnotation = annotationIntrospector.hasCreatorAnnotation(next);
            int parameterCount = next.getParameterCount();
            if (parameterCount != 0) {
                if (parameterCount == 1) {
                    AnnotatedParameter parameter = next.getParameter(0);
                    PropertyName findNameForDeserialization = parameter == null ? null : annotationIntrospector.findNameForDeserialization(parameter);
                    String simpleName = findNameForDeserialization == null ? null : findNameForDeserialization.getSimpleName();
                    if (annotationIntrospector.findInjectableValueId(parameter) == null && (simpleName == null || simpleName.length() == 0)) {
                        _handleSingleArgumentFactory(config, beanDescription, visibilityChecker, annotationIntrospector, creatorCollector, next, hasCreatorAnnotation);
                    }
                } else if (!annotationIntrospector.hasCreatorAnnotation(next)) {
                    continue;
                }
                AnnotatedParameter annotatedParameter = null;
                CreatorProperty[] creatorPropertyArr = new CreatorProperty[parameterCount];
                int i = 0;
                int i2 = 0;
                int i3 = 0;
                while (i3 < parameterCount) {
                    AnnotatedParameter parameter2 = next.getParameter(i3);
                    PropertyName findNameForDeserialization2 = parameter2 == null ? null : annotationIntrospector.findNameForDeserialization(parameter2);
                    Object findInjectableValueId = annotationIntrospector.findInjectableValueId(parameter2);
                    if (findNameForDeserialization2 != null && findNameForDeserialization2.hasSimpleName()) {
                        i++;
                        creatorPropertyArr[i3] = constructCreatorProperty(deserializationContext, beanDescription, findNameForDeserialization2, i3, parameter2, findInjectableValueId);
                        parameter2 = annotatedParameter;
                    } else if (findInjectableValueId != null) {
                        i2++;
                        creatorPropertyArr[i3] = constructCreatorProperty(deserializationContext, beanDescription, findNameForDeserialization2, i3, parameter2, findInjectableValueId);
                        parameter2 = annotatedParameter;
                    } else if (annotationIntrospector.findUnwrappingNameTransformer(parameter2) != null) {
                        creatorPropertyArr[i3] = constructCreatorProperty(deserializationContext, beanDescription, UNWRAPPED_CREATOR_PARAM_NAME, i3, parameter2, null);
                        i++;
                        parameter2 = annotatedParameter;
                    } else if (annotatedParameter != null) {
                        parameter2 = annotatedParameter;
                    }
                    i3++;
                    annotatedParameter = parameter2;
                }
                if (hasCreatorAnnotation || i > 0 || i2 > 0) {
                    if (i + i2 == parameterCount) {
                        creatorCollector.addPropertyCreator(next, creatorPropertyArr);
                    } else if (i == 0 && i2 + 1 == parameterCount) {
                        creatorCollector.addDelegatingCreator(next, creatorPropertyArr);
                    } else {
                        throw new IllegalArgumentException("Argument #" + annotatedParameter.getIndex() + " of factory method " + next + " has no property name annotation; must have name when multiple-paramater constructor annotated as Creator");
                    }
                }
            } else if (hasCreatorAnnotation) {
                creatorCollector.setDefaultCreator(next);
            }
        }
    }

    /* access modifiers changed from: protected */
    public boolean _handleSingleArgumentFactory(DeserializationConfig deserializationConfig, BeanDescription beanDescription, VisibilityChecker<?> visibilityChecker, AnnotationIntrospector annotationIntrospector, CreatorCollector creatorCollector, AnnotatedMethod annotatedMethod, boolean z) throws JsonMappingException {
        Class<?> rawParameterType = annotatedMethod.getRawParameterType(0);
        if (rawParameterType == String.class) {
            if (!z && !visibilityChecker.isCreatorVisible((AnnotatedMember) annotatedMethod)) {
                return true;
            }
            creatorCollector.addStringCreator(annotatedMethod);
            return true;
        } else if (rawParameterType == Integer.TYPE || rawParameterType == Integer.class) {
            if (!z && !visibilityChecker.isCreatorVisible((AnnotatedMember) annotatedMethod)) {
                return true;
            }
            creatorCollector.addIntCreator(annotatedMethod);
            return true;
        } else if (rawParameterType == Long.TYPE || rawParameterType == Long.class) {
            if (!z && !visibilityChecker.isCreatorVisible((AnnotatedMember) annotatedMethod)) {
                return true;
            }
            creatorCollector.addLongCreator(annotatedMethod);
            return true;
        } else if (rawParameterType == Double.TYPE || rawParameterType == Double.class) {
            if (!z && !visibilityChecker.isCreatorVisible((AnnotatedMember) annotatedMethod)) {
                return true;
            }
            creatorCollector.addDoubleCreator(annotatedMethod);
            return true;
        } else if (rawParameterType == Boolean.TYPE || rawParameterType == Boolean.class) {
            if (!z && !visibilityChecker.isCreatorVisible((AnnotatedMember) annotatedMethod)) {
                return true;
            }
            creatorCollector.addBooleanCreator(annotatedMethod);
            return true;
        } else if (!annotationIntrospector.hasCreatorAnnotation(annotatedMethod)) {
            return false;
        } else {
            creatorCollector.addDelegatingCreator(annotatedMethod, null);
            return true;
        }
    }

    /* access modifiers changed from: protected */
    public CreatorProperty constructCreatorProperty(DeserializationContext deserializationContext, BeanDescription beanDescription, PropertyName propertyName, int i, AnnotatedParameter annotatedParameter, Object obj) throws JsonMappingException {
        Std std;
        TypeDeserializer typeDeserializer;
        DeserializationConfig config = deserializationContext.getConfig();
        AnnotationIntrospector annotationIntrospector = deserializationContext.getAnnotationIntrospector();
        Boolean hasRequiredMarker = annotationIntrospector == null ? null : annotationIntrospector.hasRequiredMarker(annotatedParameter);
        PropertyMetadata construct = PropertyMetadata.construct(hasRequiredMarker != null && hasRequiredMarker.booleanValue(), annotationIntrospector == null ? null : annotationIntrospector.findPropertyDescription(annotatedParameter));
        JavaType constructType = config.getTypeFactory().constructType(annotatedParameter.getParameterType(), beanDescription.bindingsForBeanType());
        Std std2 = new Std(propertyName, constructType, annotationIntrospector.findWrapperName(annotatedParameter), beanDescription.getClassAnnotations(), (AnnotatedMember) annotatedParameter, construct);
        JavaType resolveType = resolveType(deserializationContext, beanDescription, constructType, annotatedParameter);
        if (resolveType != constructType) {
            std = std2.withType(resolveType);
        } else {
            std = std2;
        }
        JsonDeserializer<Object> findDeserializerFromAnnotation = findDeserializerFromAnnotation(deserializationContext, annotatedParameter);
        JavaType modifyTypeByAnnotation = modifyTypeByAnnotation(deserializationContext, annotatedParameter, resolveType);
        TypeDeserializer typeDeserializer2 = (TypeDeserializer) modifyTypeByAnnotation.getTypeHandler();
        if (typeDeserializer2 == null) {
            typeDeserializer = findTypeDeserializer(config, modifyTypeByAnnotation);
        } else {
            typeDeserializer = typeDeserializer2;
        }
        CreatorProperty creatorProperty = new CreatorProperty(propertyName, modifyTypeByAnnotation, std.getWrapperName(), typeDeserializer, beanDescription.getClassAnnotations(), annotatedParameter, i, obj, construct);
        if (findDeserializerFromAnnotation != null) {
            return creatorProperty.withValueDeserializer(findDeserializerFromAnnotation);
        }
        return creatorProperty;
    }

    public JsonDeserializer<?> createArrayDeserializer(DeserializationContext deserializationContext, ArrayType arrayType, BeanDescription beanDescription) throws JsonMappingException {
        TypeDeserializer typeDeserializer;
        DeserializationConfig config = deserializationContext.getConfig();
        JavaType contentType = arrayType.getContentType();
        JsonDeserializer jsonDeserializer = (JsonDeserializer) contentType.getValueHandler();
        TypeDeserializer typeDeserializer2 = (TypeDeserializer) contentType.getTypeHandler();
        if (typeDeserializer2 == null) {
            typeDeserializer = findTypeDeserializer(config, contentType);
        } else {
            typeDeserializer = typeDeserializer2;
        }
        JsonDeserializer<?> _findCustomArrayDeserializer = _findCustomArrayDeserializer(arrayType, config, beanDescription, typeDeserializer, jsonDeserializer);
        if (_findCustomArrayDeserializer == null) {
            if (jsonDeserializer == null) {
                Class rawClass = contentType.getRawClass();
                if (contentType.isPrimitive()) {
                    return PrimitiveArrayDeserializers.forType(rawClass);
                }
                if (rawClass == String.class) {
                    return StringArrayDeserializer.instance;
                }
            }
            _findCustomArrayDeserializer = new ObjectArrayDeserializer<>(arrayType, jsonDeserializer, typeDeserializer);
        }
        if (!this._factoryConfig.hasDeserializerModifiers()) {
            return _findCustomArrayDeserializer;
        }
        Iterator<BeanDeserializerModifier> it = this._factoryConfig.deserializerModifiers().iterator();
        while (true) {
            JsonDeserializer<?> jsonDeserializer2 = _findCustomArrayDeserializer;
            if (!it.hasNext()) {
                return jsonDeserializer2;
            }
            _findCustomArrayDeserializer = it.next().modifyArrayDeserializer(config, arrayType, beanDescription, jsonDeserializer2);
        }
    }

    /* access modifiers changed from: protected */
    public JsonDeserializer<?> _findCustomArrayDeserializer(ArrayType arrayType, DeserializationConfig deserializationConfig, BeanDescription beanDescription, TypeDeserializer typeDeserializer, JsonDeserializer<?> jsonDeserializer) throws JsonMappingException {
        for (Deserializers findArrayDeserializer : this._factoryConfig.deserializers()) {
            JsonDeserializer<?> findArrayDeserializer2 = findArrayDeserializer.findArrayDeserializer(arrayType, deserializationConfig, beanDescription, typeDeserializer, jsonDeserializer);
            if (findArrayDeserializer2 != null) {
                return findArrayDeserializer2;
            }
        }
        return null;
    }

    public JsonDeserializer<?> createCollectionDeserializer(DeserializationContext deserializationContext, CollectionType collectionType, BeanDescription beanDescription) throws JsonMappingException {
        TypeDeserializer typeDeserializer;
        CollectionType collectionType2;
        JsonDeserializer<?> jsonDeserializer;
        JavaType contentType = collectionType.getContentType();
        JsonDeserializer jsonDeserializer2 = (JsonDeserializer) contentType.getValueHandler();
        DeserializationConfig config = deserializationContext.getConfig();
        TypeDeserializer typeDeserializer2 = (TypeDeserializer) contentType.getTypeHandler();
        if (typeDeserializer2 == null) {
            typeDeserializer = findTypeDeserializer(config, contentType);
        } else {
            typeDeserializer = typeDeserializer2;
        }
        JsonDeserializer<?> _findCustomCollectionDeserializer = _findCustomCollectionDeserializer(collectionType, config, beanDescription, typeDeserializer, jsonDeserializer2);
        if (_findCustomCollectionDeserializer == null) {
            Class<?> rawClass = collectionType.getRawClass();
            if (jsonDeserializer2 == null && EnumSet.class.isAssignableFrom(rawClass)) {
                _findCustomCollectionDeserializer = new EnumSetDeserializer<>(contentType, null);
            }
        }
        if (_findCustomCollectionDeserializer == null) {
            if (collectionType.isInterface() || collectionType.isAbstract()) {
                collectionType2 = _mapAbstractCollectionType(collectionType, config);
                if (collectionType2 != null) {
                    beanDescription = config.introspectForCreation(collectionType2);
                } else if (collectionType.getTypeHandler() == null) {
                    throw new IllegalArgumentException("Can not find a deserializer for non-concrete Collection type " + collectionType);
                } else {
                    _findCustomCollectionDeserializer = AbstractDeserializer.constructForNonPOJO(beanDescription);
                    collectionType2 = collectionType;
                }
            } else {
                collectionType2 = collectionType;
            }
            if (_findCustomCollectionDeserializer == null) {
                ValueInstantiator findValueInstantiator = findValueInstantiator(deserializationContext, beanDescription);
                if (!findValueInstantiator.canCreateUsingDefault() && collectionType2.getRawClass() == ArrayBlockingQueue.class) {
                    return new ArrayBlockingQueueDeserializer(collectionType2, jsonDeserializer2, typeDeserializer, findValueInstantiator, null);
                }
                if (contentType.getRawClass() == String.class) {
                    _findCustomCollectionDeserializer = new StringCollectionDeserializer<>(collectionType2, jsonDeserializer2, findValueInstantiator);
                } else {
                    _findCustomCollectionDeserializer = new CollectionDeserializer<>(collectionType2, jsonDeserializer2, typeDeserializer, findValueInstantiator);
                }
            }
        } else {
            collectionType2 = collectionType;
        }
        if (this._factoryConfig.hasDeserializerModifiers()) {
            Iterator<BeanDeserializerModifier> it = this._factoryConfig.deserializerModifiers().iterator();
            while (true) {
                jsonDeserializer = _findCustomCollectionDeserializer;
                if (!it.hasNext()) {
                    break;
                }
                _findCustomCollectionDeserializer = it.next().modifyCollectionDeserializer(config, collectionType2, beanDescription, jsonDeserializer);
            }
        } else {
            jsonDeserializer = _findCustomCollectionDeserializer;
        }
        return jsonDeserializer;
    }

    /* access modifiers changed from: protected */
    public CollectionType _mapAbstractCollectionType(JavaType javaType, DeserializationConfig deserializationConfig) {
        Class cls = _collectionFallbacks.get(javaType.getRawClass().getName());
        if (cls == null) {
            return null;
        }
        return (CollectionType) deserializationConfig.constructSpecializedType(javaType, cls);
    }

    /* access modifiers changed from: protected */
    public JsonDeserializer<?> _findCustomCollectionDeserializer(CollectionType collectionType, DeserializationConfig deserializationConfig, BeanDescription beanDescription, TypeDeserializer typeDeserializer, JsonDeserializer<?> jsonDeserializer) throws JsonMappingException {
        for (Deserializers findCollectionDeserializer : this._factoryConfig.deserializers()) {
            JsonDeserializer<?> findCollectionDeserializer2 = findCollectionDeserializer.findCollectionDeserializer(collectionType, deserializationConfig, beanDescription, typeDeserializer, jsonDeserializer);
            if (findCollectionDeserializer2 != null) {
                return findCollectionDeserializer2;
            }
        }
        return null;
    }

    public JsonDeserializer<?> createCollectionLikeDeserializer(DeserializationContext deserializationContext, CollectionLikeType collectionLikeType, BeanDescription beanDescription) throws JsonMappingException {
        TypeDeserializer typeDeserializer;
        JavaType contentType = collectionLikeType.getContentType();
        JsonDeserializer jsonDeserializer = (JsonDeserializer) contentType.getValueHandler();
        DeserializationConfig config = deserializationContext.getConfig();
        TypeDeserializer typeDeserializer2 = (TypeDeserializer) contentType.getTypeHandler();
        if (typeDeserializer2 == null) {
            typeDeserializer = findTypeDeserializer(config, contentType);
        } else {
            typeDeserializer = typeDeserializer2;
        }
        JsonDeserializer<?> _findCustomCollectionLikeDeserializer = _findCustomCollectionLikeDeserializer(collectionLikeType, config, beanDescription, typeDeserializer, jsonDeserializer);
        if (_findCustomCollectionLikeDeserializer == null || !this._factoryConfig.hasDeserializerModifiers()) {
            return _findCustomCollectionLikeDeserializer;
        }
        Iterator<BeanDeserializerModifier> it = this._factoryConfig.deserializerModifiers().iterator();
        while (true) {
            JsonDeserializer<?> jsonDeserializer2 = _findCustomCollectionLikeDeserializer;
            if (!it.hasNext()) {
                return jsonDeserializer2;
            }
            _findCustomCollectionLikeDeserializer = it.next().modifyCollectionLikeDeserializer(config, collectionLikeType, beanDescription, jsonDeserializer2);
        }
    }

    /* access modifiers changed from: protected */
    public JsonDeserializer<?> _findCustomCollectionLikeDeserializer(CollectionLikeType collectionLikeType, DeserializationConfig deserializationConfig, BeanDescription beanDescription, TypeDeserializer typeDeserializer, JsonDeserializer<?> jsonDeserializer) throws JsonMappingException {
        for (Deserializers findCollectionLikeDeserializer : this._factoryConfig.deserializers()) {
            JsonDeserializer<?> findCollectionLikeDeserializer2 = findCollectionLikeDeserializer.findCollectionLikeDeserializer(collectionLikeType, deserializationConfig, beanDescription, typeDeserializer, jsonDeserializer);
            if (findCollectionLikeDeserializer2 != null) {
                return findCollectionLikeDeserializer2;
            }
        }
        return null;
    }

    /* JADX WARNING: type inference failed for: r8v0, types: [com.fasterxml.jackson.databind.JsonDeserializer] */
    /* JADX WARNING: type inference failed for: r8v1 */
    /* JADX WARNING: type inference failed for: r8v2 */
    /* JADX WARNING: type inference failed for: r8v3, types: [com.fasterxml.jackson.databind.JsonDeserializer<?>] */
    /* JADX WARNING: type inference failed for: r8v4, types: [com.fasterxml.jackson.databind.JsonDeserializer] */
    /* JADX WARNING: type inference failed for: r8v5, types: [com.fasterxml.jackson.databind.JsonDeserializer] */
    /* JADX WARNING: type inference failed for: r8v6 */
    /* JADX WARNING: type inference failed for: r8v7 */
    /* JADX WARNING: type inference failed for: r8v8, types: [com.fasterxml.jackson.databind.deser.std.MapDeserializer] */
    /* JADX WARNING: type inference failed for: r8v9, types: [com.fasterxml.jackson.databind.deser.AbstractDeserializer] */
    /* JADX WARNING: type inference failed for: r8v10, types: [com.fasterxml.jackson.databind.deser.std.EnumMapDeserializer] */
    /* JADX WARNING: type inference failed for: r8v11 */
    /* JADX WARNING: type inference failed for: r8v12 */
    /* JADX WARNING: type inference failed for: r8v13 */
    /* JADX WARNING: type inference failed for: r8v14 */
    /* JADX WARNING: type inference failed for: r8v15 */
    /* JADX WARNING: type inference failed for: r8v16 */
    /* JADX WARNING: Multi-variable type inference failed. Error: jadx.core.utils.exceptions.JadxRuntimeException: No candidate types for var: r8v1
      assigns: []
      uses: []
      mth insns count: 87
    	at jadx.core.dex.visitors.typeinference.TypeSearch.fillTypeCandidates(TypeSearch.java:237)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.typeinference.TypeSearch.run(TypeSearch.java:53)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.runMultiVariableSearch(TypeInferenceVisitor.java:104)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:97)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:27)
    	at jadx.core.dex.visitors.DepthTraversal.lambda$visit$1(DepthTraversal.java:14)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:14)
    	at jadx.core.ProcessClass.process(ProcessClass.java:30)
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
     */
    /* JADX WARNING: Removed duplicated region for block: B:26:0x00a8  */
    /* JADX WARNING: Unknown variable types count: 5 */
    public JsonDeserializer<?> createMapDeserializer(DeserializationContext deserializationContext, MapType mapType, BeanDescription beanDescription) throws JsonMappingException {
        TypeDeserializer typeDeserializer;
        MapType mapType2;
        DeserializationConfig config = deserializationContext.getConfig();
        JavaType keyType = mapType.getKeyType();
        JavaType contentType = mapType.getContentType();
        JsonDeserializer jsonDeserializer = (JsonDeserializer) contentType.getValueHandler();
        KeyDeserializer keyDeserializer = (KeyDeserializer) keyType.getValueHandler();
        TypeDeserializer typeDeserializer2 = (TypeDeserializer) contentType.getTypeHandler();
        if (typeDeserializer2 == null) {
            typeDeserializer = findTypeDeserializer(config, contentType);
        } else {
            typeDeserializer = typeDeserializer2;
        }
        ? _findCustomMapDeserializer = _findCustomMapDeserializer(mapType, config, beanDescription, keyDeserializer, typeDeserializer, jsonDeserializer);
        if (_findCustomMapDeserializer == 0) {
            Class<?> rawClass = mapType.getRawClass();
            if (EnumMap.class.isAssignableFrom(rawClass)) {
                Class<?> rawClass2 = keyType.getRawClass();
                if (rawClass2 == null || !rawClass2.isEnum()) {
                    throw new IllegalArgumentException("Can not construct EnumMap; generic (key) type not available");
                }
                _findCustomMapDeserializer = new EnumMapDeserializer(mapType, null, jsonDeserializer, typeDeserializer);
            }
            if (_findCustomMapDeserializer == 0) {
                if (mapType.isInterface() || mapType.isAbstract()) {
                    Class cls = _mapFallbacks.get(rawClass.getName());
                    if (cls != null) {
                        MapType mapType3 = (MapType) config.constructSpecializedType(mapType, cls);
                        beanDescription = config.introspectForCreation(mapType3);
                        mapType2 = mapType3;
                    } else if (mapType.getTypeHandler() == null) {
                        throw new IllegalArgumentException("Can not find a deserializer for non-concrete Map type " + mapType);
                    } else {
                        mapType2 = mapType;
                        _findCustomMapDeserializer = AbstractDeserializer.constructForNonPOJO(beanDescription);
                    }
                } else {
                    mapType2 = mapType;
                }
                if (_findCustomMapDeserializer == 0) {
                    ? mapDeserializer = new MapDeserializer((JavaType) mapType2, findValueInstantiator(deserializationContext, beanDescription), keyDeserializer, jsonDeserializer, typeDeserializer);
                    mapDeserializer.setIgnorableProperties(config.getAnnotationIntrospector().findPropertiesToIgnore(beanDescription.getClassInfo()));
                    _findCustomMapDeserializer = mapDeserializer;
                }
                if (this._factoryConfig.hasDeserializerModifiers()) {
                    for (BeanDeserializerModifier modifyMapDeserializer : this._factoryConfig.deserializerModifiers()) {
                        _findCustomMapDeserializer = modifyMapDeserializer.modifyMapDeserializer(config, mapType2, beanDescription, _findCustomMapDeserializer);
                    }
                    _findCustomMapDeserializer = _findCustomMapDeserializer;
                }
                return _findCustomMapDeserializer;
            }
        }
        mapType2 = mapType;
        _findCustomMapDeserializer = _findCustomMapDeserializer;
        if (this._factoryConfig.hasDeserializerModifiers()) {
        }
        return _findCustomMapDeserializer;
    }

    public JsonDeserializer<?> createMapLikeDeserializer(DeserializationContext deserializationContext, MapLikeType mapLikeType, BeanDescription beanDescription) throws JsonMappingException {
        TypeDeserializer typeDeserializer;
        JavaType keyType = mapLikeType.getKeyType();
        JavaType contentType = mapLikeType.getContentType();
        DeserializationConfig config = deserializationContext.getConfig();
        JsonDeserializer jsonDeserializer = (JsonDeserializer) contentType.getValueHandler();
        KeyDeserializer keyDeserializer = (KeyDeserializer) keyType.getValueHandler();
        TypeDeserializer typeDeserializer2 = (TypeDeserializer) contentType.getTypeHandler();
        if (typeDeserializer2 == null) {
            typeDeserializer = findTypeDeserializer(config, contentType);
        } else {
            typeDeserializer = typeDeserializer2;
        }
        JsonDeserializer<?> _findCustomMapLikeDeserializer = _findCustomMapLikeDeserializer(mapLikeType, config, beanDescription, keyDeserializer, typeDeserializer, jsonDeserializer);
        if (_findCustomMapLikeDeserializer == null || !this._factoryConfig.hasDeserializerModifiers()) {
            return _findCustomMapLikeDeserializer;
        }
        Iterator<BeanDeserializerModifier> it = this._factoryConfig.deserializerModifiers().iterator();
        while (true) {
            JsonDeserializer<?> jsonDeserializer2 = _findCustomMapLikeDeserializer;
            if (!it.hasNext()) {
                return jsonDeserializer2;
            }
            _findCustomMapLikeDeserializer = it.next().modifyMapLikeDeserializer(config, mapLikeType, beanDescription, jsonDeserializer2);
        }
    }

    /* access modifiers changed from: protected */
    public JsonDeserializer<?> _findCustomMapDeserializer(MapType mapType, DeserializationConfig deserializationConfig, BeanDescription beanDescription, KeyDeserializer keyDeserializer, TypeDeserializer typeDeserializer, JsonDeserializer<?> jsonDeserializer) throws JsonMappingException {
        for (Deserializers findMapDeserializer : this._factoryConfig.deserializers()) {
            JsonDeserializer<?> findMapDeserializer2 = findMapDeserializer.findMapDeserializer(mapType, deserializationConfig, beanDescription, keyDeserializer, typeDeserializer, jsonDeserializer);
            if (findMapDeserializer2 != null) {
                return findMapDeserializer2;
            }
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public JsonDeserializer<?> _findCustomMapLikeDeserializer(MapLikeType mapLikeType, DeserializationConfig deserializationConfig, BeanDescription beanDescription, KeyDeserializer keyDeserializer, TypeDeserializer typeDeserializer, JsonDeserializer<?> jsonDeserializer) throws JsonMappingException {
        for (Deserializers findMapLikeDeserializer : this._factoryConfig.deserializers()) {
            JsonDeserializer<?> findMapLikeDeserializer2 = findMapLikeDeserializer.findMapLikeDeserializer(mapLikeType, deserializationConfig, beanDescription, keyDeserializer, typeDeserializer, jsonDeserializer);
            if (findMapLikeDeserializer2 != null) {
                return findMapLikeDeserializer2;
            }
        }
        return null;
    }

    public JsonDeserializer<?> createEnumDeserializer(DeserializationContext deserializationContext, JavaType javaType, BeanDescription beanDescription) throws JsonMappingException {
        JsonDeserializer<?> jsonDeserializer;
        DeserializationConfig config = deserializationContext.getConfig();
        Class rawClass = javaType.getRawClass();
        JsonDeserializer<?> _findCustomEnumDeserializer = _findCustomEnumDeserializer(rawClass, config, beanDescription);
        if (_findCustomEnumDeserializer == null) {
            Iterator<AnnotatedMethod> it = beanDescription.getFactoryMethods().iterator();
            while (true) {
                if (!it.hasNext()) {
                    jsonDeserializer = _findCustomEnumDeserializer;
                    break;
                }
                AnnotatedMethod next = it.next();
                if (deserializationContext.getAnnotationIntrospector().hasCreatorAnnotation(next)) {
                    if (next.getParameterCount() != 1 || !next.getRawReturnType().isAssignableFrom(rawClass)) {
                        throw new IllegalArgumentException("Unsuitable method (" + next + ") decorated with @JsonCreator (for Enum type " + rawClass.getName() + ")");
                    }
                    jsonDeserializer = EnumDeserializer.deserializerForCreator(config, rawClass, next);
                }
            }
            if (jsonDeserializer == null) {
                jsonDeserializer = new EnumDeserializer<>(constructEnumResolver(rawClass, config, beanDescription.findJsonValueMethod()));
            }
        } else {
            jsonDeserializer = _findCustomEnumDeserializer;
        }
        if (!this._factoryConfig.hasDeserializerModifiers()) {
            return jsonDeserializer;
        }
        Iterator<BeanDeserializerModifier> it2 = this._factoryConfig.deserializerModifiers().iterator();
        while (true) {
            JsonDeserializer<?> jsonDeserializer2 = jsonDeserializer;
            if (!it2.hasNext()) {
                return jsonDeserializer2;
            }
            jsonDeserializer = it2.next().modifyEnumDeserializer(config, javaType, beanDescription, jsonDeserializer2);
        }
    }

    /* JADX WARNING: type inference failed for: r3v0, types: [java.lang.Class<?>, java.lang.Class] */
    /* access modifiers changed from: protected */
    /* JADX WARNING: Unknown variable types count: 1 */
    public JsonDeserializer<?> _findCustomEnumDeserializer(Class<?> r3, DeserializationConfig deserializationConfig, BeanDescription beanDescription) throws JsonMappingException {
        for (Deserializers findEnumDeserializer : this._factoryConfig.deserializers()) {
            JsonDeserializer<?> findEnumDeserializer2 = findEnumDeserializer.findEnumDeserializer(r3, deserializationConfig, beanDescription);
            if (findEnumDeserializer2 != null) {
                return findEnumDeserializer2;
            }
        }
        return null;
    }

    public JsonDeserializer<?> createTreeDeserializer(DeserializationConfig deserializationConfig, JavaType javaType, BeanDescription beanDescription) throws JsonMappingException {
        Class rawClass = javaType.getRawClass();
        JsonDeserializer<?> _findCustomTreeNodeDeserializer = _findCustomTreeNodeDeserializer(rawClass, deserializationConfig, beanDescription);
        return _findCustomTreeNodeDeserializer != null ? _findCustomTreeNodeDeserializer : JsonNodeDeserializer.getDeserializer(rawClass);
    }

    /* JADX WARNING: type inference failed for: r3v0, types: [java.lang.Class<? extends com.fasterxml.jackson.databind.JsonNode>, java.lang.Class] */
    /* access modifiers changed from: protected */
    /* JADX WARNING: Unknown variable types count: 1 */
    public JsonDeserializer<?> _findCustomTreeNodeDeserializer(Class<? extends JsonNode> r3, DeserializationConfig deserializationConfig, BeanDescription beanDescription) throws JsonMappingException {
        for (Deserializers findTreeNodeDeserializer : this._factoryConfig.deserializers()) {
            JsonDeserializer<?> findTreeNodeDeserializer2 = findTreeNodeDeserializer.findTreeNodeDeserializer(r3, deserializationConfig, beanDescription);
            if (findTreeNodeDeserializer2 != null) {
                return findTreeNodeDeserializer2;
            }
        }
        return null;
    }

    public TypeDeserializer findTypeDeserializer(DeserializationConfig deserializationConfig, JavaType javaType) throws JsonMappingException {
        Collection<NamedType> collection = null;
        AnnotatedClass classInfo = deserializationConfig.introspectClassAnnotations(javaType.getRawClass()).getClassInfo();
        AnnotationIntrospector annotationIntrospector = deserializationConfig.getAnnotationIntrospector();
        TypeResolverBuilder<?> findTypeResolver = annotationIntrospector.findTypeResolver(deserializationConfig, classInfo, javaType);
        if (findTypeResolver == null) {
            findTypeResolver = deserializationConfig.getDefaultTyper(javaType);
            if (findTypeResolver == null) {
                return null;
            }
        } else {
            collection = deserializationConfig.getSubtypeResolver().collectAndResolveSubtypes(classInfo, (MapperConfig<?>) deserializationConfig, annotationIntrospector);
        }
        if (findTypeResolver.getDefaultImpl() == null && javaType.isAbstract()) {
            JavaType mapAbstractType = mapAbstractType(deserializationConfig, javaType);
            if (!(mapAbstractType == null || mapAbstractType.getRawClass() == javaType.getRawClass())) {
                findTypeResolver = findTypeResolver.defaultImpl(mapAbstractType.getRawClass());
            }
        }
        return findTypeResolver.buildTypeDeserializer(deserializationConfig, javaType, collection);
    }

    public KeyDeserializer createKeyDeserializer(DeserializationContext deserializationContext, JavaType javaType) throws JsonMappingException {
        DeserializationConfig config = deserializationContext.getConfig();
        KeyDeserializer keyDeserializer = null;
        if (this._factoryConfig.hasKeyDeserializers()) {
            BeanDescription introspectClassAnnotations = config.introspectClassAnnotations(javaType.getRawClass());
            for (KeyDeserializers findKeyDeserializer : this._factoryConfig.keyDeserializers()) {
                keyDeserializer = findKeyDeserializer.findKeyDeserializer(javaType, config, introspectClassAnnotations);
                if (keyDeserializer != null) {
                    break;
                }
            }
        }
        if (keyDeserializer == null) {
            if (javaType.isEnumType()) {
                return _createEnumKeyDeserializer(deserializationContext, javaType);
            }
            keyDeserializer = StdKeyDeserializers.findStringBasedKeyDeserializer(config, javaType);
        }
        if (keyDeserializer == null || !this._factoryConfig.hasDeserializerModifiers()) {
            return keyDeserializer;
        }
        Iterator<BeanDeserializerModifier> it = this._factoryConfig.deserializerModifiers().iterator();
        while (true) {
            KeyDeserializer keyDeserializer2 = keyDeserializer;
            if (!it.hasNext()) {
                return keyDeserializer2;
            }
            keyDeserializer = it.next().modifyKeyDeserializer(config, javaType, keyDeserializer2);
        }
    }

    private KeyDeserializer _createEnumKeyDeserializer(DeserializationContext deserializationContext, JavaType javaType) throws JsonMappingException {
        DeserializationConfig config = deserializationContext.getConfig();
        BeanDescription introspect = config.introspect(javaType);
        JsonDeserializer<Object> findDeserializerFromAnnotation = findDeserializerFromAnnotation(deserializationContext, introspect.getClassInfo());
        if (findDeserializerFromAnnotation != null) {
            return StdKeyDeserializers.constructDelegatingKeyDeserializer(config, javaType, findDeserializerFromAnnotation);
        }
        Class rawClass = javaType.getRawClass();
        if (_findCustomEnumDeserializer(rawClass, config, introspect) != null) {
            return StdKeyDeserializers.constructDelegatingKeyDeserializer(config, javaType, findDeserializerFromAnnotation);
        }
        EnumResolver<?> constructEnumResolver = constructEnumResolver(rawClass, config, introspect.findJsonValueMethod());
        for (AnnotatedMethod next : introspect.getFactoryMethods()) {
            if (config.getAnnotationIntrospector().hasCreatorAnnotation(next)) {
                if (next.getParameterCount() != 1 || !next.getRawReturnType().isAssignableFrom(rawClass)) {
                    throw new IllegalArgumentException("Unsuitable method (" + next + ") decorated with @JsonCreator (for Enum type " + rawClass.getName() + ")");
                } else if (next.getGenericParameterType(0) != String.class) {
                    throw new IllegalArgumentException("Parameter #0 type for factory method (" + next + ") not suitable, must be java.lang.String");
                } else {
                    if (config.canOverrideAccessModifiers()) {
                        ClassUtil.checkAndFixAccess(next.getMember());
                    }
                    return StdKeyDeserializers.constructEnumKeyDeserializer(constructEnumResolver, next);
                }
            }
        }
        return StdKeyDeserializers.constructEnumKeyDeserializer(constructEnumResolver);
    }

    public TypeDeserializer findPropertyTypeDeserializer(DeserializationConfig deserializationConfig, JavaType javaType, AnnotatedMember annotatedMember) throws JsonMappingException {
        AnnotationIntrospector annotationIntrospector = deserializationConfig.getAnnotationIntrospector();
        TypeResolverBuilder<?> findPropertyTypeResolver = annotationIntrospector.findPropertyTypeResolver(deserializationConfig, annotatedMember, javaType);
        if (findPropertyTypeResolver == null) {
            return findTypeDeserializer(deserializationConfig, javaType);
        }
        return findPropertyTypeResolver.buildTypeDeserializer(deserializationConfig, javaType, deserializationConfig.getSubtypeResolver().collectAndResolveSubtypes(annotatedMember, deserializationConfig, annotationIntrospector, javaType));
    }

    public TypeDeserializer findPropertyContentTypeDeserializer(DeserializationConfig deserializationConfig, JavaType javaType, AnnotatedMember annotatedMember) throws JsonMappingException {
        AnnotationIntrospector annotationIntrospector = deserializationConfig.getAnnotationIntrospector();
        TypeResolverBuilder<?> findPropertyContentTypeResolver = annotationIntrospector.findPropertyContentTypeResolver(deserializationConfig, annotatedMember, javaType);
        JavaType contentType = javaType.getContentType();
        if (findPropertyContentTypeResolver == null) {
            return findTypeDeserializer(deserializationConfig, contentType);
        }
        return findPropertyContentTypeResolver.buildTypeDeserializer(deserializationConfig, contentType, deserializationConfig.getSubtypeResolver().collectAndResolveSubtypes(annotatedMember, deserializationConfig, annotationIntrospector, contentType));
    }

    public JsonDeserializer<?> findDefaultDeserializer(DeserializationContext deserializationContext, JavaType javaType, BeanDescription beanDescription) throws JsonMappingException {
        Class<?> rawClass = javaType.getRawClass();
        String name = rawClass.getName();
        if (!rawClass.isPrimitive() && !name.startsWith("java.")) {
            if (name.startsWith("com.fasterxml.")) {
                if (rawClass == TokenBuffer.class) {
                    return TokenBufferDeserializer.instance;
                }
                if (JavaType.class.isAssignableFrom(rawClass)) {
                    return JavaTypeDeserializer.instance;
                }
            }
            return null;
        } else if (rawClass == CLASS_OBJECT) {
            return new UntypedObjectDeserializer();
        } else {
            if (rawClass == CLASS_STRING || rawClass == CLASS_CHAR_BUFFER) {
                return StringDeserializer.instance;
            }
            if (rawClass == CLASS_ITERABLE) {
                return createCollectionDeserializer(deserializationContext, deserializationContext.getTypeFactory().constructCollectionType(Collection.class, javaType.containedTypeCount() > 0 ? javaType.containedType(0) : TypeFactory.unknownType()), beanDescription);
            }
            JsonDeserializer<?> find = NumberDeserializers.find(rawClass, name);
            if (find != null) {
                return find;
            }
            JsonDeserializer<?> find2 = DateDeserializers.find(rawClass, name);
            if (find2 == null) {
                return JdkDeserializers.find(rawClass, name);
            }
            return find2;
        }
    }

    /* access modifiers changed from: protected */
    public JsonDeserializer<Object> findDeserializerFromAnnotation(DeserializationContext deserializationContext, Annotated annotated) throws JsonMappingException {
        Object findDeserializer = deserializationContext.getAnnotationIntrospector().findDeserializer(annotated);
        if (findDeserializer == null) {
            return null;
        }
        return deserializationContext.deserializerInstance(annotated, findDeserializer);
    }

    /* access modifiers changed from: protected */
    public <T extends JavaType> T modifyTypeByAnnotation(DeserializationContext deserializationContext, Annotated annotated, T t) throws JsonMappingException {
        T t2;
        T t3;
        AnnotationIntrospector annotationIntrospector = deserializationContext.getAnnotationIntrospector();
        Class<?> findDeserializationType = annotationIntrospector.findDeserializationType(annotated, t);
        if (findDeserializationType != null) {
            try {
                t2 = t.narrowBy(findDeserializationType);
            } catch (IllegalArgumentException e) {
                throw new JsonMappingException("Failed to narrow type " + t + " with concrete-type annotation (value " + findDeserializationType.getName() + "), method '" + annotated.getName() + "': " + e.getMessage(), null, e);
            }
        } else {
            t2 = t;
        }
        if (!t2.isContainerType()) {
            return t2;
        }
        Class<?> findDeserializationKeyType = annotationIntrospector.findDeserializationKeyType(annotated, t2.getKeyType());
        if (findDeserializationKeyType == null) {
            t3 = t2;
        } else if (!(t2 instanceof MapLikeType)) {
            throw new JsonMappingException("Illegal key-type annotation: type " + t2 + " is not a Map(-like) type");
        } else {
            try {
                t3 = ((MapLikeType) t2).narrowKey(findDeserializationKeyType);
            } catch (IllegalArgumentException e2) {
                throw new JsonMappingException("Failed to narrow key type " + t2 + " with key-type annotation (" + findDeserializationKeyType.getName() + "): " + e2.getMessage(), null, e2);
            }
        }
        JavaType keyType = t3.getKeyType();
        if (keyType != null && keyType.getValueHandler() == null) {
            KeyDeserializer keyDeserializerInstance = deserializationContext.keyDeserializerInstance(annotated, annotationIntrospector.findKeyDeserializer(annotated));
            if (keyDeserializerInstance != null) {
                t3 = ((MapLikeType) t3).withKeyValueHandler(keyDeserializerInstance);
                t3.getKeyType();
            }
        }
        Class<?> findDeserializationContentType = annotationIntrospector.findDeserializationContentType(annotated, t3.getContentType());
        if (findDeserializationContentType != null) {
            try {
                t3 = t3.narrowContentsBy(findDeserializationContentType);
            } catch (IllegalArgumentException e3) {
                throw new JsonMappingException("Failed to narrow content type " + t3 + " with content-type annotation (" + findDeserializationContentType.getName() + "): " + e3.getMessage(), null, e3);
            }
        }
        if (t3.getContentType().getValueHandler() != null) {
            return t3;
        }
        JsonDeserializer<Object> deserializerInstance = deserializationContext.deserializerInstance(annotated, annotationIntrospector.findContentDeserializer(annotated));
        if (deserializerInstance != null) {
            return t3.withContentValueHandler(deserializerInstance);
        }
        return t3;
    }

    /* access modifiers changed from: protected */
    public JavaType resolveType(DeserializationContext deserializationContext, BeanDescription beanDescription, JavaType javaType, AnnotatedMember annotatedMember) throws JsonMappingException {
        TypeDeserializer findTypeDeserializer;
        if (javaType.isContainerType()) {
            AnnotationIntrospector annotationIntrospector = deserializationContext.getAnnotationIntrospector();
            if (javaType.getKeyType() != null) {
                KeyDeserializer keyDeserializerInstance = deserializationContext.keyDeserializerInstance(annotatedMember, annotationIntrospector.findKeyDeserializer(annotatedMember));
                if (keyDeserializerInstance != null) {
                    javaType = ((MapLikeType) javaType).withKeyValueHandler(keyDeserializerInstance);
                    javaType.getKeyType();
                }
            }
            JsonDeserializer<Object> deserializerInstance = deserializationContext.deserializerInstance(annotatedMember, annotationIntrospector.findContentDeserializer(annotatedMember));
            if (deserializerInstance != null) {
                javaType = javaType.withContentValueHandler(deserializerInstance);
            }
            if (annotatedMember instanceof AnnotatedMember) {
                TypeDeserializer findPropertyContentTypeDeserializer = findPropertyContentTypeDeserializer(deserializationContext.getConfig(), javaType, annotatedMember);
                if (findPropertyContentTypeDeserializer != null) {
                    javaType = javaType.withContentTypeHandler(findPropertyContentTypeDeserializer);
                }
            }
        }
        if (annotatedMember instanceof AnnotatedMember) {
            findTypeDeserializer = findPropertyTypeDeserializer(deserializationContext.getConfig(), javaType, annotatedMember);
        } else {
            findTypeDeserializer = findTypeDeserializer(deserializationContext.getConfig(), javaType);
        }
        if (findTypeDeserializer != null) {
            return javaType.withTypeHandler(findTypeDeserializer);
        }
        return javaType;
    }

    /* JADX WARNING: type inference failed for: r3v0, types: [java.lang.Class<?>, java.lang.Class] */
    /* access modifiers changed from: protected */
    /* JADX WARNING: Unknown variable types count: 1 */
    public EnumResolver<?> constructEnumResolver(Class<?> r3, DeserializationConfig deserializationConfig, AnnotatedMethod annotatedMethod) {
        if (annotatedMethod != null) {
            Method annotated = annotatedMethod.getAnnotated();
            if (deserializationConfig.canOverrideAccessModifiers()) {
                ClassUtil.checkAndFixAccess(annotated);
            }
            return EnumResolver.constructUnsafeUsingMethod(r3, annotated);
        } else if (deserializationConfig.isEnabled(DeserializationFeature.READ_ENUMS_USING_TO_STRING)) {
            return EnumResolver.constructUnsafeUsingToString(r3);
        } else {
            return EnumResolver.constructUnsafe(r3, deserializationConfig.getAnnotationIntrospector());
        }
    }

    /* access modifiers changed from: protected */
    public AnnotatedMethod _findJsonValueFor(DeserializationConfig deserializationConfig, JavaType javaType) {
        if (javaType == null) {
            return null;
        }
        return deserializationConfig.introspect(javaType).findJsonValueMethod();
    }
}