package com.fasterxml.jackson.databind.deser.impl;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;
import com.fasterxml.jackson.databind.deser.ValueInstantiator;
import com.fasterxml.jackson.databind.util.ClassUtil;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;

public final class PropertyBasedCreator {
    protected final Object[] _defaultValues;
    protected final HashMap<String, SettableBeanProperty> _properties = new HashMap<>();
    protected final SettableBeanProperty[] _propertiesWithInjectables;
    protected final int _propertyCount;
    protected final ValueInstantiator _valueInstantiator;

    protected PropertyBasedCreator(ValueInstantiator valueInstantiator, SettableBeanProperty[] settableBeanPropertyArr, Object[] objArr) {
        this._valueInstantiator = valueInstantiator;
        int length = settableBeanPropertyArr.length;
        this._propertyCount = length;
        SettableBeanProperty[] settableBeanPropertyArr2 = null;
        for (int i = 0; i < length; i++) {
            SettableBeanProperty settableBeanProperty = settableBeanPropertyArr[i];
            this._properties.put(settableBeanProperty.getName(), settableBeanProperty);
            if (settableBeanProperty.getInjectableValueId() != null) {
                settableBeanPropertyArr2 = settableBeanPropertyArr2 == null ? new SettableBeanProperty[length] : settableBeanPropertyArr2;
                settableBeanPropertyArr2[i] = settableBeanProperty;
            }
        }
        this._defaultValues = objArr;
        this._propertiesWithInjectables = settableBeanPropertyArr2;
    }

    public static PropertyBasedCreator construct(DeserializationContext deserializationContext, ValueInstantiator valueInstantiator, SettableBeanProperty[] settableBeanPropertyArr) throws JsonMappingException {
        Object obj;
        int length = settableBeanPropertyArr.length;
        SettableBeanProperty[] settableBeanPropertyArr2 = new SettableBeanProperty[length];
        Object[] objArr = null;
        for (int i = 0; i < length; i++) {
            SettableBeanProperty settableBeanProperty = settableBeanPropertyArr[i];
            if (!settableBeanProperty.hasValueDeserializer()) {
                settableBeanProperty = settableBeanProperty.withValueDeserializer(deserializationContext.findContextualValueDeserializer(settableBeanProperty.getType(), settableBeanProperty));
            }
            settableBeanPropertyArr2[i] = settableBeanProperty;
            JsonDeserializer<Object> valueDeserializer = settableBeanProperty.getValueDeserializer();
            Object nullValue = valueDeserializer == null ? null : valueDeserializer.getNullValue();
            if (nullValue != null || !settableBeanProperty.getType().isPrimitive()) {
                obj = nullValue;
            } else {
                obj = ClassUtil.defaultValue(settableBeanProperty.getType().getRawClass());
            }
            if (obj != null) {
                if (objArr == null) {
                    objArr = new Object[length];
                }
                objArr[i] = obj;
            }
        }
        return new PropertyBasedCreator(valueInstantiator, settableBeanPropertyArr2, objArr);
    }

    public void assignDeserializer(SettableBeanProperty settableBeanProperty, JsonDeserializer<Object> jsonDeserializer) {
        SettableBeanProperty withValueDeserializer = settableBeanProperty.withValueDeserializer(jsonDeserializer);
        this._properties.put(withValueDeserializer.getName(), withValueDeserializer);
    }

    public Collection<SettableBeanProperty> properties() {
        return this._properties.values();
    }

    public SettableBeanProperty findCreatorProperty(String str) {
        return this._properties.get(str);
    }

    public SettableBeanProperty findCreatorProperty(int i) {
        for (SettableBeanProperty next : this._properties.values()) {
            if (next.getPropertyIndex() == i) {
                return next;
            }
        }
        return null;
    }

    public PropertyValueBuffer startBuilding(JsonParser jsonParser, DeserializationContext deserializationContext, ObjectIdReader objectIdReader) {
        PropertyValueBuffer propertyValueBuffer = new PropertyValueBuffer(jsonParser, deserializationContext, this._propertyCount, objectIdReader);
        if (this._propertiesWithInjectables != null) {
            propertyValueBuffer.inject(this._propertiesWithInjectables);
        }
        return propertyValueBuffer;
    }

    public Object build(DeserializationContext deserializationContext, PropertyValueBuffer propertyValueBuffer) throws IOException {
        Object handleIdValue = propertyValueBuffer.handleIdValue(deserializationContext, this._valueInstantiator.createFromObjectWith(deserializationContext, propertyValueBuffer.getParameters(this._defaultValues)));
        for (PropertyValue buffered = propertyValueBuffer.buffered(); buffered != null; buffered = buffered.next) {
            buffered.assign(handleIdValue);
        }
        return handleIdValue;
    }
}