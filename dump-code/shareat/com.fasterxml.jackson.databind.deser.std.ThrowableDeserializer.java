package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.deser.BeanDeserializer;
import com.fasterxml.jackson.databind.deser.BeanDeserializerBase;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;
import com.fasterxml.jackson.databind.util.NameTransformer;
import java.io.IOException;

public class ThrowableDeserializer extends BeanDeserializer {
    protected static final String PROP_NAME_MESSAGE = "message";
    private static final long serialVersionUID = 1;

    public ThrowableDeserializer(BeanDeserializer beanDeserializer) {
        super(beanDeserializer);
        this._vanillaProcessing = false;
    }

    protected ThrowableDeserializer(BeanDeserializer beanDeserializer, NameTransformer nameTransformer) {
        super((BeanDeserializerBase) beanDeserializer, nameTransformer);
    }

    public JsonDeserializer<Object> unwrappingDeserializer(NameTransformer nameTransformer) {
        return getClass() != ThrowableDeserializer.class ? this : new ThrowableDeserializer(this, nameTransformer);
    }

    public Object deserializeFromObject(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        Object createUsingDefault;
        int i;
        Object[] objArr;
        Object obj;
        if (this._propertyBasedCreator != null) {
            return _deserializeUsingPropertyBased(jsonParser, deserializationContext);
        }
        if (this._delegateDeserializer != null) {
            return this._valueInstantiator.createUsingDelegate(deserializationContext, this._delegateDeserializer.deserialize(jsonParser, deserializationContext));
        }
        if (this._beanType.isAbstract()) {
            throw JsonMappingException.from(jsonParser, "Can not instantiate abstract type " + this._beanType + " (need to add/enable type information?)");
        }
        boolean canCreateFromString = this._valueInstantiator.canCreateFromString();
        boolean canCreateUsingDefault = this._valueInstantiator.canCreateUsingDefault();
        if (canCreateFromString || canCreateUsingDefault) {
            int i2 = 0;
            Object[] objArr2 = null;
            Object obj2 = null;
            while (jsonParser.getCurrentToken() != JsonToken.END_OBJECT) {
                String currentName = jsonParser.getCurrentName();
                SettableBeanProperty find = this._beanProperties.find(currentName);
                jsonParser.nextToken();
                if (find == null) {
                    if ("message".equals(currentName) && canCreateFromString) {
                        obj2 = this._valueInstantiator.createFromString(deserializationContext, jsonParser.getText());
                        if (objArr2 != null) {
                            for (int i3 = 0; i3 < i2; i3 += 2) {
                                ((SettableBeanProperty) objArr2[i3]).set(obj2, objArr2[i3 + 1]);
                            }
                            i = i2;
                            obj = obj2;
                            objArr = null;
                        }
                    } else if (this._ignorableProps != null && this._ignorableProps.contains(currentName)) {
                        jsonParser.skipChildren();
                        i = i2;
                        objArr = objArr2;
                        obj = obj2;
                    } else if (this._anySetter != null) {
                        this._anySetter.deserializeAndSet(jsonParser, deserializationContext, obj2, currentName);
                        i = i2;
                        objArr = objArr2;
                        obj = obj2;
                    } else {
                        handleUnknownProperty(jsonParser, deserializationContext, obj2, currentName);
                    }
                    i = i2;
                    objArr = objArr2;
                    obj = obj2;
                } else if (obj2 != null) {
                    find.deserializeAndSet(jsonParser, deserializationContext, obj2);
                    i = i2;
                    objArr = objArr2;
                    obj = obj2;
                } else {
                    if (objArr2 == null) {
                        int size = this._beanProperties.size();
                        objArr2 = new Object[(size + size)];
                    }
                    int i4 = i2 + 1;
                    objArr2[i2] = find;
                    i = i4 + 1;
                    objArr2[i4] = find.deserialize(jsonParser, deserializationContext);
                    objArr = objArr2;
                    obj = obj2;
                }
                jsonParser.nextToken();
                obj2 = obj;
                objArr2 = objArr;
                i2 = i;
            }
            if (obj2 != null) {
                return obj2;
            }
            if (canCreateFromString) {
                createUsingDefault = this._valueInstantiator.createFromString(deserializationContext, null);
            } else {
                createUsingDefault = this._valueInstantiator.createUsingDefault(deserializationContext);
            }
            if (objArr2 == null) {
                return createUsingDefault;
            }
            for (int i5 = 0; i5 < i2; i5 += 2) {
                ((SettableBeanProperty) objArr2[i5]).set(createUsingDefault, objArr2[i5 + 1]);
            }
            return createUsingDefault;
        }
        throw new JsonMappingException("Can not deserialize Throwable of type " + this._beanType + " without having a default contructor, a single-String-arg constructor; or explicit @JsonCreator");
    }
}