package com.fasterxml.jackson.databind.deser.impl;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import com.fasterxml.jackson.databind.util.TokenBuffer;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class ExternalTypeHandler {
    private final HashMap<String, Integer> _nameToPropertyIndex;
    private final ExtTypedProperty[] _properties;
    private final TokenBuffer[] _tokens;
    private final String[] _typeIds;

    public static class Builder {
        private final HashMap<String, Integer> _nameToPropertyIndex = new HashMap<>();
        private final ArrayList<ExtTypedProperty> _properties = new ArrayList<>();

        public void addExternal(SettableBeanProperty settableBeanProperty, TypeDeserializer typeDeserializer) {
            Integer valueOf = Integer.valueOf(this._properties.size());
            this._properties.add(new ExtTypedProperty(settableBeanProperty, typeDeserializer));
            this._nameToPropertyIndex.put(settableBeanProperty.getName(), valueOf);
            this._nameToPropertyIndex.put(typeDeserializer.getPropertyName(), valueOf);
        }

        public ExternalTypeHandler build() {
            return new ExternalTypeHandler((ExtTypedProperty[]) this._properties.toArray(new ExtTypedProperty[this._properties.size()]), this._nameToPropertyIndex, null, null);
        }
    }

    private static final class ExtTypedProperty {
        private final SettableBeanProperty _property;
        private final TypeDeserializer _typeDeserializer;
        private final String _typePropertyName;

        public ExtTypedProperty(SettableBeanProperty settableBeanProperty, TypeDeserializer typeDeserializer) {
            this._property = settableBeanProperty;
            this._typeDeserializer = typeDeserializer;
            this._typePropertyName = typeDeserializer.getPropertyName();
        }

        public boolean hasTypePropertyName(String str) {
            return str.equals(this._typePropertyName);
        }

        public boolean hasDefaultType() {
            return this._typeDeserializer.getDefaultImpl() != null;
        }

        public String getDefaultTypeId() {
            Class<?> defaultImpl = this._typeDeserializer.getDefaultImpl();
            if (defaultImpl == null) {
                return null;
            }
            return this._typeDeserializer.getTypeIdResolver().idFromValueAndType(null, defaultImpl);
        }

        public String getTypePropertyName() {
            return this._typePropertyName;
        }

        public SettableBeanProperty getProperty() {
            return this._property;
        }
    }

    protected ExternalTypeHandler(ExtTypedProperty[] extTypedPropertyArr, HashMap<String, Integer> hashMap, String[] strArr, TokenBuffer[] tokenBufferArr) {
        this._properties = extTypedPropertyArr;
        this._nameToPropertyIndex = hashMap;
        this._typeIds = strArr;
        this._tokens = tokenBufferArr;
    }

    protected ExternalTypeHandler(ExternalTypeHandler externalTypeHandler) {
        this._properties = externalTypeHandler._properties;
        this._nameToPropertyIndex = externalTypeHandler._nameToPropertyIndex;
        int length = this._properties.length;
        this._typeIds = new String[length];
        this._tokens = new TokenBuffer[length];
    }

    public ExternalTypeHandler start() {
        return new ExternalTypeHandler(this);
    }

    public boolean handleTypePropertyValue(JsonParser jsonParser, DeserializationContext deserializationContext, String str, Object obj) throws IOException, JsonProcessingException {
        boolean z = false;
        Integer num = this._nameToPropertyIndex.get(str);
        if (num == null) {
            return false;
        }
        int intValue = num.intValue();
        if (!this._properties[intValue].hasTypePropertyName(str)) {
            return false;
        }
        String text = jsonParser.getText();
        if (!(obj == null || this._tokens[intValue] == null)) {
            z = true;
        }
        if (z) {
            _deserializeAndSet(jsonParser, deserializationContext, obj, intValue, text);
            this._tokens[intValue] = null;
        } else {
            this._typeIds[intValue] = text;
        }
        return true;
    }

    public boolean handlePropertyValue(JsonParser jsonParser, DeserializationContext deserializationContext, String str, Object obj) throws IOException, JsonProcessingException {
        boolean z;
        boolean z2 = false;
        Integer num = this._nameToPropertyIndex.get(str);
        if (num == null) {
            return false;
        }
        int intValue = num.intValue();
        if (this._properties[intValue].hasTypePropertyName(str)) {
            this._typeIds[intValue] = jsonParser.getText();
            jsonParser.skipChildren();
            if (obj == null || this._tokens[intValue] == null) {
                z = false;
            } else {
                z = true;
            }
        } else {
            TokenBuffer tokenBuffer = new TokenBuffer(jsonParser);
            tokenBuffer.copyCurrentStructure(jsonParser);
            this._tokens[intValue] = tokenBuffer;
            if (!(obj == null || this._typeIds[intValue] == null)) {
                z2 = true;
            }
            z = z2;
        }
        if (z) {
            String str2 = this._typeIds[intValue];
            this._typeIds[intValue] = null;
            _deserializeAndSet(jsonParser, deserializationContext, obj, intValue, str2);
            this._tokens[intValue] = null;
        }
        return true;
    }

    public Object complete(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj) throws IOException, JsonProcessingException {
        String str;
        int length = this._properties.length;
        for (int i = 0; i < length; i++) {
            String str2 = this._typeIds[i];
            if (str2 == null) {
                TokenBuffer tokenBuffer = this._tokens[i];
                if (tokenBuffer == null) {
                    continue;
                } else {
                    JsonToken firstToken = tokenBuffer.firstToken();
                    if (firstToken != null && firstToken.isScalarValue()) {
                        JsonParser asParser = tokenBuffer.asParser(jsonParser);
                        asParser.nextToken();
                        SettableBeanProperty property = this._properties[i].getProperty();
                        Object deserializeIfNatural = TypeDeserializer.deserializeIfNatural(asParser, deserializationContext, property.getType());
                        if (deserializeIfNatural != null) {
                            property.set(obj, deserializeIfNatural);
                        } else if (!this._properties[i].hasDefaultType()) {
                            throw deserializationContext.mappingException("Missing external type id property '" + this._properties[i].getTypePropertyName() + "'");
                        } else {
                            str2 = this._properties[i].getDefaultTypeId();
                        }
                    }
                    str = str2;
                    _deserializeAndSet(jsonParser, deserializationContext, obj, i, str);
                }
            } else if (this._tokens[i] == null) {
                throw deserializationContext.mappingException("Missing property '" + this._properties[i].getProperty().getName() + "' for external type id '" + this._properties[i].getTypePropertyName());
            } else {
                str = str2;
                _deserializeAndSet(jsonParser, deserializationContext, obj, i, str);
            }
        }
        return obj;
    }

    public Object complete(JsonParser jsonParser, DeserializationContext deserializationContext, PropertyValueBuffer propertyValueBuffer, PropertyBasedCreator propertyBasedCreator) throws IOException, JsonProcessingException {
        int length = this._properties.length;
        Object[] objArr = new Object[length];
        for (int i = 0; i < length; i++) {
            String str = this._typeIds[i];
            if (str != null) {
                if (this._tokens[i] == null) {
                    throw deserializationContext.mappingException("Missing property '" + this._properties[i].getProperty().getName() + "' for external type id '" + this._properties[i].getTypePropertyName());
                }
                objArr[i] = _deserialize(jsonParser, deserializationContext, i, str);
            } else if (this._tokens[i] == null) {
                continue;
            } else if (!this._properties[i].hasDefaultType()) {
                throw deserializationContext.mappingException("Missing external type id property '" + this._properties[i].getTypePropertyName() + "'");
            } else {
                str = this._properties[i].getDefaultTypeId();
                objArr[i] = _deserialize(jsonParser, deserializationContext, i, str);
            }
        }
        for (int i2 = 0; i2 < length; i2++) {
            SettableBeanProperty property = this._properties[i2].getProperty();
            if (propertyBasedCreator.findCreatorProperty(property.getName()) != null) {
                propertyValueBuffer.assignParameter(property.getCreatorIndex(), objArr[i2]);
            }
        }
        Object build = propertyBasedCreator.build(deserializationContext, propertyValueBuffer);
        for (int i3 = 0; i3 < length; i3++) {
            SettableBeanProperty property2 = this._properties[i3].getProperty();
            if (propertyBasedCreator.findCreatorProperty(property2.getName()) == null) {
                property2.set(build, objArr[i3]);
            }
        }
        return build;
    }

    /* access modifiers changed from: protected */
    public final Object _deserialize(JsonParser jsonParser, DeserializationContext deserializationContext, int i, String str) throws IOException, JsonProcessingException {
        TokenBuffer tokenBuffer = new TokenBuffer(jsonParser);
        tokenBuffer.writeStartArray();
        tokenBuffer.writeString(str);
        JsonParser asParser = this._tokens[i].asParser(jsonParser);
        asParser.nextToken();
        tokenBuffer.copyCurrentStructure(asParser);
        tokenBuffer.writeEndArray();
        JsonParser asParser2 = tokenBuffer.asParser(jsonParser);
        asParser2.nextToken();
        return this._properties[i].getProperty().deserialize(asParser2, deserializationContext);
    }

    /* access modifiers changed from: protected */
    public final void _deserializeAndSet(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj, int i, String str) throws IOException, JsonProcessingException {
        TokenBuffer tokenBuffer = new TokenBuffer(jsonParser);
        tokenBuffer.writeStartArray();
        tokenBuffer.writeString(str);
        JsonParser asParser = this._tokens[i].asParser(jsonParser);
        asParser.nextToken();
        tokenBuffer.copyCurrentStructure(asParser);
        tokenBuffer.writeEndArray();
        JsonParser asParser2 = tokenBuffer.asParser(jsonParser);
        asParser2.nextToken();
        this._properties[i].getProperty().deserializeAndSet(asParser2, deserializationContext, obj);
    }
}