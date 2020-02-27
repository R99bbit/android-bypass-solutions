package com.fasterxml.jackson.databind.cfg;

import com.fasterxml.jackson.databind.ser.BeanSerializerModifier;
import com.fasterxml.jackson.databind.ser.Serializers;
import com.fasterxml.jackson.databind.util.ArrayBuilders;
import java.io.Serializable;

public final class SerializerFactoryConfig implements Serializable {
    protected static final BeanSerializerModifier[] NO_MODIFIERS = new BeanSerializerModifier[0];
    protected static final Serializers[] NO_SERIALIZERS = new Serializers[0];
    private static final long serialVersionUID = 1;
    protected final Serializers[] _additionalKeySerializers;
    protected final Serializers[] _additionalSerializers;
    protected final BeanSerializerModifier[] _modifiers;

    public SerializerFactoryConfig() {
        this(null, null, null);
    }

    protected SerializerFactoryConfig(Serializers[] serializersArr, Serializers[] serializersArr2, BeanSerializerModifier[] beanSerializerModifierArr) {
        this._additionalSerializers = serializersArr == null ? NO_SERIALIZERS : serializersArr;
        this._additionalKeySerializers = serializersArr2 == null ? NO_SERIALIZERS : serializersArr2;
        this._modifiers = beanSerializerModifierArr == null ? NO_MODIFIERS : beanSerializerModifierArr;
    }

    public SerializerFactoryConfig withAdditionalSerializers(Serializers serializers) {
        if (serializers != null) {
            return new SerializerFactoryConfig((Serializers[]) ArrayBuilders.insertInListNoDup(this._additionalSerializers, serializers), this._additionalKeySerializers, this._modifiers);
        }
        throw new IllegalArgumentException("Can not pass null Serializers");
    }

    public SerializerFactoryConfig withAdditionalKeySerializers(Serializers serializers) {
        if (serializers == null) {
            throw new IllegalArgumentException("Can not pass null Serializers");
        }
        return new SerializerFactoryConfig(this._additionalSerializers, (Serializers[]) ArrayBuilders.insertInListNoDup(this._additionalKeySerializers, serializers), this._modifiers);
    }

    public SerializerFactoryConfig withSerializerModifier(BeanSerializerModifier beanSerializerModifier) {
        if (beanSerializerModifier == null) {
            throw new IllegalArgumentException("Can not pass null modifier");
        }
        return new SerializerFactoryConfig(this._additionalSerializers, this._additionalKeySerializers, (BeanSerializerModifier[]) ArrayBuilders.insertInListNoDup(this._modifiers, beanSerializerModifier));
    }

    public boolean hasSerializers() {
        return this._additionalSerializers.length > 0;
    }

    public boolean hasKeySerializers() {
        return this._additionalKeySerializers.length > 0;
    }

    public boolean hasSerializerModifiers() {
        return this._modifiers.length > 0;
    }

    public Iterable<Serializers> serializers() {
        return ArrayBuilders.arrayAsIterable(this._additionalSerializers);
    }

    public Iterable<Serializers> keySerializers() {
        return ArrayBuilders.arrayAsIterable(this._additionalKeySerializers);
    }

    public Iterable<BeanSerializerModifier> serializerModifiers() {
        return ArrayBuilders.arrayAsIterable(this._modifiers);
    }
}