package com.fasterxml.jackson.databind.node;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser.NumberType;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;

public class BigIntegerNode extends NumericNode {
    private static final BigInteger MAX_INTEGER = BigInteger.valueOf(2147483647L);
    private static final BigInteger MAX_LONG = BigInteger.valueOf(Long.MAX_VALUE);
    private static final BigInteger MIN_INTEGER = BigInteger.valueOf(-2147483648L);
    private static final BigInteger MIN_LONG = BigInteger.valueOf(Long.MIN_VALUE);
    protected final BigInteger _value;

    public BigIntegerNode(BigInteger bigInteger) {
        this._value = bigInteger;
    }

    public static BigIntegerNode valueOf(BigInteger bigInteger) {
        return new BigIntegerNode(bigInteger);
    }

    public JsonToken asToken() {
        return JsonToken.VALUE_NUMBER_INT;
    }

    public NumberType numberType() {
        return NumberType.BIG_INTEGER;
    }

    public boolean isIntegralNumber() {
        return true;
    }

    public boolean isBigInteger() {
        return true;
    }

    public boolean canConvertToInt() {
        return this._value.compareTo(MIN_INTEGER) >= 0 && this._value.compareTo(MAX_INTEGER) <= 0;
    }

    public boolean canConvertToLong() {
        return this._value.compareTo(MIN_LONG) >= 0 && this._value.compareTo(MAX_LONG) <= 0;
    }

    public Number numberValue() {
        return this._value;
    }

    public short shortValue() {
        return this._value.shortValue();
    }

    public int intValue() {
        return this._value.intValue();
    }

    public long longValue() {
        return this._value.longValue();
    }

    public BigInteger bigIntegerValue() {
        return this._value;
    }

    public float floatValue() {
        return this._value.floatValue();
    }

    public double doubleValue() {
        return this._value.doubleValue();
    }

    public BigDecimal decimalValue() {
        return new BigDecimal(this._value);
    }

    public String asText() {
        return this._value.toString();
    }

    public boolean asBoolean(boolean z) {
        return !BigInteger.ZERO.equals(this._value);
    }

    public final void serialize(JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonProcessingException {
        jsonGenerator.writeNumber(this._value);
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || !(obj instanceof BigIntegerNode)) {
            return false;
        }
        return ((BigIntegerNode) obj)._value.equals(this._value);
    }

    public int hashCode() {
        return this._value.hashCode();
    }
}