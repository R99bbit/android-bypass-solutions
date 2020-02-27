package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import java.io.IOException;
import java.util.Arrays;
import java.util.UUID;

public class UUIDDeserializer extends FromStringDeserializer<UUID> {
    static final int[] HEX_DIGITS = new int[127];
    public static final UUIDDeserializer instance = new UUIDDeserializer();
    private static final long serialVersionUID = 1;

    static {
        Arrays.fill(HEX_DIGITS, -1);
        for (int i = 0; i < 10; i++) {
            HEX_DIGITS[i + 48] = i;
        }
        for (int i2 = 0; i2 < 6; i2++) {
            HEX_DIGITS[i2 + 97] = i2 + 10;
            HEX_DIGITS[i2 + 65] = i2 + 10;
        }
    }

    public UUIDDeserializer() {
        super(UUID.class);
    }

    /* access modifiers changed from: protected */
    public UUID _deserialize(String str, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        if (str.length() != 36) {
            if (str.length() == 24) {
                return _fromBytes(Base64Variants.getDefaultVariant().decode(str), deserializationContext);
            }
            _badFormat(str);
        }
        if (!(str.charAt(8) == '-' && str.charAt(13) == '-' && str.charAt(18) == '-' && str.charAt(23) == '-')) {
            _badFormat(str);
        }
        return new UUID(((((long) shortFromChars(str, 9)) << 16) | ((long) shortFromChars(str, 14))) + (((long) intFromChars(str, 0)) << 32), ((((long) intFromChars(str, 28)) << 32) >>> 32) | (((long) ((shortFromChars(str, 19) << 16) | shortFromChars(str, 24))) << 32));
    }

    /* access modifiers changed from: protected */
    public UUID _deserializeEmbedded(Object obj, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        if (obj instanceof byte[]) {
            return _fromBytes((byte[]) obj, deserializationContext);
        }
        super._deserializeEmbedded(obj, deserializationContext);
        return null;
    }

    private void _badFormat(String str) {
        throw new NumberFormatException("UUID has to be represented by the standard 36-char representation");
    }

    static int intFromChars(String str, int i) {
        return (byteFromChars(str, i) << 24) + (byteFromChars(str, i + 2) << 16) + (byteFromChars(str, i + 4) << 8) + byteFromChars(str, i + 6);
    }

    static int shortFromChars(String str, int i) {
        return (byteFromChars(str, i) << 8) + byteFromChars(str, i + 2);
    }

    static int byteFromChars(String str, int i) {
        char charAt = str.charAt(i);
        char charAt2 = str.charAt(i + 1);
        if (charAt <= 127 && charAt2 <= 127) {
            int i2 = (HEX_DIGITS[charAt] << 4) | HEX_DIGITS[charAt2];
            if (i2 >= 0) {
                return i2;
            }
        }
        if (charAt > 127 || HEX_DIGITS[charAt] < 0) {
            return _badChar(str, i, charAt);
        }
        return _badChar(str, i + 1, charAt2);
    }

    static int _badChar(String str, int i, char c) {
        throw new NumberFormatException("Non-hex character '" + c + "', not valid character for a UUID String" + "' (value 0x" + Integer.toHexString(c) + ") for UUID String \"" + str + "\"");
    }

    private UUID _fromBytes(byte[] bArr, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
        if (bArr.length != 16) {
            deserializationContext.mappingException("Can only construct UUIDs from byte[16]; got " + bArr.length + " bytes");
        }
        return new UUID(_long(bArr, 0), _long(bArr, 8));
    }

    private static long _long(byte[] bArr, int i) {
        return (((long) _int(bArr, i)) << 32) | ((((long) _int(bArr, i + 4)) << 32) >>> 32);
    }

    private static int _int(byte[] bArr, int i) {
        return (bArr[i] << 24) | ((bArr[i + 1] & 255) << 16) | ((bArr[i + 2] & 255) << 8) | (bArr[i + 3] & 255);
    }
}