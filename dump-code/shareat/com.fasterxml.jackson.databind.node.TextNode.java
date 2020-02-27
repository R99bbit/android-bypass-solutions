package com.fasterxml.jackson.databind.node;

import com.facebook.internal.ServerProtocol;
import com.fasterxml.jackson.core.Base64Variant;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.io.CharTypes;
import com.fasterxml.jackson.core.io.NumberInput;
import com.fasterxml.jackson.core.util.ByteArrayBuilder;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;

public class TextNode extends ValueNode {
    static final TextNode EMPTY_STRING_NODE = new TextNode("");
    static final int INT_SPACE = 32;
    final String _value;

    public TextNode(String str) {
        this._value = str;
    }

    public static TextNode valueOf(String str) {
        if (str == null) {
            return null;
        }
        if (str.length() == 0) {
            return EMPTY_STRING_NODE;
        }
        return new TextNode(str);
    }

    public JsonNodeType getNodeType() {
        return JsonNodeType.STRING;
    }

    public JsonToken asToken() {
        return JsonToken.VALUE_STRING;
    }

    public String textValue() {
        return this._value;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x002a, code lost:
        _reportInvalidBase64(r12, r0, 0);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:11:0x002d, code lost:
        if (r1 < r5) goto L_0x0032;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:0x002f, code lost:
        _reportBase64EOF();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:13:0x0032, code lost:
        r0 = r1 + 1;
        r1 = r4.charAt(r1);
        r7 = r12.decodeBase64Char(r1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:14:0x003c, code lost:
        if (r7 >= 0) goto L_0x0042;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x003e, code lost:
        _reportInvalidBase64(r12, r1, 1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0042, code lost:
        r1 = (r6 << 6) | r7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:17:0x0045, code lost:
        if (r0 < r5) goto L_0x0056;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:19:0x004b, code lost:
        if (r12.usesPadding() != false) goto L_0x0053;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:0x004d, code lost:
        r3.append(r1 >> 4);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:21:0x0053, code lost:
        _reportBase64EOF();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:22:0x0056, code lost:
        r6 = r0 + 1;
        r0 = r4.charAt(r0);
        r7 = r12.decodeBase64Char(r0);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:23:0x0060, code lost:
        if (r7 >= 0) goto L_0x00a2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:24:0x0062, code lost:
        if (r7 == -2) goto L_0x0068;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x0064, code lost:
        _reportInvalidBase64(r12, r0, 2);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x0068, code lost:
        if (r6 < r5) goto L_0x006d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:27:0x006a, code lost:
        _reportBase64EOF();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:0x006d, code lost:
        r0 = r6 + 1;
        r6 = r4.charAt(r6);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:29:0x0077, code lost:
        if (r12.usesPaddingChar(r6) != false) goto L_0x009b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x0079, code lost:
        _reportInvalidBase64(r12, r6, 3, "expected padding character '" + r12.getPaddingChar() + "'");
     */
    /* JADX WARNING: Code restructure failed: missing block: B:31:0x009b, code lost:
        r3.append(r1 >> 4);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:32:0x00a2, code lost:
        r1 = (r1 << 6) | r7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:33:0x00a6, code lost:
        if (r6 < r5) goto L_0x00b8;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:35:0x00ac, code lost:
        if (r12.usesPadding() != false) goto L_0x00b5;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:36:0x00ae, code lost:
        r3.appendTwoBytes(r1 >> 2);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:37:0x00b5, code lost:
        _reportBase64EOF();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:38:0x00b8, code lost:
        r0 = r6 + 1;
        r6 = r4.charAt(r6);
        r7 = r12.decodeBase64Char(r6);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:0x00c2, code lost:
        if (r7 >= 0) goto L_0x00d0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:40:0x00c4, code lost:
        if (r7 == -2) goto L_0x00c9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:41:0x00c6, code lost:
        _reportInvalidBase64(r12, r6, 3);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:42:0x00c9, code lost:
        r3.appendTwoBytes(r1 >> 2);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:43:0x00d0, code lost:
        r3.appendThreeBytes((r1 << 6) | r7);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x0024, code lost:
        r6 = r12.decodeBase64Char(r0);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0028, code lost:
        if (r6 >= 0) goto L_0x002d;
     */
    public byte[] getBinaryValue(Base64Variant base64Variant) throws IOException {
        ByteArrayBuilder byteArrayBuilder = new ByteArrayBuilder(100);
        String str = this._value;
        int length = str.length();
        int i = 0;
        loop0:
        while (true) {
            if (i >= length) {
                break;
            }
            while (true) {
                int i2 = i + 1;
                char charAt = str.charAt(i);
                if (i2 >= length) {
                    break loop0;
                } else if (charAt > ' ') {
                    break;
                } else {
                    i = i2;
                }
            }
        }
        return byteArrayBuilder.toByteArray();
    }

    public byte[] binaryValue() throws IOException {
        return getBinaryValue(Base64Variants.getDefaultVariant());
    }

    public String asText() {
        return this._value;
    }

    public boolean asBoolean(boolean z) {
        if (this._value == null || !ServerProtocol.DIALOG_RETURN_SCOPES_TRUE.equals(this._value.trim())) {
            return z;
        }
        return true;
    }

    public int asInt(int i) {
        return NumberInput.parseAsInt(this._value, i);
    }

    public long asLong(long j) {
        return NumberInput.parseAsLong(this._value, j);
    }

    public double asDouble(double d) {
        return NumberInput.parseAsDouble(this._value, d);
    }

    public final void serialize(JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonProcessingException {
        if (this._value == null) {
            jsonGenerator.writeNull();
        } else {
            jsonGenerator.writeString(this._value);
        }
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || !(obj instanceof TextNode)) {
            return false;
        }
        return ((TextNode) obj)._value.equals(this._value);
    }

    public int hashCode() {
        return this._value.hashCode();
    }

    public String toString() {
        int length = this._value.length();
        StringBuilder sb = new StringBuilder((length >> 4) + length + 2);
        appendQuoted(sb, this._value);
        return sb.toString();
    }

    protected static void appendQuoted(StringBuilder sb, String str) {
        sb.append('\"');
        CharTypes.appendQuoted(sb, str);
        sb.append('\"');
    }

    /* access modifiers changed from: protected */
    public void _reportInvalidBase64(Base64Variant base64Variant, char c, int i) throws JsonParseException {
        _reportInvalidBase64(base64Variant, c, i, null);
    }

    /* access modifiers changed from: protected */
    public void _reportInvalidBase64(Base64Variant base64Variant, char c, int i, String str) throws JsonParseException {
        String str2;
        if (c <= ' ') {
            str2 = "Illegal white space character (code 0x" + Integer.toHexString(c) + ") as character #" + (i + 1) + " of 4-char base64 unit: can only used between units";
        } else if (base64Variant.usesPaddingChar(c)) {
            str2 = "Unexpected padding character ('" + base64Variant.getPaddingChar() + "') as character #" + (i + 1) + " of 4-char base64 unit: padding only legal as 3rd or 4th character";
        } else if (!Character.isDefined(c) || Character.isISOControl(c)) {
            str2 = "Illegal character (code 0x" + Integer.toHexString(c) + ") in base64 content";
        } else {
            str2 = "Illegal character '" + c + "' (code 0x" + Integer.toHexString(c) + ") in base64 content";
        }
        if (str != null) {
            str2 = str2 + ": " + str;
        }
        throw new JsonParseException(str2, JsonLocation.NA);
    }

    /* access modifiers changed from: protected */
    public void _reportBase64EOF() throws JsonParseException {
        throw new JsonParseException("Unexpected end-of-String when base64 content", JsonLocation.NA);
    }
}