package com.fasterxml.jackson.core;

import com.facebook.internal.ServerProtocol;

public enum JsonToken {
    NOT_AVAILABLE(null, -1),
    START_OBJECT("{", 1),
    END_OBJECT("}", 2),
    START_ARRAY("[", 3),
    END_ARRAY("]", 4),
    FIELD_NAME(null, 5),
    VALUE_EMBEDDED_OBJECT(null, 12),
    VALUE_STRING(null, 6),
    VALUE_NUMBER_INT(null, 7),
    VALUE_NUMBER_FLOAT(null, 8),
    VALUE_TRUE(ServerProtocol.DIALOG_RETURN_SCOPES_TRUE, 9),
    VALUE_FALSE("false", 10),
    VALUE_NULL("null", 11);
    
    final int _id;
    final boolean _isBoolean;
    final boolean _isNumber;
    final boolean _isScalar;
    final boolean _isStructEnd;
    final boolean _isStructStart;
    final String _serialized;
    final byte[] _serializedBytes;
    final char[] _serializedChars;

    private JsonToken(String str, int i) {
        boolean z;
        boolean z2;
        boolean z3;
        boolean z4;
        boolean z5 = true;
        if (str == null) {
            this._serialized = null;
            this._serializedChars = null;
            this._serializedBytes = null;
        } else {
            this._serialized = str;
            this._serializedChars = str.toCharArray();
            int length = this._serializedChars.length;
            this._serializedBytes = new byte[length];
            for (int i2 = 0; i2 < length; i2++) {
                this._serializedBytes[i2] = (byte) this._serializedChars[i2];
            }
        }
        this._id = i;
        if (i == 10 || i == 9) {
            z = true;
        } else {
            z = false;
        }
        this._isBoolean = z;
        if (i == 7 || i == 8) {
            z2 = true;
        } else {
            z2 = false;
        }
        this._isNumber = z2;
        if (i == 1 || i == 3) {
            z3 = true;
        } else {
            z3 = false;
        }
        this._isStructStart = z3;
        if (i == 2 || i == 4) {
            z4 = true;
        } else {
            z4 = false;
        }
        this._isStructEnd = z4;
        this._isScalar = (this._isStructStart || this._isStructEnd || i == 5 || i == -1) ? false : z5;
    }

    public final int id() {
        return this._id;
    }

    public final String asString() {
        return this._serialized;
    }

    public final char[] asCharArray() {
        return this._serializedChars;
    }

    public final byte[] asByteArray() {
        return this._serializedBytes;
    }

    public final boolean isNumeric() {
        return this._isNumber;
    }

    public final boolean isStructStart() {
        return this._isStructStart;
    }

    public final boolean isStructEnd() {
        return this._isStructEnd;
    }

    public final boolean isScalarValue() {
        return this._isScalar;
    }

    public final boolean isBoolean() {
        return this._isBoolean;
    }
}