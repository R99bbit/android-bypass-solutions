package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.databind.DeserializationContext;
import java.io.IOException;
import java.nio.charset.Charset;

public class CharsetDeserializer extends FromStringDeserializer<Charset> {
    private static final long serialVersionUID = 1;

    public CharsetDeserializer() {
        super(Charset.class);
    }

    /* access modifiers changed from: protected */
    public Charset _deserialize(String str, DeserializationContext deserializationContext) throws IOException {
        return Charset.forName(str);
    }
}