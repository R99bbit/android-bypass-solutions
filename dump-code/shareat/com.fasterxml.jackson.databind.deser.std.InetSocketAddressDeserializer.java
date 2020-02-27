package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import java.io.IOException;
import java.net.InetSocketAddress;

public class InetSocketAddressDeserializer extends FromStringDeserializer<InetSocketAddress> {
    public static final InetSocketAddressDeserializer instance = new InetSocketAddressDeserializer();
    private static final long serialVersionUID = 1;

    public InetSocketAddressDeserializer() {
        super(InetSocketAddress.class);
    }

    /* access modifiers changed from: protected */
    public InetSocketAddress _deserialize(String str, DeserializationContext deserializationContext) throws IOException {
        if (str.startsWith("[")) {
            int lastIndexOf = str.lastIndexOf(93);
            if (lastIndexOf == -1) {
                throw new InvalidFormatException("Bracketed IPv6 address must contain closing bracket.", str, InetSocketAddress.class);
            }
            int indexOf = str.indexOf(58, lastIndexOf);
            return new InetSocketAddress(str.substring(0, lastIndexOf + 1), indexOf > -1 ? Integer.parseInt(str.substring(indexOf + 1)) : 0);
        }
        int indexOf2 = str.indexOf(58);
        if (indexOf2 == -1 || str.indexOf(58, indexOf2 + 1) != -1) {
            return new InetSocketAddress(str, 0);
        }
        return new InetSocketAddress(str.substring(0, indexOf2), Integer.parseInt(str.substring(indexOf2)));
    }
}