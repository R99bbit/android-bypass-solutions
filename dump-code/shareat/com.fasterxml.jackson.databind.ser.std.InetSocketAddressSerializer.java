package com.fasterxml.jackson.databind.ser.std;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;

public class InetSocketAddressSerializer extends StdScalarSerializer<InetSocketAddress> {
    public static final InetSocketAddressSerializer instance = new InetSocketAddressSerializer();

    public InetSocketAddressSerializer() {
        super(InetSocketAddress.class);
    }

    public void serialize(InetSocketAddress inetSocketAddress, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException {
        InetAddress address = inetSocketAddress.getAddress();
        String trim = address == null ? inetSocketAddress.getHostName() : address.toString().trim();
        int indexOf = trim.indexOf(47);
        if (indexOf >= 0) {
            trim = indexOf == 0 ? address instanceof Inet6Address ? "[" + trim.substring(1) + "]" : trim.substring(1) : trim.substring(0, indexOf);
        }
        jsonGenerator.writeString(trim + ":" + inetSocketAddress.getPort());
    }

    public void serializeWithType(InetSocketAddress inetSocketAddress, JsonGenerator jsonGenerator, SerializerProvider serializerProvider, TypeSerializer typeSerializer) throws IOException, JsonGenerationException {
        typeSerializer.writeTypePrefixForScalar(inetSocketAddress, jsonGenerator, InetSocketAddress.class);
        serialize(inetSocketAddress, jsonGenerator, serializerProvider);
        typeSerializer.writeTypeSuffixForScalar(inetSocketAddress, jsonGenerator);
    }
}