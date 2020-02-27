package com.fasterxml.jackson.databind.ser.std;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.util.ByteBufferBackedInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class ByteBufferSerializer extends StdScalarSerializer<ByteBuffer> {
    public static final ByteBufferSerializer instance = new ByteBufferSerializer();

    public ByteBufferSerializer() {
        super(ByteBuffer.class);
    }

    public void serialize(ByteBuffer byteBuffer, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException, JsonGenerationException {
        if (byteBuffer.hasArray()) {
            jsonGenerator.writeBinary(byteBuffer.array(), 0, byteBuffer.limit());
            return;
        }
        ByteBuffer asReadOnlyBuffer = byteBuffer.asReadOnlyBuffer();
        if (asReadOnlyBuffer.position() > 0) {
            asReadOnlyBuffer.rewind();
        }
        ByteBufferBackedInputStream byteBufferBackedInputStream = new ByteBufferBackedInputStream(asReadOnlyBuffer);
        jsonGenerator.writeBinary(byteBufferBackedInputStream, asReadOnlyBuffer.remaining());
        byteBufferBackedInputStream.close();
    }
}