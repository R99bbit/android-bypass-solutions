package com.ning.http.client;

import java.io.IOException;
import java.nio.channels.WritableByteChannel;

public interface RandomAccessBody extends Body {
    long transferTo(long j, long j2, WritableByteChannel writableByteChannel) throws IOException;
}