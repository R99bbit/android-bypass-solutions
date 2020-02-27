package org.jboss.netty.handler.codec.compression;

import org.jboss.netty.util.internal.jzlib.JZlib;
import org.jboss.netty.util.internal.jzlib.ZStream;

final class ZlibUtil {
    static void fail(ZStream z, String message, int resultCode) {
        throw exception(z, message, resultCode);
    }

    static CompressionException exception(ZStream z, String message, int resultCode) {
        return new CompressionException(message + " (" + resultCode + ')' + (z.msg != null ? ": " + z.msg : ""));
    }

    static Enum<?> convertWrapperType(ZlibWrapper wrapper) {
        switch (wrapper) {
            case NONE:
                return JZlib.W_NONE;
            case ZLIB:
                return JZlib.W_ZLIB;
            case GZIP:
                return JZlib.W_GZIP;
            case ZLIB_OR_NONE:
                return JZlib.W_ZLIB_OR_NONE;
            default:
                throw new Error();
        }
    }

    private ZlibUtil() {
    }
}