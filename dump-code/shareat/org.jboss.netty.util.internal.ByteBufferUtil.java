package org.jboss.netty.util.internal;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;

public final class ByteBufferUtil {
    private static final boolean CLEAN_SUPPORTED;
    private static final Method directBufferCleaner;
    private static final Method directBufferCleanerClean;

    static {
        boolean v;
        Method directBufferCleanerX = null;
        Method directBufferCleanerCleanX = null;
        try {
            directBufferCleanerX = Class.forName("java.nio.DirectByteBuffer").getMethod("cleaner", new Class[0]);
            directBufferCleanerX.setAccessible(true);
            directBufferCleanerCleanX = Class.forName("sun.misc.Cleaner").getMethod("clean", new Class[0]);
            directBufferCleanerCleanX.setAccessible(true);
            v = true;
        } catch (Exception e) {
            v = false;
        }
        CLEAN_SUPPORTED = v;
        directBufferCleaner = directBufferCleanerX;
        directBufferCleanerClean = directBufferCleanerCleanX;
    }

    public static void destroy(ByteBuffer buffer) {
        if (CLEAN_SUPPORTED && buffer.isDirect()) {
            try {
                directBufferCleanerClean.invoke(directBufferCleaner.invoke(buffer, new Object[0]), new Object[0]);
            } catch (Exception e) {
            }
        }
    }

    private ByteBufferUtil() {
    }
}