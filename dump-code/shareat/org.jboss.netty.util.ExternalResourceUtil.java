package org.jboss.netty.util;

public final class ExternalResourceUtil {
    public static void release(ExternalResourceReleasable... releasables) {
        ExternalResourceReleasable[] releasablesCopy = new ExternalResourceReleasable[releasables.length];
        for (int i = 0; i < releasables.length; i++) {
            if (releasables[i] == null) {
                throw new NullPointerException("releasables[" + i + ']');
            }
            releasablesCopy[i] = releasables[i];
        }
        for (ExternalResourceReleasable e : releasablesCopy) {
            e.releaseExternalResources();
        }
    }

    private ExternalResourceUtil() {
    }
}