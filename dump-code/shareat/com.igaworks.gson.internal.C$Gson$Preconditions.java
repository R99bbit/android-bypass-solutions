package com.igaworks.gson.internal;

/* renamed from: com.igaworks.gson.internal.$Gson$Preconditions reason: invalid class name */
public final class C$Gson$Preconditions {
    public static <T> T checkNotNull(T obj) {
        if (obj != null) {
            return obj;
        }
        throw new NullPointerException();
    }

    public static void checkArgument(boolean condition) {
        if (!condition) {
            throw new IllegalArgumentException();
        }
    }
}