package com.ning.http.util;

import java.util.Collection;
import java.util.Map;

public class MiscUtil {
    private MiscUtil() {
    }

    public static boolean isNonEmpty(String string) {
        return (string == null || string.length() == 0) ? false : true;
    }

    public static boolean isNonEmpty(Object[] array) {
        return (array == null || array.length == 0) ? false : true;
    }

    public static boolean isNonEmpty(byte[] array) {
        return (array == null || array.length == 0) ? false : true;
    }

    public static boolean isNonEmpty(Collection<?> collection) {
        return collection != null && !collection.isEmpty();
    }

    public static boolean isNonEmpty(Map<?, ?> map) {
        return map != null && !map.isEmpty();
    }
}