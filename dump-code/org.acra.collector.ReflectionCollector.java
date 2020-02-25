package org.acra.collector;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

final class ReflectionCollector {
    ReflectionCollector() {
    }

    public static String collectConstants(Class<?> cls, String str) {
        Field[] fields;
        StringBuilder sb = new StringBuilder();
        for (Field field : cls.getFields()) {
            if (str != null && str.length() > 0) {
                sb.append(str);
                sb.append('.');
            }
            sb.append(field.getName());
            sb.append("=");
            try {
                sb.append(field.get(null).toString());
            } catch (IllegalArgumentException unused) {
                sb.append("N/A");
            } catch (IllegalAccessException unused2) {
                sb.append("N/A");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    public static String collectStaticGettersResults(Class<?> cls) {
        Method[] methods;
        StringBuilder sb = new StringBuilder();
        for (Method method : cls.getMethods()) {
            if (method.getParameterTypes().length == 0 && ((method.getName().startsWith("get") || method.getName().startsWith("is")) && !method.getName().equals("getClass"))) {
                try {
                    sb.append(method.getName());
                    sb.append('=');
                    sb.append(method.invoke(null, null));
                    sb.append("\n");
                } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException unused) {
                }
            }
        }
        return sb.toString();
    }

    public static String collectConstants(Class<?> cls) {
        return collectConstants(cls, "");
    }
}