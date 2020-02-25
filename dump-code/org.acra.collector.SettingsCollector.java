package org.acra.collector;

import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings.Secure;
import android.provider.Settings.System;
import android.util.Log;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.acra.ACRA;

final class SettingsCollector {
    SettingsCollector() {
    }

    public static String collectSystemSettings(Context context) {
        Field[] fields;
        StringBuilder sb = new StringBuilder();
        for (Field field : System.class.getFields()) {
            if (!field.isAnnotationPresent(Deprecated.class) && field.getType() == String.class) {
                try {
                    String string = System.getString(context.getContentResolver(), (String) field.get(null));
                    if (string != null) {
                        sb.append(field.getName());
                        sb.append("=");
                        sb.append(string);
                        sb.append("\n");
                    }
                } catch (IllegalArgumentException e) {
                    Log.w(ACRA.LOG_TAG, "Error : ", e);
                } catch (IllegalAccessException e2) {
                    Log.w(ACRA.LOG_TAG, "Error : ", e2);
                }
            }
        }
        return sb.toString();
    }

    public static String collectSecureSettings(Context context) {
        Field[] fields;
        StringBuilder sb = new StringBuilder();
        for (Field field : Secure.class.getFields()) {
            if (!field.isAnnotationPresent(Deprecated.class) && field.getType() == String.class && isAuthorized(field)) {
                try {
                    String string = Secure.getString(context.getContentResolver(), (String) field.get(null));
                    if (string != null) {
                        sb.append(field.getName());
                        sb.append("=");
                        sb.append(string);
                        sb.append("\n");
                    }
                } catch (IllegalArgumentException e) {
                    Log.w(ACRA.LOG_TAG, "Error : ", e);
                } catch (IllegalAccessException e2) {
                    Log.w(ACRA.LOG_TAG, "Error : ", e2);
                }
            }
        }
        return sb.toString();
    }

    public static String collectGlobalSettings(Context context) {
        if (Compatibility.getAPILevel() < 17) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        try {
            Class<?> cls = Class.forName("android.provider.Settings$Global");
            Field[] fields = cls.getFields();
            Method method = cls.getMethod("getString", new Class[]{ContentResolver.class, String.class});
            for (Field field : fields) {
                if (!field.isAnnotationPresent(Deprecated.class) && field.getType() == String.class && isAuthorized(field)) {
                    Object invoke = method.invoke(null, new Object[]{context.getContentResolver(), (String) field.get(null)});
                    if (invoke != null) {
                        sb.append(field.getName());
                        sb.append("=");
                        sb.append(invoke);
                        sb.append("\n");
                    }
                }
            }
        } catch (IllegalArgumentException e) {
            Log.w(ACRA.LOG_TAG, "Error : ", e);
        } catch (IllegalAccessException e2) {
            Log.w(ACRA.LOG_TAG, "Error : ", e2);
        } catch (ClassNotFoundException e3) {
            Log.w(ACRA.LOG_TAG, "Error : ", e3);
        } catch (SecurityException e4) {
            Log.w(ACRA.LOG_TAG, "Error : ", e4);
        } catch (NoSuchMethodException e5) {
            Log.w(ACRA.LOG_TAG, "Error : ", e5);
        } catch (InvocationTargetException e6) {
            Log.w(ACRA.LOG_TAG, "Error : ", e6);
        }
        return sb.toString();
    }

    private static boolean isAuthorized(Field field) {
        if (field == null || field.getName().startsWith("WIFI_AP")) {
            return false;
        }
        for (String matches : ACRA.getConfig().excludeMatchingSettingsKeys()) {
            if (field.getName().matches(matches)) {
                return false;
            }
        }
        return true;
    }
}