package org.acra.collector;

import android.content.Context;
import android.text.format.Time;
import android.util.Log;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import org.acra.ACRA;

final class DropBoxCollector {
    private static final String NO_RESULT = "N/A";
    private static final String[] SYSTEM_TAGS = {"system_app_anr", "system_app_wtf", "system_app_crash", "system_server_anr", "system_server_wtf", "system_server_crash", "BATTERY_DISCHARGE_INFO", "SYSTEM_RECOVERY_LOG", "SYSTEM_BOOT", "SYSTEM_LAST_KMSG", "APANIC_CONSOLE", "APANIC_THREADS", "SYSTEM_RESTART", "SYSTEM_TOMBSTONE", "data_app_strictmode"};

    DropBoxCollector() {
    }

    public static String read(Context context, String[] strArr) {
        String[] strArr2 = strArr;
        try {
            String dropBoxServiceName = Compatibility.getDropBoxServiceName();
            if (dropBoxServiceName == null) {
                return NO_RESULT;
            }
            Object systemService = context.getSystemService(dropBoxServiceName);
            int i = 2;
            char c = 0;
            int i2 = 1;
            Method method = systemService.getClass().getMethod("getNextEntry", new Class[]{String.class, Long.TYPE});
            if (method == null) {
                return "";
            }
            Time time = new Time();
            time.setToNow();
            time.minute -= ACRA.getConfig().dropboxCollectionMinutes();
            time.normalize(false);
            long millis = time.toMillis(false);
            ArrayList<String> arrayList = new ArrayList<>();
            if (ACRA.getConfig().includeDropBoxSystemTags()) {
                arrayList.addAll(Arrays.asList(SYSTEM_TAGS));
            }
            if (strArr2 != null && strArr2.length > 0) {
                arrayList.addAll(Arrays.asList(strArr));
            }
            if (arrayList.isEmpty()) {
                return "No tag configured for collection.";
            }
            StringBuilder sb = new StringBuilder();
            for (String str : arrayList) {
                sb.append("Tag: ");
                sb.append(str);
                sb.append(10);
                Object[] objArr = new Object[i];
                objArr[c] = str;
                objArr[i2] = Long.valueOf(millis);
                Object invoke = method.invoke(systemService, objArr);
                if (invoke == null) {
                    sb.append("Nothing.");
                    sb.append(10);
                } else {
                    Class<?> cls = invoke.getClass();
                    Class[] clsArr = new Class[i2];
                    clsArr[c] = Integer.TYPE;
                    Method method2 = cls.getMethod("getText", clsArr);
                    Method method3 = invoke.getClass().getMethod("getTimeMillis", null);
                    Method method4 = invoke.getClass().getMethod("close", null);
                    while (invoke != null) {
                        long j = millis;
                        long longValue = ((Long) method3.invoke(invoke, null)).longValue();
                        time.set(longValue);
                        sb.append("@");
                        sb.append(time.format2445());
                        sb.append(10);
                        String str2 = (String) method2.invoke(invoke, new Object[]{Integer.valueOf(500)});
                        if (str2 != null) {
                            sb.append("Text: ");
                            sb.append(str2);
                            sb.append(10);
                        } else {
                            sb.append("Not Text!");
                            sb.append(10);
                        }
                        method4.invoke(invoke, null);
                        invoke = method.invoke(systemService, new Object[]{str, Long.valueOf(longValue)});
                        millis = j;
                    }
                    i = 2;
                    c = 0;
                    i2 = 1;
                }
            }
            return sb.toString();
        } catch (SecurityException unused) {
            Log.i(ACRA.LOG_TAG, "DropBoxManager not available.");
            return NO_RESULT;
        } catch (NoSuchMethodException unused2) {
            Log.i(ACRA.LOG_TAG, "DropBoxManager not available.");
            return NO_RESULT;
        } catch (IllegalArgumentException unused3) {
            Log.i(ACRA.LOG_TAG, "DropBoxManager not available.");
            return NO_RESULT;
        } catch (IllegalAccessException unused4) {
            Log.i(ACRA.LOG_TAG, "DropBoxManager not available.");
            return NO_RESULT;
        } catch (InvocationTargetException unused5) {
            Log.i(ACRA.LOG_TAG, "DropBoxManager not available.");
            return NO_RESULT;
        } catch (NoSuchFieldException unused6) {
            Log.i(ACRA.LOG_TAG, "DropBoxManager not available.");
            return NO_RESULT;
        }
    }
}