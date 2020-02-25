package org.acra.collector;

import android.content.Context;
import android.os.Build.VERSION;
import java.lang.reflect.Field;

public final class Compatibility {
    public static int getAPILevel() {
        try {
            return VERSION.class.getField("SDK_INT").getInt(null);
        } catch (SecurityException unused) {
            return Integer.parseInt(VERSION.SDK);
        } catch (NoSuchFieldException unused2) {
            return Integer.parseInt(VERSION.SDK);
        } catch (IllegalArgumentException unused3) {
            return Integer.parseInt(VERSION.SDK);
        } catch (IllegalAccessException unused4) {
            return Integer.parseInt(VERSION.SDK);
        }
    }

    public static String getDropBoxServiceName() throws NoSuchFieldException, IllegalAccessException {
        Field field = Context.class.getField("DROPBOX_SERVICE");
        if (field != null) {
            return (String) field.get(null);
        }
        return null;
    }
}