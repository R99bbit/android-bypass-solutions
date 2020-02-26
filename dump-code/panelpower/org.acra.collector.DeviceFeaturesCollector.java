package org.acra.collector;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;
import com.google.android.gms.measurement.api.AppMeasurementSdk.ConditionalUserProperty;
import org.acra.ACRA;

final class DeviceFeaturesCollector {
    DeviceFeaturesCollector() {
    }

    public static String getFeatures(Context context) {
        Object[] objArr;
        if (Compatibility.getAPILevel() < 5) {
            return "Data available only with API Level >= 5";
        }
        StringBuilder sb = new StringBuilder();
        try {
            for (Object obj : (Object[]) PackageManager.class.getMethod("getSystemAvailableFeatures", null).invoke(context.getPackageManager(), new Object[0])) {
                String str = (String) obj.getClass().getField(ConditionalUserProperty.NAME).get(obj);
                if (str != null) {
                    sb.append(str);
                } else {
                    sb.append("glEsVersion = ");
                    sb.append((String) obj.getClass().getMethod("getGlEsVersion", null).invoke(obj, new Object[0]));
                }
                sb.append("\n");
            }
        } catch (Throwable th) {
            String str2 = ACRA.LOG_TAG;
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Couldn't retrieve DeviceFeatures for ");
            sb2.append(context.getPackageName());
            Log.w(str2, sb2.toString(), th);
            sb.append("Could not retrieve data: ");
            sb.append(th.getMessage());
        }
        return sb.toString();
    }
}