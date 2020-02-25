package com.embrain.panelbigdata.utils;

import android.app.Activity;
import android.app.AppOpsManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.Uri;
import android.os.Build;
import android.os.Build.VERSION;
import android.telephony.TelephonyManager;
import androidx.annotation.RequiresApi;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.os.EnvironmentCompat;
import java.io.File;
import java.util.TimeZone;

public class DeviceUtils {
    public static final int REQUEST_PERMISSION_LOCATION = 1002;
    public static final int REQUEST_PERMISSION_REQUEST_PUSH = 1010;
    public static final int REQUEST_PERMISSION_REQUEST_USAGE = 1009;

    public static String getAppVersion(Context context) {
        String str = "Unknown";
        if (context == null) {
            return str;
        }
        try {
            str = context.getApplicationContext().getPackageManager().getPackageInfo(context.getApplicationContext().getPackageName(), 0).versionName;
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        }
        return str;
    }

    public static String getAppName(Context context) {
        String str = "Unknown";
        if (context == null) {
            return str;
        }
        try {
            str = context.getApplicationContext().getPackageManager().getApplicationInfo(context.getPackageName(), 128).name;
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        }
        return str;
    }

    public static String getDeviceModel() {
        if (isEmulator()) {
            return "Emulator";
        }
        return Build.MODEL;
    }

    public static String getOSVersion() {
        return VERSION.RELEASE;
    }

    public static String getTelCoperation(Context context) {
        try {
            return ((TelephonyManager) context.getSystemService("phone")).getSimOperatorName();
        } catch (Exception e) {
            e.printStackTrace();
            return "Unknown";
        }
    }

    public static String getTelStandard(Context context) {
        try {
            return ((TelephonyManager) context.getSystemService("phone")).getNetworkOperatorName();
        } catch (Exception e) {
            e.printStackTrace();
            return "Unknown";
        }
    }

    public static String getTimeZone() {
        return TimeZone.getDefault().getID();
    }

    public static boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.startsWith(EnvironmentCompat.MEDIA_UNKNOWN) || Build.MODEL.contains("google_sdk") || Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK built for x86") || Build.MANUFACTURER.contains("Genymotion") || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) || "google_sdk".equals(Build.PRODUCT);
    }

    public static void goMarket(Context context) {
        goMarket(context, context.getPackageName());
    }

    public static void goMarket(Context context, String str) {
        Intent intent = new Intent("android.intent.action.VIEW");
        StringBuilder sb = new StringBuilder();
        sb.append("market://details?id=");
        sb.append(str);
        intent.setData(Uri.parse(sb.toString()));
        try {
            context.startActivity(intent);
        } catch (Exception unused) {
        }
    }

    public static boolean rootCheck() {
        boolean z;
        try {
            Runtime.getRuntime().exec("su");
            z = true;
        } catch (Exception unused) {
            z = false;
        }
        if (!z) {
            String[] strArr = {"/sbin/su", "/system/su", "/system/sbin/su", "/system/xbin/su", "/data/data/com.noshufou.android.su", "/system/app/Superuser.apk"};
            for (String file : strArr) {
                if (new File(file).exists()) {
                    return true;
                }
            }
        }
        return z;
    }

    public static boolean hasUsagePermission(Context context) {
        boolean z = false;
        try {
            ApplicationInfo applicationInfo = context.getPackageManager().getApplicationInfo(context.getPackageName(), 0);
            if ((VERSION.SDK_INT > 19 ? ((AppOpsManager) context.getSystemService("appops")).checkOpNoThrow("android:get_usage_stats", applicationInfo.uid, applicationInfo.packageName) : 0) == 0) {
                z = true;
            }
            return z;
        } catch (NameNotFoundException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void setUsagePermission(Activity activity) {
        activity.startActivityForResult(new Intent("android.settings.USAGE_ACCESS_SETTINGS"), 1009);
    }

    public static boolean hasLocationPermission(Context context) {
        if (VERSION.SDK_INT < 23) {
            return true;
        }
        if (context.checkSelfPermission("android.permission.ACCESS_FINE_LOCATION") == 0 && context.checkSelfPermission("android.permission.ACCESS_COARSE_LOCATION") == 0) {
            return true;
        }
        return false;
    }

    @RequiresApi(api = 23)
    public static void setLocationPermission(Activity activity) {
        activity.requestPermissions(new String[]{"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"}, 1002);
    }

    public static boolean hasPushPermission(Context context) {
        return NotificationManagerCompat.from(context).areNotificationsEnabled();
    }

    public static void setPushPermission(Activity activity) {
        Intent intent = new Intent();
        if (VERSION.SDK_INT >= 26) {
            intent.setAction("android.settings.APP_NOTIFICATION_SETTINGS");
            intent.putExtra("android.provider.extra.APP_PACKAGE", activity.getPackageName());
        } else if (VERSION.SDK_INT >= 21) {
            intent.setAction("android.settings.APP_NOTIFICATION_SETTINGS");
            intent.putExtra("app_package", activity.getPackageName());
            intent.putExtra("app_uid", activity.getApplicationInfo().uid);
        } else {
            intent.setAction("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.addCategory("android.intent.category.DEFAULT");
            StringBuilder sb = new StringBuilder();
            sb.append("package:");
            sb.append(activity.getPackageName());
            intent.setData(Uri.parse(sb.toString()));
        }
        activity.startActivityForResult(intent, 1010);
    }
}