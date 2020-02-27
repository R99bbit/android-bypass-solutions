package com.igaworks.core;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.util.Log;

public class IgawLogger {
    public static final int LOG_D = 3;
    public static final int LOG_E = 0;
    public static final int LOG_I = 2;
    public static final int LOG_V = 4;
    public static final int LOG_W = 1;
    public static ApplicationInfo appInfo;
    public static int isInstalled = 0;
    public static String logEnable = null;
    public static String logMode = null;

    public static void Logging(Context context, String tag, String message, int logType) {
        Logging(context, tag, message, logType, true);
    }

    public static void Logging(Context context, String tag, String message, int logType, boolean onlyTestMode) {
        try {
            if (logMode == null) {
                appInfo = context.getPackageManager().getApplicationInfo(context.getPackageName(), 128);
                logMode = (String) appInfo.metaData.get("adbrix_logger_mode");
            }
        } catch (NameNotFoundException | Exception e) {
        }
        try {
            if (logEnable == null) {
                appInfo = context.getPackageManager().getApplicationInfo(context.getPackageName(), 128);
                logEnable = (String) appInfo.metaData.get("igaw_log_enable");
            }
        } catch (NameNotFoundException | Exception e2) {
        }
        if (logEnable != null && logEnable.equals("disable") && checkPkgInstall(context) < 2) {
            return;
        }
        if (logMode != null && logMode.equals("none")) {
            return;
        }
        if (checkPkgInstall(context) >= 2 || !onlyTestMode || (logMode != null && logMode.equals("test"))) {
            switch (logType) {
                case 0:
                    try {
                        Log.e(tag, message);
                        return;
                    } catch (Exception e3) {
                        e3.printStackTrace();
                    }
                case 1:
                    Log.w(tag, message);
                    return;
                case 2:
                    Log.i(tag, message);
                    return;
                case 3:
                    Log.d(tag, message);
                    return;
                case 4:
                    Log.v(tag, message);
                    return;
                default:
                    return;
            }
            e3.printStackTrace();
        }
    }

    public static int checkPkgInstall(Context context) {
        try {
            if (isInstalled > 0) {
                return isInstalled;
            }
            context.getPackageManager().getApplicationInfo("com.igaworks.adpopcorn.debug", 0);
            isInstalled = 2;
            return isInstalled;
        } catch (Exception e) {
            isInstalled = 1;
        }
    }

    private static Boolean getMetaData(Context context, String pKey) {
        try {
            appInfo = context.getPackageManager().getApplicationInfo(context.getPackageName(), 128);
            return Boolean.valueOf(appInfo.metaData.getBoolean(pKey));
        } catch (NameNotFoundException e) {
            return Boolean.valueOf(true);
        } catch (Exception e2) {
            return Boolean.valueOf(true);
        }
    }
}