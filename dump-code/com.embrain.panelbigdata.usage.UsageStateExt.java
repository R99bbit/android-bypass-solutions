package com.embrain.panelbigdata.usage;

import android.app.AppOpsManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Build.VERSION;
import com.embrain.panelbigdata.EmBigDataManager;
import com.embrain.panelbigdata.Vo.usage.UsageState;
import com.embrain.panelbigdata.utils.PrefUtils;

public class UsageStateExt extends UsageState {
    public UsageStateExt(Context context) {
        this.permission = hasUsagePermission(context);
        this.aliveUsageJob = EmBigDataManager.aliveUsageJob(context);
        this.userAgree = getUserAgree(context);
    }

    public static boolean canExecute(Context context) {
        return hasUsagePermission(context) && getUserAgree(context);
    }

    public static boolean getUserAgree(Context context) {
        return PrefUtils.getUserAgreeUsage(context);
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
}