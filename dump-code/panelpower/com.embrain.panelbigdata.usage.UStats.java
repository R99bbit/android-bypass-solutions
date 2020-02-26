package com.embrain.panelbigdata.usage;

import android.annotation.TargetApi;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.ResolveInfo;
import com.embrain.panelbigdata.Vo.usage.UsageInsertRequest;
import com.embrain.panelbigdata.utils.LogUtil;
import com.embrain.panelpower.MainActivity;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class UStats {
    private static SimpleDateFormat FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.sss");
    public static final String TAG = "UStats";

    public static List<UsageStats> getDailyUsage(Context context, long j) {
        Calendar instance = Calendar.getInstance();
        instance.add(5, -6);
        if (j > instance.getTimeInMillis()) {
            instance.setTimeInMillis(j);
        }
        instance.set(11, 0);
        instance.set(12, 0);
        instance.set(13, 0);
        instance.set(14, 1);
        Calendar instance2 = Calendar.getInstance();
        instance2.add(5, -1);
        instance2.set(11, 23);
        instance.set(12, 59);
        instance.set(13, 59);
        instance.set(14, MainActivity.REQUEST_SETTINGS);
        return getDailyUsage(context, instance.getTimeInMillis(), instance2.getTimeInMillis());
    }

    public static List<UsageStats> getDailyUsage(Context context, long j, long j2) {
        LogUtil.write("getDailyUsage==============");
        StringBuilder sb = new StringBuilder();
        sb.append("start : ");
        sb.append(FORMAT.format(new Date(j)));
        LogUtil.write(sb.toString());
        StringBuilder sb2 = new StringBuilder();
        sb2.append("endti : ");
        sb2.append(FORMAT.format(new Date(j2)));
        LogUtil.write(sb2.toString());
        LogUtil.write("===========================");
        return getAppTotalUsage(context, j, j2, 0);
    }

    public static List<UsageStats> getWeeklyUsage(Context context) {
        Calendar instance = Calendar.getInstance();
        instance.add(5, -6);
        long timeInMillis = instance.getTimeInMillis();
        long currentTimeMillis = System.currentTimeMillis();
        LogUtil.write("getWeeklyUsage==============");
        StringBuilder sb = new StringBuilder();
        sb.append("start : ");
        sb.append(FORMAT.format(new Date(timeInMillis)));
        LogUtil.write(sb.toString());
        StringBuilder sb2 = new StringBuilder();
        sb2.append("endti : ");
        sb2.append(FORMAT.format(new Date(currentTimeMillis)));
        LogUtil.write(sb2.toString());
        LogUtil.write("===========================");
        return getWeeklyUsage(context, timeInMillis, currentTimeMillis);
    }

    public static List<UsageStats> getWeeklyUsage(Context context, long j, long j2) {
        return getAppTotalUsage(context, j, j2, 1);
    }

    @TargetApi(21)
    private static List<UsageStats> getAppTotalUsage(Context context, long j, long j2, int i) {
        return ((UsageStatsManager) context.getSystemService("usagestats")).queryUsageStats(i, j, j2);
    }

    public static ArrayList<ApplicationDao> getApplicatonList(Context context, PackageManager packageManager) {
        String str;
        long j;
        long j2;
        ArrayList<ApplicationDao> arrayList = new ArrayList<>();
        for (ApplicationInfo next : packageManager.getInstalledApplications(128)) {
            String str2 = next.packageName;
            String installerPackageName = packageManager.getInstallerPackageName(next.packageName);
            CharSequence applicationLabel = packageManager.getApplicationLabel(next);
            long j3 = 0;
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(str2, 0);
                j = packageInfo.lastUpdateTime;
                try {
                    j3 = packageInfo.firstInstallTime;
                    str = packageInfo.versionName;
                } catch (NameNotFoundException e) {
                    e = e;
                    long j4 = j3;
                    j3 = j;
                    j2 = j4;
                    e.printStackTrace();
                    str = "";
                    long j5 = j3;
                    j3 = j2;
                    j = j5;
                    ApplicationDao applicationDao = new ApplicationDao(applicationLabel.toString(), str2, installerPackageName, j3, j, str);
                    arrayList.add(applicationDao);
                }
            } catch (NameNotFoundException e2) {
                e = e2;
                j2 = 0;
                e.printStackTrace();
                str = "";
                long j52 = j3;
                j3 = j2;
                j = j52;
                ApplicationDao applicationDao2 = new ApplicationDao(applicationLabel.toString(), str2, installerPackageName, j3, j, str);
                arrayList.add(applicationDao2);
            }
            ApplicationDao applicationDao22 = new ApplicationDao(applicationLabel.toString(), str2, installerPackageName, j3, j, str);
            arrayList.add(applicationDao22);
        }
        return arrayList;
    }

    public static UsageInsertRequest getUsageInfo(Context context, String str, String str2, String str3, long j) {
        UsageInsertRequestExt usageInsertRequestExt = new UsageInsertRequestExt(str, str2, str3);
        PackageManager packageManager = context.getPackageManager();
        Intent intent = new Intent("android.intent.action.MAIN", null);
        intent.addCategory("android.intent.category.LAUNCHER");
        List<ResolveInfo> queryIntentActivities = packageManager.queryIntentActivities(intent, 0);
        ArrayList<ApplicationDao> applicatonList = getApplicatonList(context, packageManager);
        List<UsageStats> dailyUsage = getDailyUsage(context, j);
        ArrayList arrayList = new ArrayList();
        for (UsageStats next : dailyUsage) {
            if (contains(queryIntentActivities, next.getPackageName()) && next.getTotalTimeInForeground() > 0) {
                UsageDaoExt usageDaoExt = new UsageDaoExt(next);
                try {
                    usageDaoExt.setAppName(packageManager.getApplicationLabel(packageManager.getPackageInfo(next.getPackageName(), 0).applicationInfo).toString());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                arrayList.add(usageDaoExt);
            }
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator<ApplicationDao> it = applicatonList.iterator();
        while (it.hasNext()) {
            ApplicationDao next2 = it.next();
            if (contains(queryIntentActivities, next2.package_name)) {
                arrayList2.add(next2);
            }
        }
        LogUtil.write("===============================================");
        StringBuilder sb = new StringBuilder();
        sb.append("usageList : ");
        sb.append(arrayList.size());
        LogUtil.write(sb.toString());
        StringBuilder sb2 = new StringBuilder();
        sb2.append("daily_apps : ");
        sb2.append(arrayList2.size());
        LogUtil.write(sb2.toString());
        LogUtil.write("===============================================");
        usageInsertRequestExt.setDailyUsageList(arrayList);
        usageInsertRequestExt.setAppList(arrayList2);
        return usageInsertRequestExt;
    }

    private static boolean contains(List<ResolveInfo> list, String str) {
        for (ResolveInfo resolveInfo : list) {
            try {
                if (resolveInfo.activityInfo.packageName.equals(str)) {
                    return true;
                }
            } catch (Exception unused) {
            }
        }
        return false;
    }
}