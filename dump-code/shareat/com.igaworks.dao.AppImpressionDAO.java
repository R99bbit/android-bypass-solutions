package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import com.igaworks.core.RequestParameter;
import com.igaworks.impl.InternalAction;
import java.util.Date;

public class AppImpressionDAO {
    public static final String FIRST_START_SP_NAME = "firstStart";

    public static void setInitAdidtToSP(Context context, String init_ad_id) {
        Editor firstEditor = getSharedPreferencesForFirstStart(context).edit();
        firstEditor.putString(RequestParameter.INIT_AD_ID, init_ad_id);
        firstEditor.commit();
    }

    public static String getInitAdidtToSP(Context context) {
        return getSharedPreferencesForFirstStart(context).getString(RequestParameter.INIT_AD_ID, "");
    }

    public static void addFirstStartToSP(Context context) {
        Editor firstEditor = getSharedPreferencesForFirstStart(context).edit();
        firstEditor.putBoolean("fts", true);
        firstEditor.commit();
    }

    public static SharedPreferences getSharedPreferencesForFirstStart(Context context) {
        return context.getSharedPreferences(FIRST_START_SP_NAME, 0);
    }

    public static void addRequestPermissionAlready(Context context) {
        Editor firstEditor = getSharedPreferencesForFirstStart(context).edit();
        firstEditor.putBoolean("RequestPermissionAlready", true);
        firstEditor.commit();
    }

    public static boolean getRequestPermisisonAlready(Context context) {
        return getSharedPreferencesForFirstStart(context).getBoolean("RequestPermissionAlready", false);
    }

    public static void setServerBaseTimeOffset(final Context context, final long basetime) {
        InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
            public void run() {
                Editor firstEditor = AppImpressionDAO.getSharedPreferencesForFirstStart(context).edit();
                firstEditor.putLong("ServerBaseTimeOffset", basetime);
                firstEditor.commit();
            }
        });
    }

    public static long getServerBaseTimeOffset(Context context) {
        return getSharedPreferencesForFirstStart(context).getLong("ServerBaseTimeOffset", 0);
    }

    public static void setReportThirdPartyInstallEventExist(Context context) {
        Editor firstEditor = getSharedPreferencesForFirstStart(context).edit();
        firstEditor.putBoolean("frtie", true);
        firstEditor.commit();
    }

    public static boolean getReportThirdPartyInstallEventExist(Context context) {
        return context.getSharedPreferences(FIRST_START_SP_NAME, 0).getBoolean("frtie", false);
    }

    public static void setAppLinkConversionKey(Context context, int ck) {
        Editor firstEditor = getSharedPreferencesForFirstStart(context).edit();
        firstEditor.putInt("AppLinkConversionKey", ck);
        firstEditor.commit();
    }

    public static int getAppLinkConversionKey(Context context) {
        return context.getSharedPreferences(FIRST_START_SP_NAME, 0).getInt("AppLinkConversionKey", -1);
    }

    public static void setDeferrerlink(Context context, String deferrerlink) {
        Editor firstEditor = getSharedPreferencesForFirstStart(context).edit();
        firstEditor.putString("DeferrerLink", deferrerlink);
        firstEditor.commit();
    }

    public static String getDeferrerlink(Context context) {
        return context.getSharedPreferences(FIRST_START_SP_NAME, 0).getString("DeferrerLink", "");
    }

    public static void setLastDailyRentionDate(Context context) {
        Editor edt = getSharedPreferencesForFirstStart(context).edit();
        edt.putString("LastDailyRentionDate", AdbrixDB_v2.DB_DATE_FORMAT.format(new Date()));
        edt.commit();
    }

    public static String getLastDailyRentionDate(Context context) {
        return context.getSharedPreferences(FIRST_START_SP_NAME, 0).getString("LastDailyRentionDate", "");
    }

    public static void setSynAdbrix(Context context) {
        Editor firstEditor = getSharedPreferencesForFirstStart(context).edit();
        firstEditor.putBoolean("IsSynAdbrix", true);
        firstEditor.commit();
    }

    public static boolean getSynAdbrix(Context context) {
        return getSharedPreferencesForFirstStart(context).getBoolean("IsSynAdbrix", false);
    }
}