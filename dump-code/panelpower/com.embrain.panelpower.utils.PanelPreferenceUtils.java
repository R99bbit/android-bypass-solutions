package com.embrain.panelpower.utils;

import android.content.Context;
import android.content.SharedPreferences;

public class PanelPreferenceUtils {
    private static final String PREF_AD_ID = "google_ad_id";
    private static final String PREF_FIRST_START = "first_start";
    private static final String PREF_NAME = "panel_pref";
    private static final String PREF_PUSH_TOKEN = "push_token";
    private static final String PREF_TEMP_USER_ID = "temp_user_id";

    private static SharedPreferences getPref(Context context) {
        return context.getSharedPreferences(PREF_NAME, 0);
    }

    public static void setFirstStart(Context context) {
        getPref(context).edit().putBoolean(PREF_FIRST_START, false).apply();
    }

    public static boolean getFirstStart(Context context) {
        return getPref(context).getBoolean(PREF_FIRST_START, true);
    }

    public static void setPushToken(Context context, String str) {
        getPref(context).edit().putString(PREF_PUSH_TOKEN, str).apply();
    }

    public static String getPushToken(Context context) {
        return getPref(context).getString(PREF_PUSH_TOKEN, null);
    }

    public static void setAdId(Context context, String str) {
        getPref(context).edit().putString(PREF_AD_ID, str).apply();
    }

    public static String getAdId(Context context) {
        return getPref(context).getString(PREF_AD_ID, null);
    }

    public static void setTempUserId(Context context, String str) {
        getPref(context).edit().putString(PREF_TEMP_USER_ID, str).apply();
    }

    public static String getTempUserId(Context context) {
        return getPref(context).getString(PREF_TEMP_USER_ID, null);
    }
}