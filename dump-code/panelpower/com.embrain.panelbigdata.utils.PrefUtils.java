package com.embrain.panelbigdata.utils;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;

public class PrefUtils {
    private static final String PREF_KEY_FCM_TOKEN = "fcm_token";
    private static final String PREF_KEY_GOOGLE_ADID = "google_adid";
    private static final String PREF_KEY_JOB_ID_LOCATION = "job_id_location";
    private static final String PREF_KEY_JOB_ID_USAGE = "job_id_usage";
    private static final String PREF_KEY_LOCATION_POLICY_VERSION = "policy_version_location";
    private static final String PREF_KEY_LOPLAT_ECHO_CODE = "loplat_echo_code";
    private static final String PREF_KEY_PANEL_ID = "panel_id";
    private static final String PREF_KEY_SENDER_POLICY_VERSION = "policy_version_sender";
    private static final String PREF_KEY_TOKEN_UPDATE_DATE = "token_update_date";
    private static final String PREF_KEY_USAGE_LAST_SEND_DATE = "usage_send_date";
    private static final String PREF_KEY_USAGE_POLICY_VERSION = "policy_version_usage";
    private static final String PREF_KEY_USER_AGREE_LOCATION = "agree_location";
    private static final String PREF_KEY_USER_AGREE_USAGE = "agree_usage";
    private static final String PREF_NAME = "pref_bigdata";

    private static SharedPreferences getPreference(Context context) {
        return context.getSharedPreferences(PREF_NAME, 0);
    }

    public static void setPanelId(Context context, String str) {
        Editor edit = getPreference(context).edit();
        edit.putString(PREF_KEY_PANEL_ID, str);
        edit.apply();
    }

    public static String getPanelId(Context context) {
        return getPreference(context).getString(PREF_KEY_PANEL_ID, "");
    }

    public static void setJobIdUsage(Context context, int i) {
        StringBuilder sb = new StringBuilder();
        sb.append("setJobIdUsage job id : ");
        sb.append(i);
        LogUtil.write(sb.toString());
        Editor edit = getPreference(context).edit();
        edit.putInt(PREF_KEY_JOB_ID_USAGE, i);
        edit.apply();
    }

    public static int getJobIdUsage(Context context) {
        return getPreference(context).getInt(PREF_KEY_JOB_ID_USAGE, -1);
    }

    public static void setJobIdLocation(Context context, int i) {
        StringBuilder sb = new StringBuilder();
        sb.append("setJobIdUsage job id : ");
        sb.append(i);
        LogUtil.write(sb.toString());
        Editor edit = getPreference(context).edit();
        edit.putInt(PREF_KEY_JOB_ID_LOCATION, i);
        edit.apply();
    }

    public static int getJobIdLocation(Context context) {
        return getPreference(context).getInt(PREF_KEY_JOB_ID_LOCATION, -1);
    }

    public static String getLoplatEchoCode(Context context) {
        return getPreference(context).getString(PREF_KEY_LOPLAT_ECHO_CODE, null);
    }

    public static void setFcmToken(Context context, String str) {
        StringBuilder sb = new StringBuilder();
        sb.append("set fcm token : ");
        sb.append(str);
        LogUtil.write(sb.toString());
        Editor edit = getPreference(context).edit();
        edit.putString(PREF_KEY_FCM_TOKEN, str);
        edit.apply();
    }

    public static String getFcmToken(Context context) {
        return getPreference(context).getString(PREF_KEY_FCM_TOKEN, "");
    }

    public static void setGoogleADID(Context context, String str) {
        StringBuilder sb = new StringBuilder();
        sb.append("set google adid : ");
        sb.append(str);
        LogUtil.write(sb.toString());
        Editor edit = getPreference(context).edit();
        edit.putString(PREF_KEY_GOOGLE_ADID, str);
        edit.apply();
    }

    public static String getGoogleADID(Context context) {
        return getPreference(context).getString(PREF_KEY_GOOGLE_ADID, "");
    }

    public static long getTokenUpdateDate(Context context) {
        return getPreference(context).getLong(PREF_KEY_TOKEN_UPDATE_DATE, -1);
    }

    public static void setTokenUpdateDate(Context context, long j) {
        Editor edit = getPreference(context).edit();
        edit.putLong(PREF_KEY_TOKEN_UPDATE_DATE, j);
        edit.apply();
    }

    public static boolean getUserAgreeUsage(Context context) {
        return getPreference(context).getBoolean(PREF_KEY_USER_AGREE_USAGE, false);
    }

    public static void setUserAgreeUsage(Context context, boolean z) {
        Editor edit = getPreference(context).edit();
        edit.putBoolean(PREF_KEY_USER_AGREE_USAGE, z);
        edit.apply();
    }

    public static boolean getUserAgreeLocation(Context context) {
        return getPreference(context).getBoolean(PREF_KEY_USER_AGREE_LOCATION, false);
    }

    public static void setUserAgreeLocation(Context context, boolean z) {
        Editor edit = getPreference(context).edit();
        edit.putBoolean(PREF_KEY_USER_AGREE_LOCATION, z);
        edit.apply();
    }

    public static int getUsagePolicyVersion(Context context) {
        return getPreference(context).getInt(PREF_KEY_USAGE_POLICY_VERSION, 0);
    }

    public static void setUsagePolicyVersion(Context context, int i) {
        Editor edit = getPreference(context).edit();
        edit.putInt(PREF_KEY_USAGE_POLICY_VERSION, i);
        edit.apply();
    }

    public static int getLocationPolicyVersion(Context context) {
        return getPreference(context).getInt(PREF_KEY_LOCATION_POLICY_VERSION, 0);
    }

    public static void setLocationPolicyVersion(Context context, int i) {
        Editor edit = getPreference(context).edit();
        edit.putInt(PREF_KEY_LOCATION_POLICY_VERSION, i);
        edit.apply();
    }

    public static int getSenderPolicyVersion(Context context) {
        return getPreference(context).getInt(PREF_KEY_SENDER_POLICY_VERSION, 0);
    }

    public static void setSenderPolicyVersion(Context context, int i) {
        Editor edit = getPreference(context).edit();
        edit.putInt(PREF_KEY_SENDER_POLICY_VERSION, i);
        edit.apply();
    }

    public static long getUsageLastSendDate(Context context) {
        return getPreference(context).getLong(PREF_KEY_USAGE_LAST_SEND_DATE, 0);
    }

    public static void setUsageLastSendDate(Context context, long j) {
        Editor edit = getPreference(context).edit();
        edit.putLong(PREF_KEY_USAGE_LAST_SEND_DATE, j);
        edit.apply();
    }
}