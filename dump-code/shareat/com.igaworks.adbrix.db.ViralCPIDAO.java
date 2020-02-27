package com.igaworks.adbrix.db;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;

public class ViralCPIDAO {
    public static final String VIRAL_CPI_SP_NAME = "viral_cpi_sp";
    private static Activity activity;
    private static boolean restoreViralCPI = false;
    private static ViralCPIDAO singleton;

    private ViralCPIDAO() {
    }

    public static ViralCPIDAO getInstance() {
        if (singleton == null) {
            singleton = new ViralCPIDAO();
        }
        return singleton;
    }

    public static boolean isRestoreViralCPI() {
        return restoreViralCPI;
    }

    public static void setRestoreViralCPI(boolean restoreViralCPI2) {
        restoreViralCPI = restoreViralCPI2;
    }

    public static void saveRestoreViralDialog(Activity act) {
        activity = act;
        restoreViralCPI = true;
    }

    public static Activity getActivity() {
        return activity;
    }

    public static void setActivity(Activity activity2) {
        activity = activity2;
    }

    private SharedPreferences getSharedPreference(Context context) {
        return context.getSharedPreferences(VIRAL_CPI_SP_NAME, 0);
    }

    private Editor getEditor(Context context) {
        return getSharedPreference(context).edit();
    }

    public void saveDoNotShow(Context context, int campaignKey) {
        Editor edt = getEditor(context);
        edt.putInt(new StringBuilder(String.valueOf(campaignKey)).toString(), campaignKey);
        edt.commit();
    }

    public void removeDoNotShow(Context context, int campaignKey) {
        Editor edt = getEditor(context);
        edt.remove(new StringBuilder(String.valueOf(campaignKey)).toString());
        edt.commit();
    }

    public boolean isDoNotShow(Context context, int campaignKey) {
        return getSharedPreference(context).contains(new StringBuilder(String.valueOf(campaignKey)).toString());
    }
}