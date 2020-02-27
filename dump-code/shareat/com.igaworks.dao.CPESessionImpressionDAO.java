package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import com.facebook.appevents.AppEventsConstants;

public class CPESessionImpressionDAO extends AbstractCPEImpressionDAO {
    protected static Editor adspaceEditor;
    protected static SharedPreferences adspaceSP;
    protected static Editor engagementEditor;
    protected static SharedPreferences engagementSP;
    protected static Editor promotionEditor;
    protected static SharedPreferences promotionSP;
    protected static AbstractCPEImpressionDAO singleton;

    private CPESessionImpressionDAO() {
    }

    public static AbstractCPEImpressionDAO getInstance() {
        if (singleton == null) {
            singleton = new CPESessionImpressionDAO();
        }
        return singleton;
    }

    /* access modifiers changed from: private */
    public SharedPreferences getSharedPreference(Context context, int scheduleType) {
        switch (scheduleType) {
            case 0:
                if (engagementSP == null) {
                    engagementSP = context.getSharedPreferences("session_cpe_counter", 0);
                }
                return engagementSP;
            case 1:
                if (promotionSP == null) {
                    promotionSP = context.getSharedPreferences("session_promotion_counter", 0);
                }
                return promotionSP;
            case 2:
                if (adspaceSP == null) {
                    adspaceSP = context.getSharedPreferences("session_ad_space_counter", 0);
                }
                return adspaceSP;
            default:
                return null;
        }
    }

    /* access modifiers changed from: private */
    public Editor getEditor(Context context, int scheduleType) {
        switch (scheduleType) {
            case 0:
                if (engagementEditor == null) {
                    engagementEditor = getSharedPreference(context, scheduleType).edit();
                }
                return engagementEditor;
            case 1:
                if (promotionEditor == null) {
                    promotionEditor = getSharedPreference(context, scheduleType).edit();
                }
                return promotionEditor;
            case 2:
                if (adspaceEditor == null) {
                    adspaceEditor = getSharedPreference(context, scheduleType).edit();
                }
                return adspaceEditor;
            default:
                return null;
        }
    }

    public void increaseImpressionData(Context context, int scheduleType, String targetStorageKey, String key) {
        final Context context2 = context;
        final int i = scheduleType;
        final String str = targetStorageKey;
        final String str2 = key;
        new Thread(new Runnable() {
            public void run() {
                SharedPreferences sp = CPESessionImpressionDAO.this.getSharedPreference(context2, i);
                Editor editor = CPESessionImpressionDAO.this.getEditor(context2, i);
                editor.putString(str + "::--::" + str2, new StringBuilder(String.valueOf(Integer.parseInt(sp.getString(str + "::--::" + str2, AppEventsConstants.EVENT_PARAM_VALUE_NO)) + 1)).toString());
                editor.commit();
            }
        }).start();
    }

    public void removeImpressionData(Context context, int scheduleType, String targetStorageKey, String key) {
        final Context context2 = context;
        final int i = scheduleType;
        final String str = targetStorageKey;
        final String str2 = key;
        new Thread(new Runnable() {
            public void run() {
                Editor editor = CPESessionImpressionDAO.this.getEditor(context2, i);
                editor.remove(str + "::--::" + str2);
                editor.commit();
            }
        }).start();
    }

    public String getImpressionData(Context context, int scheduleType, String targetStorageKey, String key) {
        return getSharedPreference(context, scheduleType).getString(new StringBuilder(String.valueOf(targetStorageKey)).append("::--::").append(key).toString(), AppEventsConstants.EVENT_PARAM_VALUE_NO);
    }

    public void clearImpressionData(final Context context) {
        new Thread(new Runnable() {
            public void run() {
                Editor editor = CPESessionImpressionDAO.this.getEditor(context, 0);
                editor.clear();
                editor.commit();
                Editor editor2 = CPESessionImpressionDAO.this.getEditor(context, 1);
                editor2.clear();
                editor2.commit();
            }
        }).start();
    }

    public void setImpressionData(Context context, int scheduleType, String targetStorageKey, String key, String value) {
    }
}