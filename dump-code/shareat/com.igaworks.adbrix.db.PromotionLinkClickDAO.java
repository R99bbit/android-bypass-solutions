package com.igaworks.adbrix.db;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;

public class PromotionLinkClickDAO {
    public static final String LINK_CLICK_SP_NAME = "link_click_sp";
    private static PromotionLinkClickDAO singleton;
    private Editor clickEditor;
    private SharedPreferences clickSP;

    private PromotionLinkClickDAO() {
    }

    public static PromotionLinkClickDAO getInstance() {
        if (singleton == null) {
            singleton = new PromotionLinkClickDAO();
        }
        return singleton;
    }

    private SharedPreferences getSharedPreference(Context context) {
        if (this.clickSP == null) {
            this.clickSP = context.getSharedPreferences(LINK_CLICK_SP_NAME, 0);
        }
        return this.clickSP;
    }

    private Editor getEditor(Context context) {
        if (this.clickEditor == null) {
            this.clickEditor = getSharedPreference(context).edit();
        }
        return this.clickEditor;
    }

    public void saveLinkClick(Context context, int campaignKey) {
        getEditor(context).putInt(new StringBuilder(String.valueOf(campaignKey)).toString(), campaignKey);
        getEditor(context).commit();
    }

    public int getLinkClick(Context context, int campaignKey) {
        return getSharedPreference(context).getInt(new StringBuilder(String.valueOf(campaignKey)).toString(), -1);
    }
}