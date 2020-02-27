package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import java.util.Collection;

public class NotAvailableCampaignDAO {
    public static final String NOT_AVAILABLE_SP_NAME = "not_available_campaign_sp";
    private static NotAvailableCampaignDAO singleton;
    private Editor notAvailablecampaignEditor;
    private SharedPreferences notAvailablecampaignSP;

    private NotAvailableCampaignDAO() {
    }

    public static NotAvailableCampaignDAO getInstance() {
        if (singleton == null) {
            singleton = new NotAvailableCampaignDAO();
        }
        return singleton;
    }

    private SharedPreferences getSharedPreference(Context context) {
        if (this.notAvailablecampaignSP == null) {
            this.notAvailablecampaignSP = context.getSharedPreferences(NOT_AVAILABLE_SP_NAME, 0);
        }
        return this.notAvailablecampaignSP;
    }

    /* access modifiers changed from: private */
    public Editor getEditor(Context context) {
        if (this.notAvailablecampaignEditor == null) {
            this.notAvailablecampaignEditor = getSharedPreference(context).edit();
        }
        return this.notAvailablecampaignEditor;
    }

    public void saveNotAvailableCampaign(final Context context, final int campaignKey) {
        new Thread(new Runnable() {
            public void run() {
                NotAvailableCampaignDAO.this.getEditor(context).putInt(new StringBuilder(String.valueOf(campaignKey)).toString(), campaignKey);
                NotAvailableCampaignDAO.this.getEditor(context).commit();
            }
        }).start();
    }

    public Collection<Integer> getNotAvailableCampaign(Context context) {
        return getSharedPreference(context).getAll().values();
    }
}