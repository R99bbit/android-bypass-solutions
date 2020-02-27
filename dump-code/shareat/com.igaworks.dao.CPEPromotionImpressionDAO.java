package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.dao.tracking.TrackingActivityModel;
import com.igaworks.dao.tracking.TrackingActivitySQLiteDB;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import java.util.ArrayList;
import java.util.Iterator;

@Deprecated
public class CPEPromotionImpressionDAO {
    public static final String CPE_PROMOTION_IMPRESSION_SP_NAME = "promotion_impression_sp";
    public static final String SP_CAMPAIGN_KEY = "campaign_key";
    public static final String SP_CREATED_AT = "created_at";
    public static final String SP_RESOURCE_KEY = "resource_key";
    public static final String SP_SPACE_KEY = "space_key";
    protected static Editor promotionImpressionEditor;
    protected static SharedPreferences promotionImpressionSP;
    protected static CPEPromotionImpressionDAO singleton;

    private CPEPromotionImpressionDAO() {
    }

    public static CPEPromotionImpressionDAO getInstance() {
        if (singleton == null) {
            singleton = new CPEPromotionImpressionDAO();
        }
        return singleton;
    }

    private SharedPreferences getSharedPreference(Context context) {
        if (promotionImpressionSP == null) {
            promotionImpressionSP = context.getSharedPreferences(CPE_PROMOTION_IMPRESSION_SP_NAME, 0);
        }
        return promotionImpressionSP;
    }

    /* access modifiers changed from: private */
    public Editor getEditor(Context context) {
        if (promotionImpressionEditor == null) {
            promotionImpressionEditor = getSharedPreference(context).edit();
        }
        return promotionImpressionEditor;
    }

    public ArrayList<String> getImpressionData(Context context) {
        Log.i(IgawConstant.QA_TAG, "Pls update Adbrix SDK to latest version");
        SharedPreferences sp = getSharedPreference(context);
        ArrayList<String> result = new ArrayList<>();
        Iterator<?> it = sp.getAll().values().iterator();
        while (it.hasNext()) {
            result.add((String) it.next());
        }
        clearImpressionData(context);
        try {
            Task<ArrayList<TrackingActivityModel>> impressionTrackingTask = TrackingActivitySQLiteDB.getInstance(context).getImpressionData(true, context);
            TaskUtils.wait(impressionTrackingTask);
            if (impressionTrackingTask.getError() != null) {
                Log.e(IgawConstant.QA_TAG, "Error when getting impression: " + impressionTrackingTask.getError().getMessage());
            } else {
                ArrayList<TrackingActivityModel> list = (ArrayList) impressionTrackingTask.getResult();
                for (int i = 0; i < list.size(); i++) {
                    result.add(list.get(i).getValue());
                }
            }
        } catch (Exception ex) {
            Log.e(IgawConstant.QA_TAG, "Error when geting impression tracking" + ex.getMessage());
        }
        return result;
    }

    public void clearImpressionData(final Context context) {
        new Thread(new Runnable() {
            public void run() {
                Editor editor = CPEPromotionImpressionDAO.this.getEditor(context);
                editor.clear();
                editor.commit();
            }
        }).start();
    }

    public void setImpressionData(Context context, int campaignKey, int resourceKey, String spaceKey, String createdAt) {
        TrackingActivitySQLiteDB.getInstance(context).setImpressionData(context, campaignKey, resourceKey, spaceKey, CommonHelper.GetKSTCreateAtAsString(), null, null);
    }
}