package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.dao.tracking.TrackingActivityModel;
import com.igaworks.dao.tracking.TrackingActivitySQLiteDB;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

@Deprecated
public class TrackingParamDAO {
    public static ArrayList<String> getActivityListParam(Context context, String group, String act, long endSessionParam) {
        Log.i(IgawConstant.QA_TAG, "Pls update Adbrix SDK to latest version");
        try {
            SharedPreferences tracerSP = context.getSharedPreferences("activityForTracking", 0);
            Editor trackingEditor = tracerSP.edit();
            Collection<?> trackingCollection = null;
            if (trackingCollection == null || trackingCollection.size() < 1) {
                trackingCollection = tracerSP.getAll().keySet();
            }
            ArrayList<String> activity_info_list = new ArrayList<>();
            new ArrayList();
            if (!(trackingCollection == null || trackingCollection.size() == 0)) {
                Iterator<?> it = trackingCollection.iterator();
                while (it.hasNext()) {
                    String key = (String) it.next();
                    String activity = tracerSP.getString(key, null);
                    trackingEditor.remove(key);
                    if (activity != null) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > send activity for tracking from SP: " + activity, 3);
                        activity_info_list.add(activity);
                    }
                }
                trackingEditor.apply();
            }
            Task<ArrayList<TrackingActivityModel>> getAppTrackingTask = TrackingActivitySQLiteDB.getInstance(context).getActivityListParam(true, context, group, act, endSessionParam);
            try {
                TaskUtils.wait(getAppTrackingTask);
                if (getAppTrackingTask.getError() != null) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "getAppTrackingTask: " + getAppTrackingTask.getError(), 0, true);
                    return activity_info_list;
                }
                ArrayList arrayList = (ArrayList) getAppTrackingTask.getResult();
                for (int i = 0; i < arrayList.size(); i++) {
                    activity_info_list.add(((TrackingActivityModel) arrayList.get(i)).getValue());
                }
                return activity_info_list;
            } catch (Exception ex) {
                Log.e(IgawConstant.QA_TAG, "Compat >> getAppTrackingTask error:" + ex.getMessage());
                return activity_info_list;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return new ArrayList<>();
        }
    }

    public static int getActivityCount(Context context) {
        try {
            SharedPreferences tracerSP = context.getSharedPreferences("activityForTracking", 0);
            if (tracerSP == null) {
                return 0;
            }
            return tracerSP.getAll().size();
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    public static ArrayList<String> getImpListParam(Context context) {
        try {
            CPEPromotionImpressionDAO impressionDao = CPEPromotionImpressionDAO.getInstance();
            ArrayList<String> imp_info_list = impressionDao.getImpressionData(context);
            impressionDao.clearImpressionData(context);
            return imp_info_list;
        } catch (Exception e) {
            e.printStackTrace();
            return new ArrayList<>();
        }
    }
}