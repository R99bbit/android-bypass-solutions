package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Iterator;
import org.json.JSONException;
import org.json.JSONObject;

public class ActivityInfoDAO {
    public static final String ACTIVITY_FOR_REFERRAL_SP_NAME = "referralActivityForTracking";

    public static SharedPreferences getActivityForReferralSP(Context context) {
        return context.getSharedPreferences(ACTIVITY_FOR_REFERRAL_SP_NAME, 0);
    }

    public static ArrayList<String> getActivityInfoForReferral(final Context context) {
        try {
            ArrayList<String> activity_info_list = new ArrayList<>();
            Collection<?> values = getActivityForReferralSP(context).getAll().values();
            if (values.size() != 0) {
                Iterator<?> it = values.iterator();
                while (it.hasNext()) {
                    String activity = (String) it.next();
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > start session >> send activity for referral: " + activity, 3);
                    activity_info_list.add(activity);
                }
            }
            new Thread(new Runnable() {
                public void run() {
                    Editor editor = ActivityInfoDAO.getActivityForReferralSP(context).edit();
                    editor.clear();
                    editor.commit();
                }
            }).start();
            return activity_info_list;
        } catch (Exception e) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "error occurred during restoreReferralTrackingInfo : " + e.toString() + " / " + e.getMessage(), 0, false);
            return new ArrayList<>();
        }
    }

    public static void addActivityInfoForReferral(final Context context, final String key, final String val) {
        new Thread(new Runnable() {
            public void run() {
                Editor referralActivityTrackingEditor = ActivityInfoDAO.getActivityForReferralSP(context).edit();
                referralActivityTrackingEditor.putString(key, val);
                referralActivityTrackingEditor.commit();
            }
        }).start();
    }

    public static void clearActivityInfoForReferral(final Context context) {
        new Thread(new Runnable() {
            public void run() {
                Editor referralActivityTrackingEditor = ActivityInfoDAO.getActivityForReferralSP(context).edit();
                referralActivityTrackingEditor.clear();
                referralActivityTrackingEditor.commit();
            }
        }).start();
    }

    public static void restoreReferralTrackingInfo(final Context context, final ArrayList<String> activity_info_list) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    if (activity_info_list != null) {
                        Editor trackingEditor = ActivityInfoDAO.getActivityForReferralSP(context).edit();
                        JSONObject aActivityObj = null;
                        int i = 0;
                        while (true) {
                            JSONObject aActivityObj2 = aActivityObj;
                            if (i >= activity_info_list.size()) {
                                trackingEditor.commit();
                                return;
                            }
                            String activity = (String) activity_info_list.get(i);
                            try {
                                aActivityObj = new JSONObject(activity);
                                try {
                                    trackingEditor.putString(new StringBuilder(String.valueOf(Calendar.getInstance().getTime().getTime())).append(EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR).append(aActivityObj.getString("group")).append(EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR).append(aActivityObj.getString("activity")).toString(), activity);
                                } catch (JSONException e) {
                                    e = e;
                                }
                            } catch (JSONException e2) {
                                e = e2;
                                aActivityObj = aActivityObj2;
                                trackingEditor.putString(activity, activity);
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "error occurred during callbackReferralTrackingADBrix : " + e.toString(), 0);
                                i++;
                            }
                            i++;
                        }
                    }
                } catch (Exception e3) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "error occurred during restoreReferralTrackingInfo : " + e3.toString() + " / " + e3.getMessage(), 0, false);
                }
            }
        }).start();
    }
}