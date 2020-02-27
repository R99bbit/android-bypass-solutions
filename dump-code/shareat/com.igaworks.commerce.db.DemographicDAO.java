package com.igaworks.commerce.db;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;

public class DemographicDAO {
    public static final String KEY_HASHED_EMAIL = "email";
    public static final String KEY_USN = "userId";

    public static void saveDemographic(final Context context, final String key, final String value) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    if (context == null) {
                        Log.e(IgawConstant.QA_TAG, "save demo error >> context is null.");
                        return;
                    }
                    Editor persistantDemoEditor = context.getSharedPreferences("persistantDemoForTracking", 0).edit();
                    persistantDemoEditor.putString(key, value);
                    persistantDemoEditor.commit();
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerce > save_demographic() >> key " + key + " value : " + value, 3);
                    Editor demoEditor = context.getSharedPreferences("demoForTracking", 0).edit();
                    demoEditor.putString(key, value);
                    demoEditor.commit();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public static String getDemographic(Context context, String key) {
        if (context == null) {
            try {
                Log.e(IgawConstant.QA_TAG, "save demo error >> context is null.");
                return null;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        } else {
            SharedPreferences persistantDemoPref = context.getSharedPreferences("persistantDemoForTracking", 0);
            if (persistantDemoPref.contains(key)) {
                return persistantDemoPref.getString(key, null);
            }
            return null;
        }
    }
}