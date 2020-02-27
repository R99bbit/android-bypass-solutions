package com.igaworks;

import android.app.Application;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;

public class IgawDefaultApplication extends Application {
    public void onCreate() {
        super.onCreate();
        try {
            IgawLogger.Logging(getApplicationContext(), IgawConstant.QA_TAG, "Initialized IgawApplication", 3, false);
            try {
                Class.forName("android.os.AsyncTask");
            } catch (Throwable th) {
            }
            IgawCommon.autoSessionTracking(this);
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "Error: " + e.toString());
        }
    }
}