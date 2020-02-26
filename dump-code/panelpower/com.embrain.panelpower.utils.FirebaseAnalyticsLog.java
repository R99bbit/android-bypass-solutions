package com.embrain.panelpower.utils;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.widget.Toast;
import com.embrain.panelbigdata.utils.StringUtils;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.google.gson.Gson;

public class FirebaseAnalyticsLog {
    private static final String EVENT = "event";
    private static final String EVENT_SIGN_UP = "Panel_SignUp";
    private static final String METHOD = "method";
    private static final String USER_ID = "user_id";
    private static FirebaseAnalyticsLog mInstance;
    private Activity mActivity;
    private FirebaseAnalytics mFirebaseAnalytics;

    public class PanelSignUpVo {
        public String event;
        public String method;
        public String user_id;

        public PanelSignUpVo() {
        }
    }

    public static FirebaseAnalyticsLog getInstance(Activity activity) {
        if (mInstance == null) {
            mInstance = new FirebaseAnalyticsLog(activity);
        }
        return mInstance;
    }

    private FirebaseAnalyticsLog(Activity activity) {
        this.mActivity = activity;
        this.mFirebaseAnalytics = FirebaseAnalytics.getInstance(activity);
    }

    public void logEvent(String str) {
        try {
            PanelSignUpVo panelSignUpVo = (PanelSignUpVo) new Gson().fromJson(str, PanelSignUpVo.class);
            if (StringUtils.isEmpty(panelSignUpVo.event)) {
                throw new Exception("event is null");
            } else if (!StringUtils.isEmpty(panelSignUpVo.method)) {
                Bundle bundle = new Bundle();
                bundle.putString("method", panelSignUpVo.method);
                bundle.putString(USER_ID, panelSignUpVo.user_id);
                this.mFirebaseAnalytics.logEvent(panelSignUpVo.event, bundle);
                PanelPreferenceUtils.setTempUserId(this.mActivity, panelSignUpVo.user_id);
            } else {
                throw new Exception("method is null");
            }
        } catch (Exception e) {
            e.printStackTrace();
            Context applicationContext = this.mActivity.getApplicationContext();
            StringBuilder sb = new StringBuilder();
            sb.append("firebase log event Error : ");
            sb.append(e.getMessage());
            Toast.makeText(applicationContext, sb.toString(), 0).show();
        }
    }
}