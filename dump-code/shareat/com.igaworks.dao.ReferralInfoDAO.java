package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;

public class ReferralInfoDAO {
    public static final String SENT_CPI_REFERRER_SUCCESS = "success_send_cpi_referrer";
    public static boolean onReceiveReferral = false;

    public static void setReferralInfo(Context context, int referrerConversionKey, long session_no, String referrerParams) {
        onReceiveReferral = true;
        try {
            Editor referrerEditor = context.getSharedPreferences("referral_info", 0).edit();
            if (referrerConversionKey > -1) {
                referrerEditor.putInt("conversion_key", referrerConversionKey);
            }
            if (session_no > -1) {
                referrerEditor.putLong("session_no", session_no);
            }
            referrerEditor.putString("referrer_param", referrerParams);
            referrerEditor.putBoolean("onReceiveReferral", true);
            referrerEditor.commit();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format("ReferralInfo >> IgawReceiver onReceive(): recieved Google referrer, (conversion_key = %d, session_no = %d)", new Object[]{Integer.valueOf(referrerConversionKey), Long.valueOf(session_no)}), 3, false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static int getReferralInfo_conversionKey(Context context) {
        SharedPreferences conversionPref = context.getSharedPreferences("referral_info", 0);
        try {
            return conversionPref.getInt("conversion_key", -1);
        } catch (Exception e) {
            try {
                return Integer.parseInt(conversionPref.getString("conversion_key", "-1"));
            } catch (Exception e2) {
                return -1;
            }
        }
    }

    public static long getReferralInfo_session_no(Context context) {
        SharedPreferences conversionPref = context.getSharedPreferences("referral_info", 0);
        try {
            return conversionPref.getLong("session_no", -1);
        } catch (Exception e) {
            try {
                return Long.parseLong(conversionPref.getString("session_no", "-1"));
            } catch (Exception e2) {
                return -1;
            }
        }
    }

    public static String getReferralInfo_referrer_params(Context context) {
        String referrerParam = "";
        try {
            return context.getSharedPreferences("referral_info", 0).getString("referrer_param", "");
        } catch (Exception e) {
            e.printStackTrace();
            return referrerParam;
        }
    }

    public static void clearOnReceiveReferralFlag(Context context) {
        try {
            onReceiveReferral = false;
            Editor referrerEditor = context.getSharedPreferences("referral_info", 0).edit();
            referrerEditor.putBoolean("onReceiveReferral", false);
            referrerEditor.putBoolean(SENT_CPI_REFERRER_SUCCESS, true);
            referrerEditor.commit();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ReferralInfoDAO >> clearOnReceiveReferralFlag", 3, true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean getOnReceiveReferralFlag(Context context) {
        boolean onReceiveReferral_;
        if (onReceiveReferral) {
            return true;
        }
        try {
            onReceiveReferral_ = context.getSharedPreferences("referral_info", 0).getBoolean("onReceiveReferral", false);
        } catch (Exception e) {
            e.printStackTrace();
            onReceiveReferral_ = false;
        }
        return onReceiveReferral_;
    }

    public static boolean isSentRefferrerSuccess2Adbrix(Context context) {
        try {
            return context.getSharedPreferences("referral_info", 0).getBoolean(SENT_CPI_REFERRER_SUCCESS, false);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}