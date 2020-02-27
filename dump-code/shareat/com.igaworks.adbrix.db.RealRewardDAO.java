package com.igaworks.adbrix.db;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class RealRewardDAO {
    public static final String COMPLETE_KEY_POSTFIX = "_cp";
    public static final String DAILY_COMPLETION_KEY_POSTFIX = "_dc";
    public static final String REAL_REWARD_SP_NAME = "real_reward_sp";
    public static final String RETRY_COMPLETE_KEY_POSTFIX = "_rc";
    public static final String RETRY_REDEEM_KEY_POSTFIX = "_rr";
    public static final String SESSION_KEY_POSTFIX = "_ss";
    public static final String SESSION_TIME_KEY_POSTFIX = "_st";
    public static SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
    private static RealRewardDAO singleton;

    private RealRewardDAO() {
    }

    public static RealRewardDAO getInstance() {
        if (singleton == null) {
            singleton = new RealRewardDAO();
        }
        return singleton;
    }

    private SharedPreferences getSharedPreference(Context context, String postfix) {
        return context.getSharedPreferences(new StringBuilder(REAL_REWARD_SP_NAME).append(postfix).toString(), 0);
    }

    private Editor getEditor(Context context, String postfix) {
        return getSharedPreference(context, postfix).edit();
    }

    public void saveSessionNo(Context context, int rrk, long sessionNo) {
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "save session : rrk/sn = " + rrk + "/" + sessionNo, 3);
        Editor edt = getEditor(context, SESSION_KEY_POSTFIX);
        edt.putLong(new StringBuilder(String.valueOf(rrk)).toString(), sessionNo);
        edt.commit();
        Editor edt2 = getEditor(context, SESSION_TIME_KEY_POSTFIX);
        edt2.putLong(new StringBuilder(String.valueOf(sessionNo)).toString(), new Date().getTime());
        edt2.commit();
    }

    public long getSessionNo(Context context, int rrk) {
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "get session : " + getSharedPreference(context, SESSION_KEY_POSTFIX).contains(new StringBuilder(String.valueOf(rrk)).toString()), 3);
        if (getSharedPreference(context, SESSION_KEY_POSTFIX).contains(new StringBuilder(String.valueOf(rrk)).toString())) {
            return getSharedPreference(context, SESSION_KEY_POSTFIX).getLong(new StringBuilder(String.valueOf(rrk)).toString(), -1);
        }
        return -1;
    }

    public Map<String, Long> getActiveSessionNo(Context context) {
        return getSharedPreference(context, SESSION_KEY_POSTFIX).getAll();
    }

    public long getSessionTime(Context context, long sn) {
        return getSharedPreference(context, SESSION_TIME_KEY_POSTFIX).getLong(new StringBuilder(String.valueOf(sn)).toString(), -1);
    }

    public void clearSessions(Context context, int rrk) {
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "clearSessions", 3);
        long sn = getSharedPreference(context, SESSION_KEY_POSTFIX).getLong(new StringBuilder(String.valueOf(rrk)).toString(), -1);
        Editor edt = getEditor(context, SESSION_KEY_POSTFIX);
        edt.remove(new StringBuilder(String.valueOf(rrk)).toString());
        edt.commit();
        Editor edt2 = getEditor(context, SESSION_TIME_KEY_POSTFIX);
        edt2.remove(new StringBuilder(String.valueOf(sn)).toString());
        edt2.commit();
    }

    public void saveCompletedRealRewardKey(Context context, int rrk) {
        Editor edt = getEditor(context, COMPLETE_KEY_POSTFIX);
        edt.putInt(new StringBuilder(String.valueOf(rrk)).toString(), rrk);
        edt.commit();
    }

    public boolean isCompetedRealReward(Context context, int rrk) {
        if (getSharedPreference(context, COMPLETE_KEY_POSTFIX).contains(new StringBuilder(String.valueOf(rrk)).toString())) {
            return true;
        }
        return false;
    }

    public void saveRetryCompleteCache(Context context, int rrk, long sn) {
        Editor edt = getEditor(context, RETRY_COMPLETE_KEY_POSTFIX);
        edt.putLong(new StringBuilder(String.valueOf(rrk)).toString(), sn);
        edt.commit();
    }

    public Map<String, Long> getRetryCompleteCache(Context context) {
        return getSharedPreference(context, RETRY_COMPLETE_KEY_POSTFIX).getAll();
    }

    public void clearRetryCompleteCache(Context context, int rrk) {
        Editor edt = getEditor(context, RETRY_COMPLETE_KEY_POSTFIX);
        edt.remove(new StringBuilder(String.valueOf(rrk)).toString());
        edt.commit();
    }

    public void saveRetryRedeemCache(Context context, int rrk, long sn) {
        Editor edt = getEditor(context, RETRY_REDEEM_KEY_POSTFIX);
        edt.putLong(new StringBuilder(String.valueOf(rrk)).toString(), sn);
        edt.commit();
    }

    public Map<String, Long> getRetryRedeemCache(Context context) {
        return getSharedPreference(context, RETRY_REDEEM_KEY_POSTFIX).getAll();
    }

    public void clearRetryRedeemCache(Context context, int rrk) {
        Editor edt = getEditor(context, RETRY_REDEEM_KEY_POSTFIX);
        edt.remove(new StringBuilder(String.valueOf(rrk)).toString());
        edt.commit();
    }

    private String getDay() {
        return sdf.format(new Date());
    }

    public void saveDailyCompletion(Context context, int rrk) {
        Editor edt = getEditor(context, DAILY_COMPLETION_KEY_POSTFIX);
        edt.putInt(getDay() + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + rrk, rrk);
        edt.commit();
    }

    public boolean hasCompleteToday(Context context, int rrk) {
        return getSharedPreference(context, DAILY_COMPLETION_KEY_POSTFIX).contains(getDay() + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + rrk);
    }
}