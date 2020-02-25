package com.embrain.panelpower;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.util.Log;
import androidx.annotation.Nullable;
import com.embrain.panelbigdata.EmBigDataManager;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.habit_signal.HabitSignalManager;
import com.embrain.panelpower.utils.LogUtil;
import com.embrain.panelpower.vo.UserSession;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class UserInfoManager {
    public static final String AGREE_N = "N";
    public static final String AGREE_Y = "Y";
    public static final String LOGIN_FAILED_INVALID_CAPTCHA = "invalid-captcha";
    public static final String LOGIN_FAILED_INVALID_ETC = "invalid-etc";
    public static final String LOGIN_FAILED_INVALID_LOGIN = "invalid-login";
    private static final String PREF_ACTIVE_GRADE = "activeGrade";
    private static final String PREF_BIRTHDATE = "birthdate";
    private static final String PREF_DENIED_CNT_LOCATION = "denied_loc";
    private static final String PREF_DENIED_CNT_PAY = "denied_pay";
    private static final String PREF_DENIED_CNT_PUSH = "denied_push";
    private static final String PREF_DENIED_CNT_USAGE = "denied_usage";
    private static final String PREF_FLOAT_DENIED_CNT_LOCATION = "float_denied_location";
    private static final String PREF_FLOAT_DENIED_CNT_PAY = "float_denied_pay";
    private static final String PREF_FLOAT_DENIED_CNT_PUSH = "float_denied_push";
    private static final String PREF_FLOAT_DENIED_CNT_USAGE = "float_denied_usage";
    private static final String PREF_GENDER = "gender";
    public static final String PREF_HBIT_USERID = "PREF_HBIT_USERID";
    private static final String PREF_INFO_EXT = "infoExt";
    private static final String PREF_INFO_LOCATION = "infoLocation";
    private static final String PREF_INFO_PAY = "infoPay";
    private static final String PREF_IS_PUSH_YN_SURVEY = "isPushYnSurvey";
    private static final String PREF_MEMBER_SECTION = "memSection";
    private static final String PREF_NAME = "panel_user";
    private static final String PREF_PANEL_ID = "panelId";
    public static final String PREF_PERMISSION_HBIT_CREATE_USERID = "PREF_PERMISSION_HBIT_CREATE_USERID";
    private static final String PREF_USER_ID = "user_id";
    private static final String PREF_USER_NAME = "name";
    private static final String PREF_USER_PW = "user_pw";
    private static final String TAG = "UserInfoManager";
    private static UserInfoManager mInstance;
    public static String mKakaoMsg;
    public static String mLineMsg;
    private static SharedPreferences mPref;
    public static String mUserName;
    private Context mContext;

    public class UserInfo {
        public static final String ACTIVE_GRADE_ACTIVE = "1";
        public static final String ACTIVE_GRADE_NOT_ACTIVE = "N";
        public static final String MEMBER_SECTION_MEMBER_FROM_E = "E";
        public static final String MEMBER_SECTION_MEMBER_FROM_MOBILE = "M";
        public static final String MEMBER_SECTION_MEMBER_FROM_PC = "P";
        public static final String MEMBER_SECTION_TEMP_MEMBER = "T";
        String activeGrade;
        String birthdate;
        String gender;
        String infoExt;
        String infoLocation;
        String infoPay;
        String isPushYnSurvey;
        String memSection;
        String name;
        String panelId;
        String userId;
        String userPw;

        private UserInfo(SharedPreferences sharedPreferences) {
            this.panelId = sharedPreferences.getString(UserInfoManager.PREF_PANEL_ID, null);
            this.userId = sharedPreferences.getString(UserInfoManager.PREF_USER_ID, null);
            this.userPw = sharedPreferences.getString(UserInfoManager.PREF_USER_PW, null);
            this.birthdate = sharedPreferences.getString(UserInfoManager.PREF_BIRTHDATE, null);
            this.gender = sharedPreferences.getString(UserInfoManager.PREF_GENDER, null);
            this.name = sharedPreferences.getString("name", null);
            this.memSection = sharedPreferences.getString(UserInfoManager.PREF_MEMBER_SECTION, "N");
            this.activeGrade = sharedPreferences.getString(UserInfoManager.PREF_ACTIVE_GRADE, "N");
            this.infoExt = sharedPreferences.getString(UserInfoManager.PREF_INFO_EXT, "N");
            this.infoLocation = sharedPreferences.getString(UserInfoManager.PREF_INFO_LOCATION, "N");
            this.infoPay = sharedPreferences.getString(UserInfoManager.PREF_INFO_PAY, "N");
            this.isPushYnSurvey = sharedPreferences.getString(UserInfoManager.PREF_IS_PUSH_YN_SURVEY, "N");
        }

        public String getPanelId() {
            return this.panelId;
        }

        public boolean isTempUser() {
            return StringUtils.isEmpty(this.panelId);
        }

        public String getMemSection() {
            return this.memSection;
        }

        public String getActiveGrade() {
            return this.activeGrade;
        }

        public String getInfoExt() {
            return this.infoExt;
        }

        public String getInfoLocation() {
            return this.infoLocation;
        }

        public String getInfoPay() {
            return this.infoPay;
        }

        public String getIsPushYnSurvey() {
            return this.isPushYnSurvey;
        }

        public String getUser_id() {
            return this.userId;
        }

        public String getUser_pw() {
            return this.userPw;
        }

        public String getBirthdate() {
            return this.birthdate;
        }

        public String getBirthYear() throws Exception {
            return this.birthdate.substring(0, 4);
        }

        public String getGender() {
            return this.gender;
        }

        public String getUserNm() {
            return this.name;
        }

        public boolean equals(@Nullable Object obj) {
            try {
                if (obj instanceof UserInfo) {
                    UserInfo userInfo = (UserInfo) obj;
                    return this.panelId.equals(userInfo.panelId) && this.userId.equals(userInfo.userId);
                }
            } catch (Exception unused) {
            }
            return super.equals(obj);
        }
    }

    public static UserInfoManager getInstance(Context context) {
        if (mInstance == null) {
            mInstance = new UserInfoManager(context);
        }
        return mInstance;
    }

    public UserInfoManager(Context context) {
        this.mContext = context;
        getPref(context);
    }

    private static SharedPreferences getPref(Context context) {
        if (mPref == null) {
            mPref = context.getSharedPreferences(PREF_NAME, 0);
        }
        return mPref;
    }

    public boolean setUserInfo(UserInfo userInfo) {
        try {
            UserInfo userInfo2 = getUserInfo();
            if (userInfo2 != null && !userInfo2.equals(userInfo) && !userInfo2.isTempUser()) {
                Log.w(TAG, "[saveUserInfo] change User Info");
                deleteUserInfo();
            }
            Editor edit = getPref(this.mContext).edit();
            if (!StringUtils.isEmpty(userInfo.userPw)) {
                edit.putString(PREF_PANEL_ID, userInfo.panelId);
                edit.putString(PREF_USER_ID, userInfo.userId);
                edit.putString(PREF_USER_PW, userInfo.userPw);
            } else if (userInfo2.isTempUser()) {
                edit.putString(PREF_PANEL_ID, userInfo.panelId);
            }
            edit.putString("name", userInfo.name);
            edit.putString(PREF_GENDER, userInfo.gender);
            edit.putString(PREF_BIRTHDATE, userInfo.birthdate);
            edit.putString(PREF_MEMBER_SECTION, userInfo.memSection);
            edit.putString(PREF_ACTIVE_GRADE, userInfo.activeGrade);
            edit.apply();
            setAgreePush(this.mContext, userInfo.getIsPushYnSurvey());
            setAgreePay(this.mContext, userInfo.getInfoPay());
            setAgreeUsage(this.mContext, userInfo.getInfoExt());
            setAgreeLocation(this.mContext, userInfo.getInfoLocation());
            EmBigDataManager.setPanelId(this.mContext, userInfo.panelId);
            return true;
        } catch (Exception e) {
            String str = TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("[saveUserInfo] Error during save user info : ");
            sb.append(e.getMessage());
            Log.w(str, sb.toString());
            e.printStackTrace();
            return false;
        }
    }

    public void setPassword(String str) {
        if (getUserInfo() == null) {
            LogUtil.write("setPassword() : userInfo is null");
            return;
        }
        Editor edit = getPref(this.mContext).edit();
        edit.putString(PREF_USER_PW, str);
        edit.apply();
    }

    @Deprecated
    public void saveUserInfo(UserSession userSession, String str) {
        try {
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty((String) PREF_MEMBER_SECTION, userSession.memSection);
            jsonObject.addProperty((String) PREF_ACTIVE_GRADE, userSession.activeGrade);
            jsonObject.addProperty((String) PREF_INFO_EXT, userSession.infoExt);
            jsonObject.addProperty((String) PREF_INFO_LOCATION, userSession.infoLocation);
            jsonObject.addProperty((String) PREF_INFO_PAY, userSession.infoPay);
            jsonObject.addProperty((String) PREF_IS_PUSH_YN_SURVEY, userSession.isPushYnSurvey);
            jsonObject.addProperty((String) PREF_PANEL_ID, userSession.panelId);
            jsonObject.addProperty((String) "userId", userSession.userId);
            jsonObject.addProperty((String) "userPw", str);
            getInstance(this.mContext).setUserInfo((UserInfo) new Gson().fromJson(jsonObject.toString(), UserInfo.class));
        } catch (Exception e) {
            LogUtil.write("\ub85c\uadf8\uc778 \uc815\ubcf4 \uc800\uc7a5\uc5d0 \uc2e4\ud328\ud588\uc2b5\ub2c8\ub2e4. ");
            e.printStackTrace();
        }
    }

    private boolean validate(UserInfo userInfo) {
        return userInfo != null && !StringUtils.isEmpty(userInfo.userId);
    }

    public String getPanelId() {
        try {
            return getUserInfo().getPanelId();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public UserInfo getUserInfo() {
        UserInfo userInfo = new UserInfo(getPref(this.mContext));
        if (validate(userInfo)) {
            return userInfo;
        }
        return null;
    }

    public void deleteUserInfo() {
        LogUtil.write("[UserInfoManager] delete User Info");
        getPref(this.mContext).edit().clear().apply();
        EmBigDataManager.setPanelId(this.mContext, "");
        EmBigDataManager.setLocationAgree(this.mContext, false);
        EmBigDataManager.setUsageAgree(this.mContext, false);
        HabitSignalManager.quitSignalLib(this.mContext);
    }

    public static void addDeniedCntPush(Context context) {
        getPref(context).edit().putInt(PREF_DENIED_CNT_PUSH, getDeniedCntPush(context) + 1).apply();
    }

    public static int getDeniedCntPush(Context context) {
        return getPref(context).getInt(PREF_DENIED_CNT_PUSH, 0);
    }

    public static void addDeniedCntLocation(Context context) {
        getPref(context).edit().putInt(PREF_DENIED_CNT_LOCATION, getDeniedCntLocation(context) + 1).apply();
    }

    public static int getDeniedCntLocation(Context context) {
        return getPref(context).getInt(PREF_DENIED_CNT_LOCATION, 0);
    }

    public static void addDeniedCntUsage(Context context) {
        getPref(context).edit().putInt(PREF_DENIED_CNT_USAGE, getDeniedCntUsage(context) + 1).apply();
    }

    public static int getDeniedCntUsage(Context context) {
        return getPref(context).getInt(PREF_DENIED_CNT_USAGE, 0);
    }

    public static void addDeniedCntPay(Context context) {
        getPref(context).edit().putInt(PREF_DENIED_CNT_PAY, getDeniedCntPay(context) + 1).apply();
    }

    public static int getDeniedCntPay(Context context) {
        return getPref(context).getInt(PREF_DENIED_CNT_PAY, 0);
    }

    public static void addFloatDeniedCntPay(Context context) {
        getPref(context).edit().putInt(PREF_FLOAT_DENIED_CNT_PAY, getFloatDeniedCntPay(context) + 1).apply();
    }

    public static int getFloatDeniedCntPay(Context context) {
        return getPref(context).getInt(PREF_FLOAT_DENIED_CNT_PAY, 0);
    }

    public static void addFloatDeniedCntUsage(Context context) {
        getPref(context).edit().putInt(PREF_FLOAT_DENIED_CNT_USAGE, getFloatDeniedCntUsage(context) + 1).apply();
    }

    public static int getFloatDeniedCntUsage(Context context) {
        return getPref(context).getInt(PREF_FLOAT_DENIED_CNT_USAGE, 0);
    }

    public static void addFloatDeniedCntLocation(Context context) {
        getPref(context).edit().putInt(PREF_FLOAT_DENIED_CNT_LOCATION, getFloatDeniedCntLocation(context) + 1).apply();
    }

    public static int getFloatDeniedCntLocation(Context context) {
        return getPref(context).getInt(PREF_FLOAT_DENIED_CNT_LOCATION, 0);
    }

    public static void addFloatDeniedCntPush(Context context) {
        getPref(context).edit().putInt(PREF_FLOAT_DENIED_CNT_PUSH, getFloatDeniedCntPush(context) + 1).apply();
    }

    public static int getFloatDeniedCntPush(Context context) {
        return getPref(context).getInt(PREF_FLOAT_DENIED_CNT_PUSH, 0);
    }

    public static void setAgreePush(Context context, String str) {
        getPref(context).edit().putString(PREF_IS_PUSH_YN_SURVEY, str).apply();
    }

    public static void setAgreePay(Context context, String str) {
        getPref(context).edit().putString(PREF_INFO_PAY, str).apply();
        if ("N".equals(str)) {
            HabitSignalManager.quitSignalLib(context);
        } else {
            HabitSignalManager.initSignalLib(context);
        }
    }

    public static void setAgreeUsage(Context context, String str) {
        getPref(context).edit().putString(PREF_INFO_EXT, str).apply();
        EmBigDataManager.setUsageAgree(context, AGREE_Y.equals(str));
    }

    public static void setAgreeLocation(Context context, String str) {
        getPref(context).edit().putString(PREF_INFO_LOCATION, str).apply();
        EmBigDataManager.setLocationAgree(context, AGREE_Y.equals(str));
    }

    public static void setHabitUserId(Context context, String str) {
        getPref(context).edit().putString(PREF_HBIT_USERID, str).apply();
    }

    public static String getHabitUserId(Context context) {
        return getPref(context).getString(PREF_HBIT_USERID, null);
    }
}