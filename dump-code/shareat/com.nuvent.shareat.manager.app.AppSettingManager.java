package com.nuvent.shareat.manager.app;

import android.content.SharedPreferences.Editor;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.api.ApiUrl;

public class AppSettingManager {
    private static final String KEY_AGREE_TERMS_STATUS = "KEY_AGREE_TERMS_STATUS";
    private static final String KEY_AUTO_BRANCH_POPUP_STATUS = "KEY_AUTO_BRANCH_POPUP_STATUS";
    private static final String KEY_AUTO_BRANCH_SEARCH_STATUS = "KEY_AUTO_BRANCH_SEARCH_STATUS";
    private static final String KEY_CARD_VIEW_ACTION_GUIDE_STATUS = "KEY_CARD_VIEW_ACTION_GUIDE_STATUS";
    private static final String KEY_EVENT_VIEWING_DATE = "KEY_EVENT_VIEWING_DATE";
    private static final String KEY_GPS_LAT = "KEY_GPS_LAT";
    private static final String KEY_GPS_LNG = "KEY_GPS_LNG";
    private static final String KEY_GUIDE_VIEWING_OFF = "KEY_GUIDE_VIEWING_OFF";
    private static final String KEY_LOCATION_INFO_AGREED = "KEY_LOCATION_INFO_AGREED";
    private static final String KEY_MAIN_LIST_ACTION_GUIDE_STATUS = "KEY_MAIN_LIST_ACTION_GUIDE_STATUS";
    private static final String KEY_NAVER_MAP_VIEW_ACTION_GUIDE_STATUS = "KEY_NAVER_MAP_VIEW_ACTION_GUIDE_STATUS";
    private static final String KEY_NON_MEMBER_PUSH_STATUS = "KEY_NON_MEMBER_PUSH_STATUS";
    private static final String KEY_NOTIFICATION_COUNT = "KEY_NOTIFICATION_COUNT";
    private static final String KEY_NOTIFICATION_ID = "KEY_NOTIFICATION_ID";
    private static final String KEY_OPEN_LOCATION_CODE = "KEY_OPEN_LOCATION_CODE";
    private static final String KEY_PASSWORD_CHECK = "KEY_PASSWORD_CHECK";
    private static final String KEY_PERMISSION_CONFIRM = "KEY_PERMISSION_CONFIRM";
    private static final String KEY_SHOW_PUSH_AGREEMENT_DIALOG = "KEY_SHOW_PUSH_AGREEMENT_DIALOG";
    private static final String KEY_SNS_REVIEW_VIEWING_OFF = "KEY_SNS_REVIEW_VIEWING_OFF";
    private static final String KEY_SOCKET_URL = "KEY_SOCKET_URL";
    private static final String KEY_START_ACTIVITY = "KEY_START_ACTIVITY";
    private static final String KEY_STORE_PARAMS_JSON = "KEY_STORE_PARAMS_JSON";
    public static AppSettingManager mInstance = new AppSettingManager();
    private static final boolean sEnableAutoBranchPopup = false;

    public static synchronized AppSettingManager getInstance() {
        AppSettingManager appSettingManager;
        synchronized (AppSettingManager.class) {
            try {
                appSettingManager = mInstance;
            }
        }
        return appSettingManager;
    }

    public boolean isLocationInfoAgreed() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_LOCATION_INFO_AGREED, false);
    }

    public void setLocationInfoAgreed(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_LOCATION_INFO_AGREED, value);
        editor.commit();
    }

    public String getStoreParamsJson() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_STORE_PARAMS_JSON, "");
    }

    public void setStoreParamsJson(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_STORE_PARAMS_JSON, value);
        editor.commit();
    }

    public boolean isGuideViewingOff() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_GUIDE_VIEWING_OFF, false);
    }

    public void setGuideViewingOff(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_GUIDE_VIEWING_OFF, value);
        editor.commit();
    }

    public boolean isPasswordCheck() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_PASSWORD_CHECK, false);
    }

    public void setPasswordCheck(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_PASSWORD_CHECK, value);
        editor.commit();
    }

    public long getEventViewingDate() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getLong(KEY_EVENT_VIEWING_DATE, 0);
    }

    public void setEventViewingDate(long closeTime) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putLong(KEY_EVENT_VIEWING_DATE, closeTime);
        editor.commit();
    }

    public boolean isSnsReviewGuideView() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_SNS_REVIEW_VIEWING_OFF, true);
    }

    public void setSnsReviewGuideView(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_SNS_REVIEW_VIEWING_OFF, value);
        editor.commit();
    }

    public int getNotificationId() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getInt(KEY_NOTIFICATION_ID, 1);
    }

    public void setNotificationId(int value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putInt(KEY_NOTIFICATION_ID, value);
        editor.commit();
    }

    public int getNotificationCount() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getInt(KEY_NOTIFICATION_COUNT, 0);
    }

    public void setNotificationCountint(int value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putInt(KEY_NOTIFICATION_COUNT, value);
        editor.commit();
    }

    public String getSocketUrl() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_SOCKET_URL, ApiUrl.SOCKET_IO_URL);
    }

    public void setSocketUrl(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_SOCKET_URL, value);
        editor.commit();
    }

    public String getGPSLat() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_GPS_LAT, "");
    }

    public void setGPSLat(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_GPS_LAT, value);
        editor.commit();
    }

    public String getGPSLng() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_GPS_LNG, "");
    }

    public void setGPSLng(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_GPS_LNG, value);
        editor.commit();
    }

    public boolean isStartActivity() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_START_ACTIVITY, false);
    }

    public void setStartActivity(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_START_ACTIVITY, value);
        editor.commit();
    }

    public boolean isShowPushAgreementDialog() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_SHOW_PUSH_AGREEMENT_DIALOG, false);
    }

    public void setShowPushAgreementDialog(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_SHOW_PUSH_AGREEMENT_DIALOG, value);
        editor.commit();
    }

    public String getOpenLocationCode() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_OPEN_LOCATION_CODE, "");
    }

    public void setOpenLocationCode(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_OPEN_LOCATION_CODE, value);
        editor.commit();
    }

    public boolean getAutoBranchPopupStatus() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_AUTO_BRANCH_POPUP_STATUS, true);
    }

    public void setAutoBranchPopupStatus(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_AUTO_BRANCH_POPUP_STATUS, value);
        editor.commit();
    }

    public boolean getAutoBranchSearchStatus() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_AUTO_BRANCH_SEARCH_STATUS, true);
    }

    public void setAutoBranchSearchStatus(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_AUTO_BRANCH_SEARCH_STATUS, value);
        editor.commit();
    }

    public boolean getIsEnableAutoBranchPopupValue() {
        return false;
    }

    public boolean getMainListActionGuideStatus() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_MAIN_LIST_ACTION_GUIDE_STATUS, false);
    }

    public void setMainListActionGuideStatus(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_MAIN_LIST_ACTION_GUIDE_STATUS, value);
        editor.commit();
    }

    public boolean getCardviewActionGuideStatus() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_CARD_VIEW_ACTION_GUIDE_STATUS, false);
    }

    public void setCardviewActionGuideStatus(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_CARD_VIEW_ACTION_GUIDE_STATUS, value);
        editor.commit();
    }

    public boolean getNaverMapActionGuideStatus() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_NAVER_MAP_VIEW_ACTION_GUIDE_STATUS, false);
    }

    public void setNaverMapActionGuideStatus(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_NAVER_MAP_VIEW_ACTION_GUIDE_STATUS, value);
        editor.commit();
    }

    public boolean getKeyNonMemberPushStatus() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_NON_MEMBER_PUSH_STATUS, false);
    }

    public void setKeyNonMemberPushStatus(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_NON_MEMBER_PUSH_STATUS, value);
        editor.commit();
    }

    public boolean getPermissionConfirm() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_PERMISSION_CONFIRM, false);
    }

    public void setPermissionConfirm(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_PERMISSION_CONFIRM, value);
        editor.commit();
    }

    public void setAgreeTerms(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_AGREE_TERMS_STATUS, value);
        editor.commit();
    }

    public boolean getAgreeTerms() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_AGREE_TERMS_STATUS, false);
    }
}