package com.nuvent.shareat.manager.app;

import android.content.SharedPreferences.Editor;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.model.user.CardResultModel;
import com.nuvent.shareat.model.user.UserModel;
import com.nuvent.shareat.model.user.UserResultModel;

public class SessionManager {
    private static final String KEY_AD_ID = "KEY_AD_ID";
    private static final String KEY_AUTH_TOKEN = "KEY_AUTH_TOKEN";
    private static final String KEY_CARD_LIST_JSON = "KEY_CARD_LIST_JSON";
    private static final String KEY_IS_JOIN = "KEY_IS_JOIN";
    private static final String KEY_IS_LOGIN = "KEY_IS_LOGIN";
    private static final String KEY_PUSH_TOKEN = "KEY_PUSH_TOKEN";
    private static final String KEY_SESSION_COOKIE = "KEY_SESSION_COOKIE";
    private static final String KEY_USER_INFO_JSON = "KEY_USER_INFO_JSON";
    public static SessionManager mInstance = new SessionManager();
    private static CardResultModel sCardResultModel;
    private static UserModel sUserModel;

    public static synchronized SessionManager getInstance() {
        SessionManager sessionManager;
        synchronized (SessionManager.class) {
            try {
                sessionManager = mInstance;
            }
        }
        return sessionManager;
    }

    public void clearSession() {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.remove(KEY_AUTH_TOKEN);
        editor.remove(KEY_SESSION_COOKIE);
        editor.remove(KEY_IS_LOGIN);
        editor.remove(KEY_PUSH_TOKEN);
        editor.remove(KEY_USER_INFO_JSON);
        editor.remove(KEY_CARD_LIST_JSON);
        editor.commit();
    }

    public boolean hasSession() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_IS_LOGIN, true);
    }

    public void setHasSession(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_IS_LOGIN, value);
        editor.commit();
    }

    public boolean isJoinUser() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getBoolean(KEY_IS_JOIN, false);
    }

    public void setJoinUser(boolean value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putBoolean(KEY_IS_JOIN, value);
        editor.commit();
    }

    public String getAuthToken() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_AUTH_TOKEN, "");
    }

    public void setAuthToken(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_AUTH_TOKEN, value);
        editor.commit();
    }

    public String getPushToken() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_PUSH_TOKEN, "");
    }

    public void setPushToken(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_PUSH_TOKEN, value);
        editor.commit();
    }

    public String getAdID() {
        return "";
    }

    public void setAdID(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_AD_ID, value);
        editor.commit();
    }

    public String getSessionCookie() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_SESSION_COOKIE, "");
    }

    public void setSessionCookie(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_SESSION_COOKIE, value);
        editor.commit();
    }

    public UserModel getUserModel() {
        if (sUserModel == null) {
            if (getUserJsonString() == null || getUserJsonString().isEmpty()) {
                return null;
            }
            sUserModel = ((UserResultModel) new Gson().fromJson((JsonElement) new JsonParser().parse(getUserJsonString()).getAsJsonObject(), UserResultModel.class)).getUserInfo();
        }
        return sUserModel;
    }

    public void setUserModel(UserModel model) {
        sUserModel = model;
    }

    public String getUserJsonString() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_USER_INFO_JSON, "");
    }

    public void setUserJsonString(String jsonString) {
        sUserModel = ((UserResultModel) new Gson().fromJson((JsonElement) new JsonParser().parse(jsonString).getAsJsonObject(), UserResultModel.class)).getUserInfo();
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_USER_INFO_JSON, jsonString);
        editor.commit();
    }

    public CardResultModel getCardResultModel() {
        if (sCardResultModel == null) {
            if (getUserJsonString() == null || getUserJsonString().isEmpty()) {
                return null;
            }
            sCardResultModel = (CardResultModel) new Gson().fromJson((JsonElement) new JsonParser().parse(getUserJsonString()).getAsJsonObject(), CardResultModel.class);
        }
        return sCardResultModel;
    }

    public void setCardResultModel(CardResultModel model) {
        sCardResultModel = model;
    }

    public String getCardListJsonString() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_CARD_LIST_JSON, "");
    }

    public void setCardListJsonString(String jsonString) {
        sCardResultModel = (CardResultModel) new Gson().fromJson((JsonElement) new JsonParser().parse(jsonString).getAsJsonObject(), CardResultModel.class);
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_CARD_LIST_JSON, jsonString);
        editor.commit();
    }
}