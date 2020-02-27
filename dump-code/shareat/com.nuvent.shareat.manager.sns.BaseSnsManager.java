package com.nuvent.shareat.manager.sns;

import com.nuvent.shareat.model.SnsModel;

public class BaseSnsManager {
    public static final String SNS_LOGIN_TYPE_FACEBOOK = "01";
    public static final String SNS_LOGIN_TYPE_GOOGLE = "04";
    public static final String SNS_LOGIN_TYPE_KAKAO = "02";
    public static final String SNS_LOGIN_TYPE_NAVER = "03";
    protected LoginInterface mListener;

    public interface LoginInterface {
        void onCompleted(SnsModel snsModel, String str);

        void onError(Exception exc, String str);

        void onErrorNaverReAgree(Runnable runnable, Runnable runnable2);
    }

    public void setOnLoginListener(LoginInterface listener) {
        this.mListener = listener;
    }
}