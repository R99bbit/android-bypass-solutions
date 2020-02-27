package com.nuvent.shareat.manager.sns;

import android.app.Activity;
import com.kakao.auth.APIErrorResult;
import com.kakao.auth.Session;
import com.kakao.auth.SessionCallback;
import com.kakao.usermgmt.LoginButton;
import com.kakao.usermgmt.MeResponseCallback;
import com.kakao.usermgmt.UserManagement;
import com.kakao.usermgmt.UserProfile;
import com.kakao.util.exception.KakaoException;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.model.SnsModel;

public class KakaoLoginManager extends BaseSnsManager {
    /* access modifiers changed from: private */
    public Activity mActivity;
    private SessionCallback mKakaoSessionCallback = new SessionCallback() {
        public void onSessionOpened() {
            ((BaseActivity) KakaoLoginManager.this.mActivity).showLoadingDialog(false);
            KakaoLoginManager.this.requestKakaoUserApi();
        }

        public void onSessionClosed(KakaoException exception) {
            ((BaseActivity) KakaoLoginManager.this.mActivity).showLoadingDialog(false);
        }

        public void onSessionOpening() {
            ((BaseActivity) KakaoLoginManager.this.mActivity).showLoadingDialog(true);
        }
    };
    private LoginButton mLoginButton;

    public KakaoLoginManager(Activity activity, LoginButton loginButton) {
        this.mActivity = activity;
        this.mLoginButton = loginButton;
        Session.initialize(activity);
    }

    public void requestKakaoLoginApi() {
        Session session = Session.getCurrentSession();
        if (session == null || !session.isOpened()) {
            session.addCallback(this.mKakaoSessionCallback);
            this.mLoginButton.performClick();
            return;
        }
        requestKakaoUserApi();
    }

    /* access modifiers changed from: private */
    public void requestKakaoUserApi() {
        UserManagement.requestMe(new MeResponseCallback() {
            public void onSuccess(UserProfile userProfile) {
                String avatarImage = userProfile.getProfileImagePath();
                String snsId = userProfile.getId() + "";
                String userName = userProfile.getNickname();
                String oAuthToken = Session.getCurrentSession().getAccessToken();
                SnsModel model = new SnsModel();
                model.setUserEmail("");
                model.setAccessToken(oAuthToken);
                model.setUserName(userName);
                model.setSNSID(snsId);
                model.setAvatarImageUrl(avatarImage);
                KakaoLoginManager.this.mListener.onCompleted(model, BaseSnsManager.SNS_LOGIN_TYPE_KAKAO);
            }

            public void onNotSignedUp() {
            }

            public void onSessionClosedFailure(APIErrorResult apiErrorResult) {
            }

            public void onFailure(APIErrorResult apiErrorResult) {
                KakaoLoginManager.this.mListener.onError(new Exception(KakaoLoginManager.this.mActivity.getResources().getString(R.string.NAVER_LOGIN_ALERT_01)), BaseSnsManager.SNS_LOGIN_TYPE_KAKAO);
            }
        });
    }
}