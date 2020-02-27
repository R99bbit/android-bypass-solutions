package com.nuvent.shareat.activity.menu;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import com.facebook.AccessToken;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.common.ConfirmPasswordActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.intro.PasswordResetApi;
import com.nuvent.shareat.api.member.UserInfoApi;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.util.GAEvent;

public class PasswordSettingActivity extends MainActionBarActivity {
    public void onClickCheck(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_pwd_setting, (int) R.string.ga_ev_click, (int) R.string.ga_pwd_setting_lock);
        view.setSelected(!view.isSelected());
        requestEditUserInfoApi(view.isSelected());
    }

    public void onClickPasswordChange(View view) {
        pushActivity(new Intent(this, ConfirmPasswordActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, 2));
    }

    public void onClickPasswordReset(View view) {
        showConfirmDialog(getString(R.string.PASSWORD_RESET_CONFIRM), "\ud655\uc778", "\ucde8\uc18c", new Runnable() {
            public void run() {
                PasswordSettingActivity.this.requestPasswordResetApi();
            }
        }, null);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_setting, 2);
        GAEvent.onGAScreenView(this, R.string.ga_pwd_setting);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\ube44\ubc00\ubc88\ud638");
        boolean enablePassword = false;
        if (SessionManager.getInstance().getUserModel() != null) {
            enablePassword = SessionManager.getInstance().getUserModel().isEnablePassword();
        }
        findViewById(R.id.screenLockCheck).setSelected(enablePassword);
    }

    /* access modifiers changed from: private */
    public void requestEditUserInfoApi(final boolean isOn) {
        UserInfoApi request = new UserInfoApi(this, 2);
        request.addParam("login_pwd_yn", isOn ? "Y" : "N");
        request.request(new RequestHandler() {
            public void onStart() {
                PasswordSettingActivity.this.showLoadingDialog(true);
            }

            public void onResult(Object result) {
                PasswordSettingActivity.this.showLoadingDialog(false);
                BaseResultModel baseResultModel = (BaseResultModel) result;
            }

            public void onFailure(Exception exception) {
                PasswordSettingActivity.this.showLoadingDialog(false);
                PasswordSettingActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        PasswordSettingActivity.this.requestEditUserInfoApi(isOn);
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestPasswordResetApi() {
        PasswordResetApi request = new PasswordResetApi(this);
        request.addParam("name", "name");
        request.addParam(AccessToken.USER_ID_KEY, SessionManager.getInstance().getUserModel().getEmail());
        request.request(new RequestHandler() {
            public void onStart() {
                PasswordSettingActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                PasswordSettingActivity.this.showCircleDialog(false);
                BaseResultModel model = (BaseResultModel) result;
                if (model.getResult() == null || !model.getResult().equals("Y")) {
                    PasswordSettingActivity.this.showDialog(PasswordSettingActivity.this.getResources().getString(R.string.PASSWORD_RESET_FAILED));
                    return;
                }
                PasswordSettingActivity.this.showDialog(PasswordSettingActivity.this.getResources().getString(R.string.PASSWORD_RESET_COMPLETE, new Object[]{SessionManager.getInstance().getUserModel().getEmail()}));
            }

            public void onFailure(Exception exception) {
                PasswordSettingActivity.this.showCircleDialog(false);
                PasswordSettingActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        PasswordSettingActivity.this.requestPasswordResetApi();
                    }
                });
            }
        });
    }
}