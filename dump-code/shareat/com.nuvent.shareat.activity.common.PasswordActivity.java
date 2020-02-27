package com.nuvent.shareat.activity.common;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.TextView;
import com.facebook.AccessToken;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.intro.PasswordResetApi;
import com.nuvent.shareat.api.intro.SigninApi;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.SignedModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.MD5;

public class PasswordActivity extends MainActionBarActivity {
    public static final int REQUEST_TYPE_CERTIFICATION_PASSWORD = 2;
    public static final int REQUEST_TYPE_REGIST_PASSWORD = 1;
    /* access modifiers changed from: private */
    public int defaultHintResouceId;
    private boolean isConfirm;
    private String mConfirmPassword = "";
    /* access modifiers changed from: private */
    public Handler mHandler;
    /* access modifiers changed from: private */
    public String mPassword = "";
    private int mRequestType;

    public void onBackPressed() {
        finish(R.anim.scale_up, R.anim.modal_exit_animation);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickTitle(View view) {
        onBackPressed();
    }

    public void onClickFindPassword(View view) {
        showConfirmDialog(getResources().getString(R.string.PASSWORD_RESET_DESCRIPTION), new Runnable() {
            public void run() {
                PasswordActivity.this.requestPasswordResetApi(PasswordActivity.this.getIntent().getStringExtra("email"));
            }
        });
    }

    public void onClickConfirm(View view) {
        if (1 == this.mRequestType) {
            GAEvent.onGaEvent((Activity) this, (int) R.string.ga_join_password, (int) R.string.ga_ev_reg, (int) R.string.ga_join_password);
            Intent result = getIntent();
            result.putExtra("password", this.mPassword);
            setResult(-1, result);
            onBackPressed();
            return;
        }
        requestSigninApi(this.mPassword);
    }

    public void onClickPassword(View view) {
        if (!findViewById(R.id.confirmButton).isEnabled()) {
            if (!this.isConfirm) {
                this.mPassword += ((String) view.getTag());
            } else {
                this.mConfirmPassword += ((String) view.getTag());
            }
            setInputView();
        }
    }

    public void onClickRemove(View view) {
        findViewById(R.id.confirmButton).setEnabled(false);
        if (!this.isConfirm) {
            this.mPassword = setRemove(this.mPassword);
        } else {
            this.mConfirmPassword = setRemove(this.mConfirmPassword);
        }
        setInputView();
    }

    public void onClickCancel(View view) {
        findViewById(R.id.confirmButton).setEnabled(false);
        if (!this.isConfirm) {
            this.mPassword = "";
        } else {
            this.mConfirmPassword = "";
        }
        setInputView();
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        int i = 0;
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password, 2);
        showFavoriteButton(false);
        setTitle("\ube44\ubc00\ubc88\ud638 \uc124\uc815");
        findViewById(R.id.confirmButton).setEnabled(false);
        this.mHandler = new Handler();
        this.mRequestType = getIntent().getIntExtra("requestType", 2);
        View findViewById = findViewById(R.id.findPasswordButton);
        if (2 != this.mRequestType) {
            i = 8;
        }
        findViewById.setVisibility(i);
        if (2 == this.mRequestType) {
            this.defaultHintResouceId = R.string.PASSWORD_HINT;
            GAEvent.onGAScreenView(this, R.string.ga_login_password);
            setTitle("\ube44\ubc00\ubc88\ud638 \uc785\ub825");
        } else {
            this.defaultHintResouceId = R.string.PASSWORD_JOIN_HINT;
            GAEvent.onGAScreenView(this, R.string.ga_join_password);
            setTitle("\ube44\ubc00\ubc88\ud638 \uc124\uc815");
        }
        ((TextView) findViewById(R.id.hintLabel)).setText(getResources().getString(this.defaultHintResouceId));
    }

    private void setInputView() {
        if (!this.isConfirm) {
            findViewById(R.id.input01).setSelected(false);
            findViewById(R.id.input02).setSelected(false);
            findViewById(R.id.input03).setSelected(false);
            findViewById(R.id.input04).setSelected(false);
            for (int i = 0; i < this.mPassword.length(); i++) {
                switch (i) {
                    case 0:
                        findViewById(R.id.input01).setSelected(true);
                        break;
                    case 1:
                        findViewById(R.id.input02).setSelected(true);
                        break;
                    case 2:
                        findViewById(R.id.input03).setSelected(true);
                        break;
                    case 3:
                        if (1 != this.mRequestType) {
                            findViewById(R.id.input04).setSelected(true);
                            findViewById(R.id.confirmButton).setEnabled(true);
                            break;
                        } else {
                            findViewById(R.id.input01).setSelected(false);
                            findViewById(R.id.input02).setSelected(false);
                            findViewById(R.id.input03).setSelected(false);
                            findViewById(R.id.input04).setSelected(false);
                            this.mConfirmPassword = "";
                            ((TextView) findViewById(R.id.hintLabel)).setText(getResources().getString(R.string.PASSWORD_CONFIRM_HINT));
                            this.isConfirm = true;
                            break;
                        }
                }
            }
            return;
        }
        findViewById(R.id.input01).setSelected(false);
        findViewById(R.id.input02).setSelected(false);
        findViewById(R.id.input03).setSelected(false);
        findViewById(R.id.input04).setSelected(false);
        for (int i2 = 0; i2 < this.mConfirmPassword.length(); i2++) {
            switch (i2) {
                case 0:
                    findViewById(R.id.input01).setSelected(true);
                    break;
                case 1:
                    findViewById(R.id.input02).setSelected(true);
                    break;
                case 2:
                    findViewById(R.id.input03).setSelected(true);
                    break;
                case 3:
                    if (!this.mPassword.equals(this.mConfirmPassword)) {
                        findViewById(R.id.input01).setSelected(false);
                        findViewById(R.id.input02).setSelected(false);
                        findViewById(R.id.input03).setSelected(false);
                        findViewById(R.id.input04).setSelected(false);
                        this.mConfirmPassword = "";
                        ((TextView) findViewById(R.id.hintLabel)).setText(getResources().getString(R.string.PASSWORD_CONFIRM_ALERT));
                        ((TextView) findViewById(R.id.hintLabel)).setTextColor(Color.parseColor("#FF36DFF8"));
                        ((TextView) findViewById(R.id.hintLabel)).setCompoundDrawablesWithIntrinsicBounds(R.drawable.exclamation_mark, 0, 0, 0);
                        ((TextView) findViewById(R.id.hintLabel)).setCompoundDrawablePadding(getResources().getDimensionPixelOffset(R.dimen.TEXTVIEW_DRAWALBE_PADDING));
                        this.mHandler.removeMessages(0);
                        this.mHandler.postDelayed(new Runnable() {
                            public void run() {
                                ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setText(PasswordActivity.this.getResources().getString(R.string.PASSWORD_CONFIRM_HINT));
                                ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setTextColor(PasswordActivity.this.getResources().getColor(R.color.WHITE_COLOR));
                                ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0);
                            }
                        }, 2000);
                        break;
                    } else {
                        findViewById(R.id.input04).setSelected(true);
                        findViewById(R.id.confirmButton).setEnabled(true);
                        break;
                    }
            }
        }
    }

    private String setRemove(String value) {
        String reValue = "";
        if (value.isEmpty() || 1 == value.length()) {
            return reValue;
        }
        char[] charValue = value.toCharArray();
        for (int i = 0; i < charValue.length - 1; i++) {
            reValue = reValue + charValue[i];
        }
        return reValue;
    }

    /* access modifiers changed from: private */
    public void requestSigninApi(final String userPassword) {
        SigninApi request = new SigninApi(this);
        request.addParam(AccessToken.USER_ID_KEY, getIntent().getStringExtra("email"));
        try {
            request.addParam("user_pwd", MD5.makeMD5(userPassword));
        } catch (Exception e) {
            request.addParam("user_pwd", userPassword);
        }
        if (ShareatApp.getInstance().getPhonenumber().equals("01000000000")) {
            showDialog(getResources().getString(R.string.SIGNUP_ERROR_4), new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    PasswordActivity.this.finish();
                }
            });
            return;
        }
        request.addParam("user_phone", ShareatApp.getInstance().getPhonenumber());
        request.addParam("guid", ShareatApp.getInstance().getGUID());
        request.addParam("phone_os", "A");
        request.request(new RequestHandler() {
            public void onStart() {
                PasswordActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                PasswordActivity.this.showCircleDialog(false);
                SignedModel model = (SignedModel) result;
                if (model == null || model.getResult() == null) {
                    GAEvent.onGaEvent(PasswordActivity.this.getResources().getString(R.string.error), PasswordActivity.this.getResources().getString(R.string.ga_ev_login), PasswordActivity.this.getResources().getString(R.string.ga_auth_server_error));
                    PasswordActivity.this.showDialog(PasswordActivity.this.getResources().getString(R.string.LOGIN_ALERT_02));
                } else if (!model.getResult().equals("Y")) {
                    GAEvent.onGaEvent(PasswordActivity.this.getResources().getString(R.string.error), PasswordActivity.this.getResources().getString(R.string.ga_ev_login), PasswordActivity.this.getResources().getString(R.string.ga_auth_server_error) + " " + model.getResult());
                    PasswordActivity.this.findViewById(R.id.confirmButton).setEnabled(false);
                    PasswordActivity.this.findViewById(R.id.input01).setSelected(false);
                    PasswordActivity.this.findViewById(R.id.input02).setSelected(false);
                    PasswordActivity.this.findViewById(R.id.input03).setSelected(false);
                    PasswordActivity.this.findViewById(R.id.input04).setSelected(false);
                    PasswordActivity.this.mPassword = "";
                    ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setText(PasswordActivity.this.getResources().getString(R.string.PASSWORD_CONFIRM_ALERT));
                    ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setTextColor(Color.parseColor("#FF36DFF8"));
                    ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setCompoundDrawablesWithIntrinsicBounds(R.drawable.exclamation_mark, 0, 0, 0);
                    ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setCompoundDrawablePadding(PasswordActivity.this.getResources().getDimensionPixelOffset(R.dimen.TEXTVIEW_DRAWALBE_PADDING));
                    PasswordActivity.this.mHandler.removeMessages(0);
                    PasswordActivity.this.mHandler.postDelayed(new Runnable() {
                        public void run() {
                            ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setText(PasswordActivity.this.getResources().getString(PasswordActivity.this.defaultHintResouceId));
                            ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setTextColor(PasswordActivity.this.getResources().getColor(R.color.WHITE_COLOR));
                            ((TextView) PasswordActivity.this.findViewById(R.id.hintLabel)).setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0);
                        }
                    }, 2000);
                } else if (model.getAuth_token() == null || model.getAuth_token().isEmpty()) {
                    PasswordActivity.this.showDialog(PasswordActivity.this.getResources().getString(R.string.LOGIN_ALERT_02));
                } else {
                    SessionManager.getInstance().setAuthToken(model.getAuth_token());
                    PasswordActivity.this.setResult(-1);
                    PasswordActivity.this.onBackPressed();
                }
            }

            public void onFailure(Exception exception) {
                PasswordActivity.this.showCircleDialog(false);
                PasswordActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        PasswordActivity.this.requestSigninApi(userPassword);
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestPasswordResetApi(final String email) {
        PasswordResetApi request = new PasswordResetApi(this);
        request.addParam("name", "name");
        request.addParam(AccessToken.USER_ID_KEY, email);
        request.request(new RequestHandler() {
            public void onStart() {
                PasswordActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                PasswordActivity.this.showCircleDialog(false);
                BaseResultModel model = (BaseResultModel) result;
                if (model.getResult() == null || !model.getResult().equals("Y")) {
                    PasswordActivity.this.showDialog(PasswordActivity.this.getResources().getString(R.string.PASSWORD_RESET_FAILED));
                    return;
                }
                PasswordActivity.this.showDialog(PasswordActivity.this.getResources().getString(R.string.PASSWORD_RESET_COMPLETE, new Object[]{email}));
            }

            public void onFailure(Exception exception) {
                PasswordActivity.this.showCircleDialog(false);
                PasswordActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        PasswordActivity.this.requestPasswordResetApi(email);
                    }
                });
            }
        });
    }
}