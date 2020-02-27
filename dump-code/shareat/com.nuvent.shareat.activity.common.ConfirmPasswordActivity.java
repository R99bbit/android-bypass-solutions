package com.nuvent.shareat.activity.common;

import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.TextView;
import com.facebook.AccessToken;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.intro.PasswordResetApi;
import com.nuvent.shareat.api.member.PasswordValidApi;
import com.nuvent.shareat.api.member.UserInfoApi;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.MD5;

public class ConfirmPasswordActivity extends MainActionBarActivity {
    public static final int HIDE_ACTIONBAR = 3;
    public static final int TYPE_PASSWORD_CONFIRM = 1;
    public static final int TYPE_PASSWORD_RESET = 2;
    /* access modifiers changed from: private */
    public boolean isChecked;
    private boolean isConfirm;
    private String mConfirmPassword = "";
    /* access modifiers changed from: private */
    public int mCurrentType;
    /* access modifiers changed from: private */
    public Handler mHandler;
    private String mPassword = "";

    public void onClickFindPassword(View view) {
        showConfirmDialog(getResources().getString(R.string.PASSWORD_RESET_DESCRIPTION), new Runnable() {
            public void run() {
                ConfirmPasswordActivity.this.requestPasswordResetApi();
            }
        });
    }

    public void onBackPressed() {
        finish(R.anim.scale_up, R.anim.modal_exit_animation);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickTitle(View view) {
        onBackPressed();
    }

    public void onClickPassword(View view) {
        if (!findViewById(R.id.confirmButton).isEnabled()) {
            if (!this.isChecked) {
                this.mPassword += ((String) view.getTag());
            } else if (!this.isChecked || this.isConfirm) {
                this.mConfirmPassword += ((String) view.getTag());
            } else {
                this.mPassword += ((String) view.getTag());
            }
            setInputView();
        }
    }

    public void onClickRemove(View view) {
        findViewById(R.id.confirmButton).setEnabled(false);
        if (!this.isChecked) {
            this.mPassword = setRemove(this.mPassword);
        } else if (!this.isChecked || this.isConfirm) {
            this.mConfirmPassword = setRemove(this.mConfirmPassword);
        } else {
            this.mPassword = setRemove(this.mPassword);
        }
        setInputView();
    }

    public void onClickCancel(View view) {
        findViewById(R.id.confirmButton).setEnabled(false);
        if (!this.isChecked) {
            this.mPassword = "";
        } else if (!this.isChecked || this.isConfirm) {
            this.mConfirmPassword = "";
        } else {
            this.mPassword = "";
        }
        setInputView();
    }

    public void onClickConfirm(View view) {
        if (!this.isChecked) {
            findViewById(R.id.input01).setSelected(false);
            findViewById(R.id.input02).setSelected(false);
            findViewById(R.id.input03).setSelected(false);
            findViewById(R.id.input04).setSelected(false);
            findViewById(R.id.confirmButton).setEnabled(false);
            requestPasswordValidApi(this.mPassword);
            this.mPassword = "";
            return;
        }
        requestEditUserInfoApi(this.mPassword);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        int i = 0;
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_confirm_password, 2);
        this.mHandler = new Handler();
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\ube44\ubc00\ubc88\ud638");
        this.mCurrentType = getIntent().getIntExtra(KakaoTalkLinkProtocol.ACTION_TYPE, 1);
        findViewById(R.id.confirmButton).setEnabled(false);
        View findViewById = findViewById(R.id.findPasswordButton);
        if (1 != this.mCurrentType) {
            i = 8;
        }
        findViewById.setVisibility(i);
        if (2 == this.mCurrentType) {
            GAEvent.onGAScreenView(this, R.string.ga_pwd_setting_update);
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

    private void setInputView() {
        if (!this.isChecked) {
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
                        findViewById(R.id.input04).setSelected(true);
                        findViewById(R.id.confirmButton).setEnabled(true);
                        break;
                }
            }
        } else if (!this.isChecked || this.isConfirm) {
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
                                    ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setText(ConfirmPasswordActivity.this.getResources().getString(R.string.PASSWORD_CONFIRM_HINT));
                                    ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setTextColor(ConfirmPasswordActivity.this.getResources().getColor(R.color.WHITE_COLOR));
                                    ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0);
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
        } else {
            findViewById(R.id.input01).setSelected(false);
            findViewById(R.id.input02).setSelected(false);
            findViewById(R.id.input03).setSelected(false);
            findViewById(R.id.input04).setSelected(false);
            for (int i3 = 0; i3 < this.mPassword.length(); i3++) {
                switch (i3) {
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
    }

    /* access modifiers changed from: private */
    public void requestPasswordValidApi(final String password) {
        String param = String.format("?pin_pwd=%s", new Object[]{password});
        PasswordValidApi request = new PasswordValidApi(this);
        request.addGetParam(param);
        request.request(new RequestHandler() {
            public void onStart() {
                ConfirmPasswordActivity.this.showLoadingDialog(true);
            }

            public void onResult(Object result) {
                ConfirmPasswordActivity.this.showLoadingDialog(false);
                if (!((BaseResultModel) result).getResult().equals("Y")) {
                    ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setText(ConfirmPasswordActivity.this.getResources().getString(R.string.PASSWORD_CONFIRM_ALERT));
                    ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setTextColor(Color.parseColor("#FF36DFF8"));
                    ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setCompoundDrawablesWithIntrinsicBounds(R.drawable.exclamation_mark, 0, 0, 0);
                    ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setCompoundDrawablePadding(ConfirmPasswordActivity.this.getResources().getDimensionPixelOffset(R.dimen.TEXTVIEW_DRAWALBE_PADDING));
                    ConfirmPasswordActivity.this.mHandler.removeMessages(0);
                    ConfirmPasswordActivity.this.mHandler.postDelayed(new Runnable() {
                        public void run() {
                            ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setText(ConfirmPasswordActivity.this.getResources().getString(R.string.PASSWORD_HINT));
                            ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setTextColor(ConfirmPasswordActivity.this.getResources().getColor(R.color.WHITE_COLOR));
                            ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0);
                        }
                    }, 2000);
                } else if (1 == ConfirmPasswordActivity.this.mCurrentType) {
                    ConfirmPasswordActivity.this.setResult(-1, ConfirmPasswordActivity.this.getIntent());
                    ConfirmPasswordActivity.this.finish();
                } else {
                    ConfirmPasswordActivity.this.isChecked = true;
                    ((TextView) ConfirmPasswordActivity.this.findViewById(R.id.hintLabel)).setText(ConfirmPasswordActivity.this.getResources().getString(R.string.PASSWORD_NEW_HINT));
                    ConfirmPasswordActivity.this.findViewById(R.id.findPasswordButton).setVisibility(8);
                }
            }

            public void onFailure(Exception exception) {
                ConfirmPasswordActivity.this.showLoadingDialog(false);
                ConfirmPasswordActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ConfirmPasswordActivity.this.requestPasswordValidApi(password);
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestEditUserInfoApi(final String password) {
        UserInfoApi request = new UserInfoApi(this, 2);
        try {
            request.addParam("pin_pwd", MD5.makeMD5(password));
        } catch (Exception e) {
            e.printStackTrace();
            request.addParam("pin_pwd", password);
        }
        request.request(new RequestHandler() {
            public void onStart() {
                ConfirmPasswordActivity.this.showLoadingDialog(true);
            }

            public void onResult(Object result) {
                ConfirmPasswordActivity.this.showLoadingDialog(false);
                BaseResultModel model = (BaseResultModel) result;
                if (model.getResult() == null || !model.getResult().equals("Y")) {
                    ConfirmPasswordActivity.this.showDialog(ConfirmPasswordActivity.this.getResources().getString(R.string.ERROR_MSG_FAIL_CHANGE_PASSWORD));
                } else {
                    ConfirmPasswordActivity.this.finish();
                }
            }

            public void onFailure(Exception exception) {
                ConfirmPasswordActivity.this.showLoadingDialog(false);
                ConfirmPasswordActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ConfirmPasswordActivity.this.requestEditUserInfoApi(password);
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
                ConfirmPasswordActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                ConfirmPasswordActivity.this.showCircleDialog(false);
                BaseResultModel model = (BaseResultModel) result;
                if (model.getResult() == null || !model.getResult().equals("Y")) {
                    ConfirmPasswordActivity.this.showDialog(ConfirmPasswordActivity.this.getResources().getString(R.string.PASSWORD_RESET_FAILED));
                    return;
                }
                ConfirmPasswordActivity.this.showDialog(ConfirmPasswordActivity.this.getResources().getString(R.string.PASSWORD_RESET_COMPLETE, new Object[]{SessionManager.getInstance().getUserModel().getEmail()}));
            }

            public void onFailure(Exception exception) {
                ConfirmPasswordActivity.this.showCircleDialog(false);
                ConfirmPasswordActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ConfirmPasswordActivity.this.requestPasswordResetApi();
                    }
                });
            }
        });
    }
}