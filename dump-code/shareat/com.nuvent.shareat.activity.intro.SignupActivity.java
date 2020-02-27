package com.nuvent.shareat.activity.intro;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Rect;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;
import com.crashlytics.android.answers.Answers;
import com.crashlytics.android.answers.LoginEvent;
import com.crashlytics.android.answers.SignUpEvent;
import com.facebook.AccessToken;
import com.facebook.CallbackManager;
import com.facebook.CallbackManager.Factory;
import com.facebook.FacebookSdk;
import com.igaworks.adbrix.IgawAdbrix;
import com.kakao.auth.Session;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.kakao.usermgmt.LoginButton;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.common.PasswordActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.intro.IDCheckApi;
import com.nuvent.shareat.api.intro.SignupApi;
import com.nuvent.shareat.dialog.TermsDialog;
import com.nuvent.shareat.event.LoginSuccessEvent;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.manager.sns.BaseSnsManager;
import com.nuvent.shareat.manager.sns.BaseSnsManager.LoginInterface;
import com.nuvent.shareat.manager.sns.FacebookLoginManager;
import com.nuvent.shareat.manager.sns.KakaoLoginManager;
import com.nuvent.shareat.manager.sns.NaverLoginManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.SignedModel;
import com.nuvent.shareat.model.SnsModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.MD5;
import de.greenrobot.event.EventBus;
import net.xenix.util.ValidUtil;

public class SignupActivity extends MainActionBarActivity implements OnClickListener {
    private static final int REQUEST_CODE_EMAIL = 19;
    private static final int REQUEST_CODE_PASSWORD = 18;
    private static final int REQUEST_CODE_SIGNUP_ACCOUNT = 17;
    private CallbackManager mCallbackManager;
    /* access modifiers changed from: private */
    public LoginInterface mOnSnsLoginListener = new LoginInterface() {
        public void onCompleted(SnsModel model, String type) {
            if (model.getUserEmail() == null || model.getUserEmail().isEmpty()) {
                Intent intent = new Intent(SignupActivity.this, SnsEmailActivity.class);
                intent.putExtra("model", model);
                intent.putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, type);
                SignupActivity.this.animActivityForResult(intent, 19, R.anim.fade_in_activity, R.anim.fade_out_activity);
                return;
            }
            SignupActivity.this.requestSNSCheckApi(model.getUserEmail(), model.getSNSID(), type, model);
        }

        public void onError(Exception e, String type) {
            SignupActivity signupActivity = SignupActivity.this;
            int i = type.equals(BaseSnsManager.SNS_LOGIN_TYPE_FACEBOOK) ? R.string.ga_auth_facebook_error : type.equals(BaseSnsManager.SNS_LOGIN_TYPE_KAKAO) ? R.string.ga_auth_kakao_error : R.string.ga_auth_naver_error;
            GAEvent.onGaEvent((Activity) signupActivity, (int) R.string.error, (int) R.string.ga_ev_join, i);
            SignupActivity.this.showDialog(e.getMessage());
        }

        public void onErrorNaverReAgree(Runnable doneRun, Runnable cancelRun) {
            SignupActivity.this.showConfirmDialog((String) "\ub124\uc774\ubc84ID\ub97c \ud1b5\ud558\uc5ec \uac04\ud3b8\ud68c\uc6d0 \uac00\uc785\uc744 \ud558\uc2dc\ub824\uba74, \ud504\ub85c\ud544 \ud56d\ubaa9 \uc81c\uacf5\uc5d0 \ub300\ud55c \ub3d9\uc758\uac00 \ud544\uc694\ud569\ub2c8\ub2e4.\n \ub124\uc774\ubc84 ID \ud504\ub85c\ud544 \uc81c\uacf5 \ub3d9\uc758\ub97c \uc9c4\ud589\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?", (Runnable) new Runnable() {
                public void run() {
                    NaverLoginManager manager = new NaverLoginManager(SignupActivity.this);
                    manager.setOnLoginListener(SignupActivity.this.mOnSnsLoginListener);
                    manager.requestNaverSession();
                }
            }, cancelRun);
        }
    };

    public void onBackPressed() {
        finish(false);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickTitle(View view) {
        onBackPressed();
    }

    private void setListenerToRootView() {
        findViewById(R.id.rootLayout).getViewTreeObserver().addOnGlobalLayoutListener(new OnGlobalLayoutListener() {
            public void onGlobalLayout() {
                Rect rect = new Rect();
                SignupActivity.this.findViewById(R.id.rootLayout).getWindowVisibleDisplayFrame(rect);
                if (SignupActivity.this.findViewById(R.id.rootLayout).getRootView().getHeight() - rect.bottom > 300) {
                    SignupActivity.this.findViewById(R.id.lineView).setVisibility(8);
                    SignupActivity.this.findViewById(R.id.snsButtonLayout).setVisibility(8);
                    SignupActivity.this.findViewById(R.id.loginLayoutButton).setVisibility(8);
                    return;
                }
                SignupActivity.this.findViewById(R.id.lineView).setVisibility(0);
                SignupActivity.this.findViewById(R.id.snsButtonLayout).setVisibility(0);
                SignupActivity.this.findViewById(R.id.loginLayoutButton).setVisibility(0);
                if (TextUtils.isEmpty(((EditText) SignupActivity.this.findViewById(R.id.emailField)).getText())) {
                    SignupActivity.this.findViewById(R.id.emailField).setSelected(false);
                    ((TextView) SignupActivity.this.findViewById(R.id.emailLabel)).setTextColor(Color.parseColor("#7cffffff"));
                }
            }
        });
    }

    public void onEventMainThread(LoginSuccessEvent event) {
        finish(false);
    }

    public void onClickTerms(View view) {
        new TermsDialog(this, ApiUrl.TERMS_SERVICE).show();
    }

    public void onClickSignup(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_join, (int) R.string.ga_ev_join, (int) R.string.ga_join_email);
        hideKeyboard(findViewById(R.id.emailField));
        checkEmail();
    }

    public void onClickLogin(View view) {
        Intent intent = new Intent(this, SigninActivity.class);
        intent.addFlags(872415232);
        animActivity(intent, R.anim.fade_in_activity, R.anim.fade_out_activity);
    }

    public void onClickKakao(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_join, (int) R.string.ga_ev_join, (int) R.string.ga_join_kakao);
        KakaoLoginManager manager = new KakaoLoginManager(this, (LoginButton) findViewById(R.id.com_kakao_login));
        manager.setOnLoginListener(this.mOnSnsLoginListener);
        manager.requestKakaoLoginApi();
    }

    public void onClickNaver(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_join, (int) R.string.ga_ev_join, (int) R.string.ga_join_naver);
        NaverLoginManager manager = new NaverLoginManager(this);
        manager.setOnLoginListener(this.mOnSnsLoginListener);
        manager.requestNaverSession();
    }

    public void onClickFacebook(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_join, (int) R.string.ga_ev_join, (int) R.string.ga_join_facebook);
        FacebookLoginManager manager = new FacebookLoginManager(this, this.mCallbackManager);
        manager.setOnLoginListener(this.mOnSnsLoginListener);
        manager.requestFacebookGraphApi();
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (-1 == resultCode) {
            switch (requestCode) {
                case 1:
                case 2:
                    try {
                        if (Session.getCurrentSession().handleActivityResult(requestCode, resultCode, data)) {
                        }
                        return;
                    } catch (IllegalStateException e) {
                        e.printStackTrace();
                        return;
                    }
                case 17:
                    SessionManager.getInstance().setHasSession(true);
                    showDialog(getResources().getString(R.string.JOIN_COMPLETE), new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            Answers.getInstance().logLogin(new LoginEvent());
                            IgawAdbrix.retention("login");
                            SignupActivity.this.onStartMainActivity();
                        }
                    });
                    return;
                case 18:
                    if (data.hasExtra("password")) {
                        requestSignupApi((SnsModel) data.getSerializableExtra("model"), data.getStringExtra(KakaoTalkLinkProtocol.ACTION_TYPE), data.getStringExtra("password"));
                        return;
                    }
                    return;
                case 19:
                    SnsModel model = (SnsModel) data.getSerializableExtra("model");
                    requestSNSCheckApi(model.getUserEmail(), model.getSNSID(), data.getStringExtra(KakaoTalkLinkProtocol.ACTION_TYPE), model);
                    return;
            }
        } else if (19 == requestCode) {
            showDialog(getResources().getString(R.string.EMAIL_SIGNUP_ALERT));
            return;
        }
        this.mCallbackManager.onActivityResult(requestCode, resultCode, data);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_signup, 2);
        showFavoriteButton(false);
        setTitle("\ud68c\uc6d0\uac00\uc785");
        GAEvent.onGAScreenView(this, R.string.ga_join);
        FacebookSdk.sdkInitialize(getApplicationContext());
        this.mCallbackManager = Factory.create();
        findViewById(R.id.emailField).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                view.setSelected(true);
                ((TextView) SignupActivity.this.findViewById(R.id.emailLabel)).setTextColor(-1);
            }
        });
        ((EditText) findViewById(R.id.emailField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                SignupActivity.this.findViewById(R.id.signupButton).setEnabled(ValidUtil.isValidEmail(s.toString()));
            }
        });
        ((EditText) findViewById(R.id.emailField)).setOnEditorActionListener(new OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                switch (actionId) {
                    case 6:
                        SignupActivity.this.hideKeyboard(v);
                        return true;
                    default:
                        return false;
                }
            }
        });
        setListenerToRootView();
        findViewById(R.id.terms_next).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (!SignupActivity.this.isAllAgree()) {
                    String msg = "";
                    if (!SignupActivity.this.findViewById(R.id.termsAgreedButton06).isSelected()) {
                        msg = "\uc11c\ube44\uc2a4 \uc774\uc6a9\uc57d\uad00";
                    } else if (!SignupActivity.this.findViewById(R.id.termsAgreedButton07).isSelected()) {
                        msg = "\uac1c\uc778\uc815\ubcf4 \ucde8\uae09\ubc29\uce68";
                    } else if (!SignupActivity.this.findViewById(R.id.termsAgreedButton08).isSelected()) {
                        msg = "\uc704\uce58\uae30\ubc18 \uc11c\ube44\uc2a4 \uc774\uc6a9\uc57d\uad00";
                    }
                    SignupActivity.this.showDialog("[" + msg + " \uc57d\uad00] \uc5d0 \ub300\ud55c \ub3d9\uc758\uac00 \ub418\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4.\n\ud68c\uc6d0\uac00\uc785\uc744 \uc704\ud55c \ud544\uc218 \uc815\ubcf4\ub85c \uad00\ub828 \ub3d9\uc758 \ub0b4\uc6a9\uc744 \ud655\uc778 \ud558\uc2e0 \ud6c4 \ub3d9\uc758 \uc5ec\ubd80\ub97c \uccb4\ud06c\ud574 \uc8fc\uc138\uc694!");
                    return;
                }
                SignupActivity.this.findViewById(R.id.terms_layout).setVisibility(8);
                SignupActivity.this.findViewById(R.id.join_layout).setVisibility(0);
                AppSettingManager.getInstance().setAgreeTerms(true);
            }
        });
        findViewById(R.id.termsAgreedButton06).setOnClickListener(this);
        findViewById(R.id.termsAgreedButton07).setOnClickListener(this);
        findViewById(R.id.termsAgreedButton08).setOnClickListener(this);
        findViewById(R.id.termsAgreeAll).setOnClickListener(this);
        findViewById(R.id.termsButton06).setOnClickListener(this);
        findViewById(R.id.termsButton07).setOnClickListener(this);
        findViewById(R.id.termsButton08).setOnClickListener(this);
        if (true == AppSettingManager.getInstance().getAgreeTerms()) {
            findViewById(R.id.terms_layout).setVisibility(8);
            findViewById(R.id.join_layout).setVisibility(0);
        }
    }

    public void onClick(View v) {
        boolean z = true;
        switch (v.getId()) {
            case R.id.termsAgreeAll /*2131297382*/:
                if (v.isSelected()) {
                    z = false;
                }
                v.setSelected(z);
                findViewById(R.id.termsAgreedButton06).setSelected(v.isSelected());
                findViewById(R.id.termsAgreedButton07).setSelected(v.isSelected());
                findViewById(R.id.termsAgreedButton08).setSelected(v.isSelected());
                findViewById(R.id.terms_next).setSelected(isAllAgree());
                return;
            case R.id.termsAgreedButton06 /*2131297388*/:
            case R.id.termsAgreedButton07 /*2131297389*/:
            case R.id.termsAgreedButton08 /*2131297390*/:
                if (v.isSelected()) {
                    z = false;
                }
                v.setSelected(z);
                findViewById(R.id.terms_next).setSelected(isAllAgree());
                return;
            case R.id.termsButton06 /*2131297398*/:
                new TermsDialog(this, ApiUrl.TERMS_SERVICE).show();
                return;
            case R.id.termsButton07 /*2131297399*/:
                new TermsDialog(this, ApiUrl.TERMS_USER_INFO_TERMS).show();
                return;
            case R.id.termsButton08 /*2131297400*/:
                new TermsDialog(this, ApiUrl.TERMS_LOCATION_SERVICE).show();
                return;
            default:
                return;
        }
    }

    /* access modifiers changed from: private */
    public boolean isAllAgree() {
        if (true == findViewById(R.id.termsAgreedButton06).isSelected() && true == findViewById(R.id.termsAgreedButton07).isSelected() && true == findViewById(R.id.termsAgreedButton08).isSelected()) {
            return true;
        }
        return false;
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }

    public void checkEmail() {
        String email = ((EditText) findViewById(R.id.emailField)).getText().toString().trim();
        if (!email.isEmpty()) {
            requestEmailCheckApi(email);
        }
    }

    private void requestEmailCheckApi(String email) {
        String parameter = String.format("?user_id=%s&gubun=%s&user_sns_id=%s", new Object[]{email, "99", ""});
        IDCheckApi request = new IDCheckApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onStart() {
                SignupActivity.this.showLoadingDialog(true);
            }

            public void onResult(Object result) {
                SignupActivity.this.showLoadingDialog(false);
                BaseResultModel model = (BaseResultModel) result;
                if (model.isOkResponse()) {
                    if (model.getResult().equals("N")) {
                        SignupActivity.this.showDialog(SignupActivity.this.getResources().getString(R.string.SIGNUP_ERROR_1));
                    } else if (model.getResult().equals("D")) {
                        SignupActivity.this.showDialog(SignupActivity.this.getResources().getString(R.string.SIGNUP_ERROR_2));
                    } else {
                        Intent intent = new Intent(SignupActivity.this, SignupAccountActivity.class);
                        intent.putExtra("email", ((EditText) SignupActivity.this.findViewById(R.id.emailField)).getText().toString().trim());
                        SignupActivity.this.animActivityForResult(intent, 17, R.anim.fade_in_activity, R.anim.fade_out_activity);
                    }
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestSNSCheckApi(String email, String snsId, final String type, final SnsModel snsModel) {
        String parameter = String.format("?user_id=%s&gubun=%s&user_sns_id=%s", new Object[]{email, type, snsId});
        IDCheckApi request = new IDCheckApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onStart() {
                SignupActivity.this.showLoadingDialog(true);
            }

            public void onResult(Object result) {
                SignupActivity.this.showLoadingDialog(false);
                BaseResultModel model = (BaseResultModel) result;
                if (model.isOkResponse()) {
                    if (model.getResult().equals("N")) {
                        SignupActivity.this.showDialog(SignupActivity.this.getResources().getString(R.string.SIGNUP_ERROR_1));
                    } else if (model.getResult().equals("D")) {
                        SignupActivity.this.showDialog(SignupActivity.this.getResources().getString(R.string.SIGNUP_ERROR_2));
                    } else {
                        Intent intent = new Intent(SignupActivity.this, PasswordActivity.class);
                        intent.putExtra("requestType", 1);
                        intent.putExtra("model", snsModel);
                        intent.putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, type);
                        SignupActivity.this.animActivityForResult(intent, 18, R.anim.modal_animation, R.anim.scale_down);
                    }
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestSignupApi(final SnsModel model, final String type, final String password) {
        SignupApi request = new SignupApi(this);
        request.addParam(AccessToken.USER_ID_KEY, model.getUserEmail());
        try {
            request.addParam("user_pwd", MD5.makeMD5(password));
        } catch (Exception e) {
            request.addParam("user_pwd", password);
        }
        request.addParam("user_name", model.getUserName());
        if (ShareatApp.getInstance().getPhonenumber().equals("01000000000")) {
            showDialog(getResources().getString(R.string.SIGNUP_ERROR_4), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    SignupActivity.this.finish();
                }
            });
            return;
        }
        request.addParam("user_phone", ShareatApp.getInstance().getPhonenumber());
        request.addParam("guid", ShareatApp.getInstance().getGUID());
        request.addParam("gubun", type);
        request.addParam("oauth_token", model.getAccessToken());
        request.addParam("user_img", model.getAvatarImageUrl());
        request.addParam("user_sns_id", model.getSNSID());
        request.addParam("os", "A");
        request.request(new RequestHandler() {
            public void onStart() {
                SignupActivity.this.showLoadingDialog(true);
            }

            public void onResult(Object result) {
                SignupActivity.this.showLoadingDialog(false);
                SignedModel model = (SignedModel) result;
                if (model == null || model.getResult() == null) {
                    SignupActivity.this.showDialog(SignupActivity.this.getResources().getString(R.string.SIGNUP_ERROR_3));
                } else if (model.getResult().equals("Y")) {
                    SessionManager.getInstance().setHasSession(true);
                    SessionManager.getInstance().setAuthToken(model.getAuth_token());
                    SignupActivity.this.showDialog(SignupActivity.this.getResources().getString(R.string.JOIN_COMPLETE), new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            Answers.getInstance().logSignUp(new SignUpEvent().putMethod(type).putSuccess(true));
                            SignupActivity.this.onStartMainActivity();
                        }
                    });
                } else if (model.getResult().equals("N")) {
                    GAEvent.onGaEvent(SignupActivity.this.getResources().getString(R.string.error), SignupActivity.this.getResources().getString(R.string.ga_ev_join), SignupActivity.this.getResources().getString(R.string.ga_auth_server_error) + " " + model.getResult());
                    SignupActivity.this.showDialog(SignupActivity.this.getResources().getString(R.string.JOIN_ALERT_02));
                } else if (model.getResult().equals("D")) {
                    GAEvent.onGaEvent(SignupActivity.this.getResources().getString(R.string.error), SignupActivity.this.getResources().getString(R.string.ga_ev_join), SignupActivity.this.getResources().getString(R.string.ga_auth_server_error) + " " + model.getResult());
                    SignupActivity.this.showDialog(SignupActivity.this.getResources().getString(R.string.JOIN_ALERT_03));
                } else if (model.getResult().equals("P")) {
                    GAEvent.onGaEvent(SignupActivity.this.getResources().getString(R.string.error), SignupActivity.this.getResources().getString(R.string.ga_ev_join), SignupActivity.this.getResources().getString(R.string.ga_auth_server_error) + " " + model.getResult());
                    SignupActivity.this.showDialog(SignupActivity.this.getResources().getString(R.string.SIGNUP_ERROR_4));
                }
            }

            public void onFailure(Exception exception) {
                SignupActivity.this.showLoadingDialog(false);
                SignupActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        SignupActivity.this.requestSignupApi(model, type, password);
                    }
                });
            }
        });
    }
}