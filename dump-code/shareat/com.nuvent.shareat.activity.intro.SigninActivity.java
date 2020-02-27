package com.nuvent.shareat.activity.intro;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Rect;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;
import com.crashlytics.android.answers.Answers;
import com.crashlytics.android.answers.LoginEvent;
import com.facebook.CallbackManager;
import com.facebook.CallbackManager.Factory;
import com.facebook.FacebookSdk;
import com.igaworks.adbrix.IgawAdbrix;
import com.kakao.auth.Session;
import com.kakao.usermgmt.LoginButton;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.common.PasswordActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.intro.EmailCertificationApi;
import com.nuvent.shareat.api.intro.SNSSigninApi;
import com.nuvent.shareat.dialog.TermsDialog;
import com.nuvent.shareat.event.LoginSuccessEvent;
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
import de.greenrobot.event.EventBus;

public class SigninActivity extends MainActionBarActivity {
    private static final int REQUEST_CODE_PASSWORD = 17;
    private CallbackManager mCallbackManager;
    private LoginInterface mOnSnsLoginListener = new LoginInterface() {
        public void onCompleted(SnsModel model, String type) {
            SigninActivity.this.requestSNSSignupApi(model, type);
        }

        public void onError(Exception e, String type) {
            SigninActivity signinActivity = SigninActivity.this;
            int i = type.equals(BaseSnsManager.SNS_LOGIN_TYPE_FACEBOOK) ? R.string.ga_auth_facebook_error : type.equals(BaseSnsManager.SNS_LOGIN_TYPE_KAKAO) ? R.string.ga_auth_kakao_error : R.string.ga_auth_naver_error;
            GAEvent.onGaEvent((Activity) signinActivity, (int) R.string.error, (int) R.string.ga_ev_login, i);
            SigninActivity.this.showDialog(e.getMessage());
        }

        public void onErrorNaverReAgree(Runnable doneRun, Runnable cancelRun) {
            SigninActivity.this.showConfirmDialog((String) "\ub124\uc774\ubc84ID\ub97c \ud1b5\ud558\uc5ec \ub85c\uadf8\uc778 \ud558\uc2dc\ub824\uba74, \ud504\ub85c\ud544 \ud56d\ubaa9 \uc81c\uacf5\uc5d0 \ub300\ud55c \ub3d9\uc758\uac00 \ud544\uc694\ud569\ub2c8\ub2e4.\n \ub124\uc774\ubc84 ID \ud504\ub85c\ud544 \uc81c\uacf5 \ub3d9\uc758\ub97c \uc9c4\ud589\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?", doneRun, cancelRun);
        }
    };

    private void setListenerToRootView() {
        findViewById(R.id.rootLayout).getViewTreeObserver().addOnGlobalLayoutListener(new OnGlobalLayoutListener() {
            public void onGlobalLayout() {
                Rect rect = new Rect();
                SigninActivity.this.findViewById(R.id.rootLayout).getWindowVisibleDisplayFrame(rect);
                if (SigninActivity.this.findViewById(R.id.rootLayout).getRootView().getHeight() - rect.bottom > 300) {
                    SigninActivity.this.findViewById(R.id.lineView).setVisibility(8);
                    SigninActivity.this.findViewById(R.id.snsButtonLayout).setVisibility(8);
                    return;
                }
                SigninActivity.this.findViewById(R.id.lineView).setVisibility(0);
                SigninActivity.this.findViewById(R.id.snsButtonLayout).setVisibility(0);
                if (TextUtils.isEmpty(((EditText) SigninActivity.this.findViewById(R.id.emailField)).getText())) {
                    SigninActivity.this.findViewById(R.id.emailField).setSelected(false);
                    ((TextView) SigninActivity.this.findViewById(R.id.emailLabel)).setTextColor(Color.parseColor("#7cffffff"));
                }
            }
        });
    }

    public void onBackPressed() {
        finish(R.anim.fade_in_activity, R.anim.fade_out_activity);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickTitle(View view) {
        onBackPressed();
    }

    public void onClickFacebook(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_login, (int) R.string.ga_ev_login, (int) R.string.ga_join_login_facebook);
        IgawAdbrix.retention("login", "facebook");
        FacebookLoginManager manager = new FacebookLoginManager(this, this.mCallbackManager);
        manager.setOnLoginListener(this.mOnSnsLoginListener);
        manager.requestFacebookGraphApi();
    }

    public void onClickNaver(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_login, (int) R.string.ga_ev_login, (int) R.string.ga_join_login_naver);
        IgawAdbrix.retention("login", "naver");
        NaverLoginManager manager = new NaverLoginManager(this);
        manager.setOnLoginListener(this.mOnSnsLoginListener);
        manager.requestNaverSession();
    }

    public void onClickKakao(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_login, (int) R.string.ga_ev_login, (int) R.string.ga_join_login_kakao);
        IgawAdbrix.retention("login", Session.REDIRECT_URL_PREFIX);
        KakaoLoginManager manager = new KakaoLoginManager(this, (LoginButton) findViewById(R.id.com_kakao_login));
        manager.setOnLoginListener(this.mOnSnsLoginListener);
        manager.requestKakaoLoginApi();
    }

    public void onClickSignin(View view) {
        hideKeyboard(findViewById(R.id.emailField));
        final String email = ((EditText) findViewById(R.id.emailField)).getText().toString().trim();
        if (!email.isEmpty()) {
            showLoadingDialog(true);
            findViewById(R.id.emailField).postDelayed(new Runnable() {
                public void run() {
                    SigninActivity.this.requestEmailCertificationApi(email);
                }
            }, 500);
        }
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
                    showDialog(getResources().getString(R.string.LOGIN_COMPLETE), new OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            Answers.getInstance().logLogin(new LoginEvent().putSuccess(true));
                            IgawAdbrix.retention("login");
                            SigninActivity.this.onStartMainActivity();
                        }
                    });
                    EventBus.getDefault().post(new LoginSuccessEvent());
                    return;
            }
        }
        this.mCallbackManager.onActivityResult(requestCode, resultCode, data);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_signin, 2);
        showFavoriteButton(false);
        setTitle("\ub85c\uadf8\uc778");
        if (!FacebookSdk.isInitialized()) {
            FacebookSdk.sdkInitialize(getApplicationContext());
        }
        GAEvent.onGAScreenView(this, R.string.ga_login);
        IgawAdbrix.retention("login");
        findViewById(R.id.confirmButton).setEnabled(false);
        this.mCallbackManager = Factory.create();
        findViewById(R.id.emailField).setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                view.setSelected(true);
                ((TextView) SigninActivity.this.findViewById(R.id.emailLabel)).setTextColor(-1);
            }
        });
        ((EditText) findViewById(R.id.emailField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                SigninActivity.this.findViewById(R.id.confirmButton).setEnabled(s.length() > 0);
            }
        });
        ((EditText) findViewById(R.id.emailField)).setOnEditorActionListener(new OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                switch (actionId) {
                    case 6:
                        SigninActivity.this.hideKeyboard(v);
                        return true;
                    default:
                        return false;
                }
            }
        });
        setListenerToRootView();
    }

    /* access modifiers changed from: private */
    public void requestEmailCertificationApi(final String email) {
        String parameter = String.format("?user_id=%s&phone_os=A", new Object[]{email});
        EmailCertificationApi request = new EmailCertificationApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onStart() {
                SigninActivity.this.showLoadingDialog(true);
            }

            public void onResult(Object result) {
                SigninActivity.this.showLoadingDialog(false);
                if (((BaseResultModel) result).getResult().equals("Y")) {
                    Intent intent = new Intent(SigninActivity.this, PasswordActivity.class);
                    intent.putExtra("requestType", 2);
                    intent.putExtra("email", email);
                    SigninActivity.this.animActivityForResult(intent, 17, R.anim.modal_animation, R.anim.scale_down);
                    return;
                }
                SigninActivity.this.showDialog(SigninActivity.this.getResources().getString(R.string.LOGIN_ALERT_01));
                SigninActivity.this.showKeyboard(SigninActivity.this.findViewById(R.id.emailField));
            }

            public void onFailure(Exception exception) {
                SigninActivity.this.showLoadingDialog(false);
                SigninActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        SigninActivity.this.requestEmailCertificationApi(email);
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestSNSSignupApi(final SnsModel snsModel, final String type) {
        SNSSigninApi request = new SNSSigninApi(this);
        request.addParam("user_sns_id", snsModel.getSNSID());
        request.addParam("sns_gubun", type);
        request.addParam("guid", ShareatApp.getInstance().getGUID());
        request.addParam("phone_os", "A");
        if (ShareatApp.getInstance().getPhonenumber().equals("01000000000")) {
            showDialog(getResources().getString(R.string.SIGNUP_ERROR_4), new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    SigninActivity.this.finish();
                }
            });
            return;
        }
        request.addParam("user_phone", ShareatApp.getInstance().getPhonenumber());
        request.request(new RequestHandler() {
            public void onStart() {
                SigninActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                SigninActivity.this.showCircleDialog(false);
                SignedModel model = (SignedModel) result;
                if (model == null || model.getResult() == null) {
                    SigninActivity.this.showDialog(SigninActivity.this.getResources().getString(R.string.LOGIN_ALERT_02));
                } else if (!model.getResult().equals("Y")) {
                    GAEvent.onGaEvent(SigninActivity.this.getResources().getString(R.string.error), SigninActivity.this.getResources().getString(R.string.ga_ev_login), SigninActivity.this.getResources().getString(R.string.ga_auth_server_error) + " " + model.getResult());
                    SigninActivity.this.showDialog(SigninActivity.this.getResources().getString(R.string.LOGIN_ALERT_01));
                } else if (model.getAuth_token() == null || model.getAuth_token().isEmpty()) {
                    SigninActivity.this.showDialog(SigninActivity.this.getResources().getString(R.string.LOGIN_ALERT_02));
                } else {
                    SessionManager.getInstance().setAuthToken(model.getAuth_token());
                    SessionManager.getInstance().setHasSession(true);
                    SigninActivity.this.showDialog(SigninActivity.this.getResources().getString(R.string.LOGIN_COMPLETE), new OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            Answers.getInstance().logLogin(new LoginEvent());
                            IgawAdbrix.retention("login");
                            SigninActivity.this.onStartMainActivity();
                        }
                    });
                    EventBus.getDefault().post(new LoginSuccessEvent());
                }
            }

            public void onFailure(Exception exception) {
                SigninActivity.this.showCircleDialog(false);
                SigninActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        SigninActivity.this.requestSNSSignupApi(snsModel, type);
                    }
                });
            }
        });
    }

    public void onClickJoin(View view) {
        Intent intent = new Intent(this, SignupActivity.class);
        intent.addFlags(872415232);
        animActivity(intent, R.anim.fade_in_activity, R.anim.fade_out_activity);
    }

    public void onClickTerms(View view) {
        new TermsDialog(this, ApiUrl.TERMS_SERVICE).show();
    }
}