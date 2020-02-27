package com.nuvent.shareat.activity.intro;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageView;
import com.facebook.AccessToken;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.common.PasswordActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.intro.SignupApi;
import com.nuvent.shareat.dialog.PhotoTypeDialog;
import com.nuvent.shareat.dialog.PhotoTypeDialog.DialogClickListener;
import com.nuvent.shareat.dialog.TermsDialog;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.SignedModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.MD5;
import net.xenix.util.ImageDisplay;

public class SignupAccountActivity extends MainActionBarActivity {
    private static final int REQUEST_CODE_PASSWORD = 17;
    /* access modifiers changed from: private */
    public String mAvatarImagePath;

    public void onBackPressed() {
        finish(R.anim.fade_in_activity, R.anim.fade_out_activity);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickTitle(View view) {
        onBackPressed();
    }

    public void onClickTerms(View view) {
        new TermsDialog(this, ApiUrl.TERMS_SERVICE).show();
    }

    public void onClickAvatar(View view) {
        PhotoTypeDialog dialog = new PhotoTypeDialog(this, true);
        dialog.setOnDialogClickListener(new DialogClickListener() {
            public void onClickViewer() {
            }

            public void onDismiss() {
            }
        });
        dialog.show();
    }

    public void onClickConfirm(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_join_signup, (int) R.string.ga_ev_join, (int) R.string.ga_join_signup);
        Intent intent = new Intent(this, PasswordActivity.class);
        intent.putExtra("requestType", 1);
        animActivityForResult(intent, 17, R.anim.modal_animation, R.anim.scale_down);
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == -1) {
            switch (requestCode) {
                case 1:
                    this.mAvatarImagePath = ImageDisplay.getInstance().setPickImageView(this, PhotoTypeDialog.getCameraOutputUri().getPath(), (ImageView) findViewById(R.id.avatarImageView));
                    return;
                case 17:
                    if (data.hasExtra("password")) {
                        requestSignupApi(((EditText) findViewById(R.id.emailField)).getText().toString().trim(), ((EditText) findViewById(R.id.nameField)).getText().toString().trim(), data.getStringExtra("password"));
                        return;
                    }
                    return;
                case 101:
                case 102:
                    if (resultCode == -1 && data != null) {
                        this.mAvatarImagePath = ImageDisplay.getInstance().setPickImageView(this, ImageDisplay.getInstance().getImagePath(this, requestCode, data.getData()), (ImageView) findViewById(R.id.avatarImageView));
                        return;
                    }
                    return;
                default:
                    return;
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_signup_account, 2);
        showFavoriteButton(false);
        setTitle("\ud68c\uc6d0\uac00\uc785");
        GAEvent.onGAScreenView(this, R.string.ga_join_account);
        findViewById(R.id.confirmButton).setEnabled(false);
        ((EditText) findViewById(R.id.emailField)).setText(getIntent().getStringExtra("email"));
        ((EditText) findViewById(R.id.nameField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                SignupAccountActivity.this.findViewById(R.id.confirmButton).setEnabled(s.length() > 0);
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestSignupApi(final String userId, final String userName, final String userPassword) {
        SignupApi request = new SignupApi(this);
        request.addParam(AccessToken.USER_ID_KEY, userId);
        request.addParam("user_name", userName);
        try {
            request.addParam("user_pwd", MD5.makeMD5(userPassword));
        } catch (Exception e) {
            request.addParam("user_pwd", userPassword);
        }
        if (ShareatApp.getInstance().getPhonenumber().equals("01000000000")) {
            showDialog(getResources().getString(R.string.SIGNUP_ERROR_4), new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    SignupAccountActivity.this.finish();
                }
            });
            return;
        }
        request.addParam("user_phone", ShareatApp.getInstance().getPhonenumber());
        request.addParam("guid", ShareatApp.getInstance().getGUID());
        request.addParam("gubun", "99");
        request.addParam("os", "A");
        request.request(new RequestHandler() {
            public void onStart() {
                SignupAccountActivity.this.showLoadingDialog(true);
            }

            public void onResult(Object result) {
                SignupAccountActivity.this.showLoadingDialog(false);
                SignedModel model = (SignedModel) result;
                if (model == null || model.getResult() == null) {
                    GAEvent.onGaEvent((Activity) SignupAccountActivity.this, (int) R.string.error, (int) R.string.ga_ev_join, (int) R.string.ga_auth_server_error);
                    SignupAccountActivity.this.showDialog("\ud68c\uc6d0\uac00\uc785\uc5d0 \uc2e4\ud328\ud588\uc2b5\ub2c8\ub2e4.");
                } else if (model.getResult().equals("Y")) {
                    SessionManager.getInstance().setAuthToken(model.getAuth_token());
                    if (SignupAccountActivity.this.mAvatarImagePath != null && !SignupAccountActivity.this.mAvatarImagePath.isEmpty()) {
                        ShareatApp.getInstance();
                        ShareatApp.requestAvatarImageApi(SignupAccountActivity.this.mAvatarImagePath);
                    }
                    SignupAccountActivity.this.setResult(-1);
                    SignupAccountActivity.this.onBackPressed();
                } else if (model.getResult().equals("W")) {
                    GAEvent.onGaEvent(SignupAccountActivity.this.getResources().getString(R.string.error), SignupAccountActivity.this.getResources().getString(R.string.ga_ev_join), SignupAccountActivity.this.getResources().getString(R.string.ga_auth_server_error) + " " + model.getResult());
                    SignupAccountActivity.this.showDialog(SignupAccountActivity.this.getResources().getString(R.string.JOIN_ALERT_01));
                    SignupAccountActivity.this.showKeyboard(SignupAccountActivity.this.findViewById(R.id.nameField));
                } else if (model.getResult().equals("N")) {
                    GAEvent.onGaEvent(SignupAccountActivity.this.getResources().getString(R.string.error), SignupAccountActivity.this.getResources().getString(R.string.ga_ev_join), SignupAccountActivity.this.getResources().getString(R.string.ga_auth_server_error) + " " + model.getResult());
                    SignupAccountActivity.this.showDialog(SignupAccountActivity.this.getResources().getString(R.string.JOIN_ALERT_02));
                } else if (model.getResult().equals("D")) {
                    GAEvent.onGaEvent(SignupAccountActivity.this.getResources().getString(R.string.error), SignupAccountActivity.this.getResources().getString(R.string.ga_ev_join), SignupAccountActivity.this.getResources().getString(R.string.ga_auth_server_error) + " " + model.getResult());
                    SignupAccountActivity.this.showDialog(SignupAccountActivity.this.getResources().getString(R.string.JOIN_ALERT_03));
                } else if (model.getResult().equals("P")) {
                    GAEvent.onGaEvent(SignupAccountActivity.this.getResources().getString(R.string.error), SignupAccountActivity.this.getResources().getString(R.string.ga_ev_join), SignupAccountActivity.this.getResources().getString(R.string.ga_auth_server_error) + " " + model.getResult());
                    SignupAccountActivity.this.showDialog(SignupAccountActivity.this.getResources().getString(R.string.SIGNUP_ERROR_4));
                }
            }

            public void onFailure(Exception exception) {
                SignupAccountActivity.this.showLoadingDialog(false);
                SignupAccountActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        SignupAccountActivity.this.requestSignupApi(userId, userName, userPassword);
                    }
                });
            }
        });
    }
}