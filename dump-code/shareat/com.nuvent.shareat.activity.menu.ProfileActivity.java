package com.nuvent.shareat.activity.menu;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.member.UserInfoApi;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.util.GAEvent;

public class ProfileActivity extends MainActionBarActivity {
    public void onClickWithdraw(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_profile_edit, (int) R.string.ga_ev_click, (int) R.string.ga_withdraw);
        pushActivity(new Intent(this, WithdrawActivity.class));
    }

    public void onClickConfirm(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_profile_edit, (int) R.string.ga_ev_click, (int) R.string.ga_ev_complete);
        requestEditUserInfoApi(((EditText) findViewById(R.id.nameField)).getText().toString().trim());
    }

    public void onClickCheck(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_profile_edit, (int) R.string.ga_ev_click, (int) R.string.ga_profile_edit_private);
        view.setSelected(!view.isSelected());
        findViewById(R.id.privateLockView).setSelected(view.isSelected());
        ((TextView) findViewById(R.id.privateLockView)).setText(view.isSelected() ? "\uc815\ubcf4\ube44\uacf5\uac1c" : "\uc815\ubcf4\uacf5\uac1c");
        checkValue();
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        boolean z = true;
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_profile, 2);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\ud68c\uc6d0\uc815\ubcf4");
        GAEvent.onGAScreenView(this, R.string.ga_profile_edit);
        if (SessionManager.getInstance().getUserModel() == null) {
            finish();
            return;
        }
        ((EditText) findViewById(R.id.nameField)).setText(SessionManager.getInstance().getUserModel().getUserName());
        ((TextView) findViewById(R.id.emailLabel)).setText(SessionManager.getInstance().getUserModel().getEmail());
        if (!ShareatApp.getInstance().getPhonenumber().isEmpty()) {
            String phoneNum = ShareatApp.getInstance().getPhonenumber();
            if (10 < phoneNum.length()) {
                phoneNum = phoneNum.substring(0, 3) + "-" + phoneNum.substring(3, 7) + "-" + phoneNum.substring(7, phoneNum.length());
            }
            ((TextView) findViewById(R.id.phoneLabel)).setText(phoneNum);
        }
        findViewById(R.id.privateCheck).setSelected(!SessionManager.getInstance().getUserModel().enableOpen());
        View findViewById = findViewById(R.id.privateLockView);
        if (SessionManager.getInstance().getUserModel().enableOpen()) {
            z = false;
        }
        findViewById.setSelected(z);
        ((TextView) findViewById(R.id.privateLockView)).setText(findViewById(R.id.privateLockView).isSelected() ? "\uc815\ubcf4\ube44\uacf5\uac1c" : "\uc815\ubcf4\uacf5\uac1c");
        findViewById(R.id.confirmButton).setEnabled(false);
        ((EditText) findViewById(R.id.nameField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                ProfileActivity.this.checkValue();
            }
        });
    }

    /* access modifiers changed from: private */
    public void checkValue() {
        boolean isChanged = false;
        String userName = ((EditText) findViewById(R.id.nameField)).getText().toString().trim();
        if (userName.isEmpty() || SessionManager.getInstance().getUserModel().getUserName().equals(userName)) {
            if ((!SessionManager.getInstance().getUserModel().enableOpen()) != findViewById(R.id.privateCheck).isSelected()) {
                isChanged = true;
            }
        } else {
            isChanged = true;
        }
        findViewById(R.id.confirmButton).setEnabled(isChanged);
    }

    /* access modifiers changed from: private */
    public void requestEditUserInfoApi(final String name) {
        UserInfoApi request = new UserInfoApi(this, 2);
        request.addParam("user_name", name);
        request.addParam("open_yn", findViewById(R.id.privateCheck).isSelected() ? AppEventsConstants.EVENT_PARAM_VALUE_YES : AppEventsConstants.EVENT_PARAM_VALUE_NO);
        request.request(new RequestHandler() {
            public void onStart() {
                ProfileActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                ProfileActivity.this.showCircleDialog(false);
                BaseResultModel model = (BaseResultModel) result;
                if (model.getResult().equals("W")) {
                    ProfileActivity.this.showDialog(ProfileActivity.this.getResources().getString(R.string.PROFILE_EDIT_ALERT2), new OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            ProfileActivity.this.showKeyboard(ProfileActivity.this.findViewById(R.id.nameField));
                        }
                    });
                } else if (!model.getResult().equals("Y")) {
                    ProfileActivity.this.showDialog(ProfileActivity.this.getResources().getString(R.string.PROFILE_EDIT_ALERT));
                } else {
                    ProfileActivity.this.finish();
                }
            }

            public void onFailure(Exception exception) {
                ProfileActivity.this.showCircleDialog(false);
                ProfileActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ProfileActivity.this.requestEditUserInfoApi(name);
                    }
                });
            }
        });
    }
}