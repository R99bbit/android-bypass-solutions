package com.nuvent.shareat.activity.common;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.menu.MyCardActivity;
import com.nuvent.shareat.activity.menu.MyPaymentActivity;
import com.nuvent.shareat.activity.menu.PasswordSettingActivity;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;

public class PostMyInfoActivity extends BaseActivity {
    public static final int POST_TYPE_PASSWORD_CHECK_MY_CARD = 18;
    public static final int POST_TYPE_PASSWORD_CHECK_MY_PASSWORD = 19;
    public static final int POST_TYPE_PASSWORD_CHECK_MY_PAYMENT = 17;
    public static final int REQUEST_TYPE_PASSWORD_CHECK = 153;
    private final String MYINFO_TYPE_CARD = "paymentSetting";
    private final String MYINFO_TYPE_PASSWORD = "passwordSetting";
    private final String MYINFO_TYPE_PAYMENT = "orderHistory";

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == -1) {
            switch (requestCode) {
                case 153:
                    AppSettingManager.getInstance().setPasswordCheck(true);
                    int postType = data.getIntExtra("postType", 0);
                    if (17 == postType) {
                        pushActivity(new Intent(this, MyPaymentActivity.class));
                        finish(false);
                        return;
                    } else if (18 == postType) {
                        pushActivity(new Intent(this, MyCardActivity.class));
                        finish(false);
                        return;
                    } else {
                        if (19 == postType) {
                        }
                        return;
                    }
                default:
                    return;
            }
        } else {
            finish(false);
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (!SessionManager.getInstance().hasSession()) {
            finish(false);
        } else if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_URL)) {
            String path = Uri.parse(getIntent().getStringExtra(CustomSchemeManager.EXTRA_INTENT_URL)).getPath();
            if (path.startsWith("/")) {
                path = path.replaceFirst("/", "");
            }
            String[] segment = path.split("/");
            if (segment[0].equals("orderHistory")) {
                if (!AppSettingManager.getInstance().isPasswordCheck()) {
                    Intent intent = new Intent(this, ConfirmPasswordActivity.class);
                    intent.putExtra("postType", 17);
                    animActivityForResult(intent, 153, R.anim.modal_animation, R.anim.scale_down);
                    return;
                }
                pushActivity(new Intent(this, MyPaymentActivity.class));
                finish(false);
            } else if (segment[0].equals("paymentSetting")) {
                if (!AppSettingManager.getInstance().isPasswordCheck()) {
                    Intent intent2 = new Intent(this, ConfirmPasswordActivity.class);
                    intent2.putExtra("postType", 18);
                    animActivityForResult(intent2, 153, R.anim.modal_animation, R.anim.scale_down);
                    return;
                }
                pushActivity(new Intent(this, MyCardActivity.class));
                finish(false);
            } else if (segment[0].equals("passwordSetting")) {
                pushActivity(new Intent(this, PasswordSettingActivity.class));
                finish(false);
            }
        }
    }
}