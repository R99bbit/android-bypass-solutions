package com.embrain.panelpower;

import android.app.Activity;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.TextView;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.utils.LogUtil;

public class PushPopupActivity extends Activity {
    public static final String EXTRA_PUSH_MSG = "msg";
    public static final String EXTRA_PUSH_SURVEY_ALIAS = "survey_alias";
    public static final String EXTRA_PUSH_TYPE = "type";
    public static final String EXTRA_PUSH_URL = "url";
    private static final String TAG = "PushPopupActivity";
    private String ChannelId = "embrain_channel_id";
    private String ChannelSeqNm = "embrain_seq_nm";

    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_push_popup);
        getWindow().addFlags(6815744);
        handleIntent(getIntent());
    }

    /* access modifiers changed from: protected */
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        try {
            showPushDialog(intent.getStringExtra("type"), intent.getStringExtra("msg"), intent.getStringExtra(EXTRA_PUSH_SURVEY_ALIAS), intent.getStringExtra("url"));
        } catch (Exception unused) {
            finishActivity();
        }
    }

    /* access modifiers changed from: private */
    public void finishActivity() {
        LogUtil.write("finishActivity");
        if (VERSION.SDK_INT >= 16) {
            try {
                finishAffinity();
                LogUtil.write("finishAffinity");
            } catch (Exception unused) {
                finish();
                LogUtil.write("finish - Exception");
            }
        } else {
            finish();
            LogUtil.write("finish ");
        }
    }

    private void showPushDialog(final String str, String str2, final String str3, final String str4) {
        ((TextView) findViewById(R.id.tv_push_message)).setText(str2);
        findViewById(R.id.btn_push_left).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                PushPopupActivity.this.finishActivity();
            }
        });
        findViewById(R.id.btn_push_right).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                if (!"josa".equals(str) || StringUtils.isEmpty(str3)) {
                    PushPopupActivity.this.startApplication(str, str3, str4);
                } else {
                    PushPopupActivity.this.startSurveyActivity(str3);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void startSurveyActivity(String str) {
        clearNotification();
        Intent intent = new Intent(this, SurveyActivity.class);
        intent.putExtra(SurveyActivity.EXTRA_SURVEY_ID, str);
        startActivity(intent);
        finishActivity();
    }

    /* access modifiers changed from: private */
    public void startApplication(String str, String str2, String str3) {
        clearNotification();
        Intent intent = new Intent(this, SplashActivity.class);
        intent.putExtra("type", str);
        intent.putExtra(EXTRA_PUSH_SURVEY_ALIAS, str2);
        intent.putExtra("url", str3);
        startActivity(intent);
        finishActivity();
    }

    private void clearNotification() {
        NotificationManager notificationManager = (NotificationManager) getSystemService("notification");
        notificationManager.cancelAll();
        if (VERSION.SDK_INT >= 26) {
            try {
                notificationManager.createNotificationChannel(new NotificationChannel(this.ChannelId, this.ChannelSeqNm, 3));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}