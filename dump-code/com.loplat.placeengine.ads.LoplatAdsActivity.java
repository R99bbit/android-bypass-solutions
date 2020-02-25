package com.loplat.placeengine.ads;

import android.app.Activity;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import com.loplat.placeengine.Plengi;

public class LoplatAdsActivity extends Activity {
    public static final String NOTI_VIEW_AD_ACTION = "com.loplat.ad.VIEW_LOPLAT_ADPAGE";

    /* renamed from: a reason: collision with root package name */
    public int f55a;

    public final Intent a() {
        Intent launchIntentForPackage = getPackageManager().getLaunchIntentForPackage(getPackageName());
        if (launchIntentForPackage == null) {
            return null;
        }
        launchIntentForPackage.setFlags(536870912);
        try {
            startActivity(launchIntentForPackage);
            Plengi.getInstance(this).feedbackAdResult(this.f55a, 1);
        } catch (Exception unused) {
        }
        return launchIntentForPackage;
    }

    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Intent intent = getIntent();
        if (intent != null && NOTI_VIEW_AD_ACTION.equals(intent.getAction())) {
            this.f55a = intent.getIntExtra("msg_id", 0);
            ((NotificationManager) getSystemService("notification")).cancel(intent.getIntExtra("campaign_id", 0));
            String stringExtra = intent.getStringExtra("target_intent");
            if (stringExtra != null) {
                finish();
                if (stringExtra.startsWith("http://") || stringExtra.startsWith("https://")) {
                    Uri parse = Uri.parse(stringExtra);
                    Intent intent2 = new Intent("android.intent.action.VIEW");
                    intent2.setData(parse);
                    intent2.setFlags(268435456);
                    try {
                        startActivity(intent2);
                        Plengi.getInstance(this).feedbackAdResult(this.f55a, 1);
                    } catch (Exception unused) {
                        a();
                    }
                } else {
                    try {
                        startActivity(new Intent("android.intent.action.VIEW", Uri.parse(stringExtra)));
                        Plengi.getInstance(this).feedbackAdResult(this.f55a, 1);
                    } catch (Exception unused2) {
                        a();
                    }
                }
                return;
            }
        }
        finish();
    }
}