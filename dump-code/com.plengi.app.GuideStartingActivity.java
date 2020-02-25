package com.plengi.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

@RequiresApi(api = 26)
public class GuideStartingActivity extends Activity {
    public void finish() {
        super.finish();
        overridePendingTransition(0, 0);
    }

    public void onCreate(@Nullable Bundle bundle) {
        super.onCreate(bundle);
        overridePendingTransition(0, 0);
        startActivity(new Intent("android.settings.CHANNEL_NOTIFICATION_SETTINGS").putExtra("android.provider.extra.APP_PACKAGE", getPackageName()).putExtra("android.provider.extra.CHANNEL_ID", "plengi_default_2"));
        startActivity(new Intent(this, GuideDialogActivity.class));
        finish();
    }
}