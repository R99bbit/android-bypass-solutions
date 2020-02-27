package com.adpick.advertiser.sdk;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class InstallReceiver extends BroadcastReceiver {
    private String certkey;

    public void onReceive(Context context, Intent intent) {
        try {
            Context ac = context.getApplicationContext();
            Bundle extras = intent.getExtras();
            String secretkey = AdPickAdvertiser.GetPref(ac, "secretkey");
            if (extras != null) {
                this.certkey = extras.getString("referrer");
                AdPickAdvertiser.SetPref(ac, "installed", "YES");
                AdPickAdvertiser.SetPref(ac, "certkey", this.certkey);
                if (secretkey != null && !secretkey.isEmpty()) {
                    AdPickAdvertiser.UserActivity(ac, "install", "");
                }
                Log.i("ADPICK", "ADPICK Install Referrer Ready");
                return;
            }
            Log.i("ADPICK", "ADPICK Install Referrer Empty");
        } catch (Exception e) {
            Log.i("ADPICK", "ADPICK Install Referrer Error");
        }
    }
}