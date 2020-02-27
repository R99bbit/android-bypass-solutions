package com.nuvent.shareat.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import com.adpick.advertiser.sdk.InstallReceiver;
import com.google.android.gms.analytics.CampaignTrackingReceiver;
import com.igaworks.IgawReceiver;

public class NuventInstallReferrer extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        new IgawReceiver().onReceive(context, intent);
        Log.e("GAV", "onReceive");
        new InstallReceiver().onReceive(context, intent);
        Log.d("jongmiss", "REFERRER : " + intent.getStringExtra("referrer"));
        new CampaignTrackingReceiver().onReceive(context, intent);
    }
}