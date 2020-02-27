package com.nuvent.shareat.gcm;

import android.app.IntentService;
import android.content.Intent;
import android.os.Bundle;

public class GCMIntentService extends IntentService {
    public GCMIntentService() {
        super("ShareAtIntentService");
    }

    /* access modifiers changed from: protected */
    public void onHandleIntent(Intent intent) {
        Bundle extras = intent.getExtras();
    }
}