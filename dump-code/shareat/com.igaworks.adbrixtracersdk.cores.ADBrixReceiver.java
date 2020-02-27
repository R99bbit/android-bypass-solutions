package com.igaworks.adbrixtracersdk.cores;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.igaworks.IgawReceiver;

public class ADBrixReceiver extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        new IgawReceiver().onReceive(context, intent);
    }
}