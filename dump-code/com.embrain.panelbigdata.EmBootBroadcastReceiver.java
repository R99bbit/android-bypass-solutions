package com.embrain.panelbigdata;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.embrain.panelbigdata.utils.LogUtil;

public class EmBootBroadcastReceiver extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        StringBuilder sb = new StringBuilder();
        sb.append("EmBootBroadcastReceiver.onReceive() : ");
        sb.append(intent.getAction());
        LogUtil.write(sb.toString());
        EmBigDataManager.start(context, true);
    }
}