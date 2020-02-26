package co.habitfactory.signalfinance_embrain.comm;

import android.annotation.TargetApi;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build.VERSION;

public class SignalNotificationManager implements SignalLibConsts {
    @TargetApi(26)
    public static void createChannel(Context context) {
        if (VERSION.SDK_INT >= 26) {
            ((NotificationManager) context.getSystemService("notification")).createNotificationChannel(new NotificationChannel(SignalLibConsts.g_DataChannel, SignalLibConsts.g_DataChannel, 4));
        }
    }
}