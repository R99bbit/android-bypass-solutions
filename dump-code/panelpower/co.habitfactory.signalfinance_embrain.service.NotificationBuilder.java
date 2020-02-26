package co.habitfactory.signalfinance_embrain.service;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.preference.PreferenceManager;
import androidx.core.app.NotificationCompat.Builder;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;
import co.habitfactory.signalfinance_embrain.R;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;

public class NotificationBuilder implements SignalLibConsts {
    private static final String NOTIFICATION_ID = "co.habitfactory.signalfinance.NOTIFICATION_ID";
    private static final int SUMMARY_ID = 0;
    private static final String TAG = "NotificationBuilder";
    private final Context mContext;
    private SignalLibPrefs mPrefs;
    private final NotificationManagerCompat notificationManager;

    public static NotificationBuilder newInstance(Context context) {
        Context applicationContext = context.getApplicationContext();
        Context createDeviceProtectedStorageContext = ContextCompat.createDeviceProtectedStorageContext(applicationContext);
        if (createDeviceProtectedStorageContext != null) {
            applicationContext = createDeviceProtectedStorageContext;
        }
        return new NotificationBuilder(applicationContext, NotificationManagerCompat.from(applicationContext), PreferenceManager.getDefaultSharedPreferences(applicationContext));
    }

    private NotificationBuilder(Context context, NotificationManagerCompat notificationManagerCompat, SharedPreferences sharedPreferences) {
        this.mPrefs = new SignalLibPrefs(context);
        this.mContext = context.getApplicationContext();
        this.notificationManager = notificationManagerCompat;
    }

    public void sendBundledNotification(String str, String str2, String str3, String str4, String str5, int i, int i2) {
        Notification notification = i2 == 0 ? buildNotificationSms(str, str2, str3, str4, str5, i) : i2 == 1 ? buildNotificationPush(str, str2, str3, str4, str5, i) : null;
        if (notification != null) {
            this.notificationManager.notify(getNotificationId(), notification);
            this.notificationManager.notify(0, buildSummary(SignalLibConsts.g_DataChannel));
        }
    }

    private Notification buildNotificationSms(String str, String str2, String str3, String str4, String str5, int i) {
        Bitmap bitmap;
        StringBuilder sb = new StringBuilder();
        sb.append("signalembrain://action_signal?");
        sb.append(SignalLibConsts.SCHEME_LINK_ID);
        sb.append("=");
        sb.append(str);
        Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(sb.toString()));
        intent.addFlags(268468224);
        PendingIntent activity = PendingIntent.getActivity(this.mContext, 0, intent, 134217728);
        if ("BK".equals(str2)) {
            bitmap = null;
        } else {
            bitmap = BitmapFactory.decodeResource(this.mContext.getResources(), setCategoryImg(str3, "_c"));
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append("store : ");
        sb2.append(str4);
        SignalUtil.PRINT_LOG(TAG, sb2.toString());
        StringBuilder sb3 = new StringBuilder();
        sb3.append("store.length : ");
        sb3.append(str4.length());
        SignalUtil.PRINT_LOG(TAG, sb3.toString());
        if (str4 == null || str4.length() <= 0) {
            str4 = "(\uc0ac\uc6a9\ucc98\uac00 \uc5c6\uc2b5\ub2c8\ub2e4)";
        }
        return new Builder(this.mContext, SignalLibConsts.g_DataChannel).setContentTitle(str4).setContentText(str5).setWhen(System.currentTimeMillis()).setLargeIcon(bitmap).setSmallIcon(R.drawable.icon_signal_negative).setShowWhen(true).setGroupAlertBehavior(1).setAutoCancel(true).setDefaults(5).setVibrate(new long[]{0}).setContentIntent(activity).setContentInfo("").setColor(this.mContext.getResources().getColor(R.color.signalnoticolor)).setTicker("").setGroup(SignalLibConsts.g_DataChannel).build();
    }

    private Notification buildNotificationPush(String str, String str2, String str3, String str4, String str5, int i) {
        Bitmap bitmap;
        String str6;
        StringBuilder sb = new StringBuilder();
        sb.append("signalembrain://action_signal?");
        sb.append(SignalLibConsts.SCHEME_LINK_ID);
        sb.append("=");
        sb.append(str);
        Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(sb.toString()));
        intent.addFlags(268468224);
        PendingIntent activity = PendingIntent.getActivity(this.mContext, 0, intent, 134217728);
        if ("BK".equals(str2)) {
            bitmap = null;
        } else {
            bitmap = BitmapFactory.decodeResource(this.mContext.getResources(), setCategoryImg(str3, "_c"));
        }
        if (str4 == null || str4.length() <= 0) {
            str6 = "(\ud478\uc2dc\uc54c\ub9bc)";
        } else {
            StringBuilder sb2 = new StringBuilder();
            sb2.append(str4);
            sb2.append(" (\ud478\uc2dc\uc54c\ub9bc)");
            str6 = sb2.toString();
        }
        return new Builder(this.mContext, SignalLibConsts.g_DataChannel).setContentTitle(str6).setContentText(str5).setWhen(System.currentTimeMillis()).setGroupAlertBehavior(1).setLargeIcon(bitmap).setSmallIcon(R.drawable.icon_signal_negative).setShowWhen(true).setAutoCancel(true).setDefaults(5).setVibrate(new long[]{0}).setContentIntent(activity).setContentInfo("").setColor(this.mContext.getResources().getColor(R.color.signalnoticolor)).setTicker("").setGroup(SignalLibConsts.g_DataChannel).build();
    }

    private Notification buildSummary(String str) {
        this.mPrefs.getInt(NOTIFICATION_ID, 0);
        Intent intent = new Intent("android.intent.action.VIEW", Uri.parse("signalembrain://action_signal?"));
        intent.addFlags(268468224);
        return new Builder(this.mContext, SignalLibConsts.g_DataChannel).setWhen(System.currentTimeMillis()).setGroupAlertBehavior(1).setSmallIcon(R.drawable.icon_signal_negative).setColor(this.mContext.getResources().getColor(R.color.signalnoticolor)).setShowWhen(true).setGroup(str).setAutoCancel(true).setContentIntent(PendingIntent.getActivity(this.mContext, 0, intent, 134217728)).setGroupSummary(true).build();
    }

    private int getNotificationId() {
        int i = this.mPrefs.getInt(NOTIFICATION_ID, 0);
        do {
            i++;
        } while (i == 0);
        this.mPrefs.putInt(NOTIFICATION_ID, i);
        return i;
    }

    public int setCategoryImg(String str, String str2) {
        int i = 0;
        try {
            if (str.length() == 5) {
                str = str.substring(0, 3);
            }
            Resources resources = this.mContext.getResources();
            StringBuilder sb = new StringBuilder();
            sb.append("icon_category_");
            sb.append(str);
            sb.append(str2);
            i = resources.getIdentifier(sb.toString(), "drawable", this.mContext.getPackageName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (i != 0) {
            return i;
        }
        Resources resources2 = this.mContext.getResources();
        StringBuilder sb2 = new StringBuilder();
        sb2.append("icon_category_017");
        sb2.append(str2);
        return resources2.getIdentifier(sb2.toString(), "drawable", this.mContext.getPackageName());
    }
}