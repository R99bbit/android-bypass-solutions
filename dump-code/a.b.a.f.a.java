package a.b.a.f;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build.VERSION;
import androidx.annotation.DrawableRes;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.core.app.NotificationCompat.Builder;
import com.loplat.placeengine.R;
import com.plengi.app.GuideStartingActivity;

/* compiled from: ForegroundNotification */
public class a {

    /* renamed from: a reason: collision with root package name */
    public static Notification f32a;
    public static Notification b;
    @StringRes
    public static int c;
    @StringRes
    public static int d;
    @StringRes
    public static int e;
    @DrawableRes
    public static int f;
    @StringRes
    public static int g;
    @StringRes
    public static int h;

    public static void a(Context context) {
        if (VERSION.SDK_INT >= 26) {
            int i = c;
            if (i == 0) {
                i = R.string.channel_name_default;
            }
            NotificationChannel notificationChannel = new NotificationChannel("plengi_default_2", context.getString(i), 2);
            int i2 = d;
            notificationChannel.setDescription(i2 == 0 ? null : context.getString(i2));
            notificationChannel.enableLights(false);
            notificationChannel.enableVibration(false);
            notificationChannel.setShowBadge(false);
            notificationChannel.setSound(null, null);
            notificationChannel.setLockscreenVisibility(-1);
            ((NotificationManager) context.getSystemService("notification")).createNotificationChannel(notificationChannel);
        }
    }

    public static Notification b(Context context) {
        Notification notification = f32a;
        if (notification != null) {
            return notification;
        }
        if (b == null) {
            Builder builder = new Builder(context, "plengi_default_2");
            int i = f;
            if (i == 0) {
                i = R.drawable.ic_noti_fgs;
            }
            Builder smallIcon = builder.setSmallIcon(i);
            int i2 = g;
            if (i2 == 0) {
                i2 = R.string.noti_title_default;
            }
            Builder contentTitle = smallIcon.setContentTitle(context.getString(i2));
            int i3 = h;
            if (i3 == 0) {
                i3 = R.string.noti_text_default;
            }
            Builder autoCancel = contentTitle.setContentText(context.getString(i3)).setShowWhen(false).setPriority(-1).setAutoCancel(true);
            if (VERSION.SDK_INT >= 26) {
                autoCancel.setContentIntent(PendingIntent.getActivity(context, 0, new Intent(context, GuideStartingActivity.class), 0));
            }
            b = autoCancel.build();
        }
        return b;
    }

    public static boolean a(@Nullable CharSequence charSequence, @Nullable CharSequence charSequence2) {
        if (charSequence == null && charSequence2 == null) {
            return true;
        }
        if (charSequence == null || charSequence2 == null) {
            return false;
        }
        return charSequence.equals(charSequence2);
    }
}