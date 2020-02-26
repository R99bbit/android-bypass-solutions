package a.b.a.h;

import a.b.a.c.a;
import a.b.a.f;
import a.b.a.g;
import android.app.AlarmManager;
import android.app.AlarmManager.AlarmClockInfo;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build.VERSION;
import androidx.core.app.NotificationCompat;
import com.embrain.panelpower.IConstValue.SavedMoney;
import com.loplat.placeengine.EventReceiver;
import com.loplat.placeengine.PlaceEngineBase;

/* compiled from: PlaceEngineTimer */
public class c {

    /* renamed from: a reason: collision with root package name */
    public static int f45a = 180901;

    public static void a(Context context, int i) {
        try {
            AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
            if (alarmManager != null) {
                PendingIntent broadcast = PendingIntent.getBroadcast(context, f45a, b(context), 268435456);
                long j = (long) i;
                long currentTimeMillis = System.currentTimeMillis() + j;
                if (VERSION.SDK_INT >= 23) {
                    if (VERSION.SDK_INT >= 26) {
                        if (a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) SavedMoney.GIVE_TP_GIFT_CARD_ONLINE, false)) {
                            alarmManager.setAlarmClock(new AlarmClockInfo(currentTimeMillis, null), broadcast);
                        }
                    }
                    alarmManager.setExactAndAllowWhileIdle(0, currentTimeMillis, broadcast);
                } else {
                    alarmManager.setRepeating(0, currentTimeMillis, j, broadcast);
                }
                StringBuilder sb = new StringBuilder();
                sb.append("setScanTimer: ");
                sb.append(i);
                sb.append(", sdk: ");
                sb.append(VERSION.SDK_INT);
                sb.toString();
            }
        } catch (Exception unused) {
        }
    }

    public static Intent b(Context context) {
        Intent intent = new Intent(PlaceEngineBase.ENGINE_EVENT_SCAN_WIFI);
        intent.setPackage(context.getPackageName());
        if (VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26) {
            intent.setClass(context, EventReceiver.class);
        }
        return intent;
    }

    public static void c(Context context) {
        int i;
        a(context);
        int h = a.b.a.g.a.h(context);
        if (h == 0) {
            if (f.f(context) == 2) {
                i = a.b.a.g.a.j(context);
            } else {
                i = a.b.a.g.a.i(context);
            }
        } else if (h != 1) {
            i = a.b.a.g.a.i(context);
        } else if (g.j(context) == 1) {
            i = a.b.a.g.a.l(context);
        } else {
            i = a.b.a.g.a.k(context);
        }
        a(context, i);
    }

    public static void a(Context context) {
        try {
            AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
            if (alarmManager != null) {
                PendingIntent broadcast = PendingIntent.getBroadcast(context, f45a, b(context), 536870912);
                if (broadcast != null) {
                    alarmManager.cancel(broadcast);
                    broadcast.cancel();
                }
            }
        } catch (Exception unused) {
        }
    }
}