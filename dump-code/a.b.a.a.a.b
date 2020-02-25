package a.b.a.a.a;

import a.b.a.b.l;
import a.b.a.f;
import android.app.AlarmManager;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.media.RingtoneManager;
import android.os.Build.VERSION;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationCompat.BigTextStyle;
import androidx.core.app.NotificationCompat.Builder;
import com.google.gson.Gson;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.R;
import com.loplat.placeengine.cloud.RequestMessage;
import com.loplat.placeengine.cloud.ResponseMessage.Advertisement;
import com.loplat.placeengine.service.PeriodicJobService;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* compiled from: AdsProcess */
public class b {

    /* renamed from: a reason: collision with root package name */
    public static b f0a = null;
    public static final String b = "b";
    public Context c;
    public AlarmManager d;
    public a e = null;
    public boolean f = false;

    /* compiled from: AdsProcess */
    private class a extends BroadcastReceiver {
        public /* synthetic */ a(a aVar) {
        }

        public void onReceive(Context context, Intent intent) {
            Advertisement advertisement;
            if (intent != null) {
                String action = intent.getAction();
                if ("com.loplat.ad.noti.delete".equals(action)) {
                    l.a(context, intent.getIntExtra("msg_id", 0), 0);
                } else if ("com.loplat.ad.noti.pending".equals(action) && intent.hasExtra("campaign_id")) {
                    int intExtra = intent.getIntExtra("campaign_id", -1);
                    List<Advertisement> a2 = b.this.b();
                    Iterator it = a2.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            advertisement = null;
                            break;
                        }
                        advertisement = (Advertisement) it.next();
                        if (advertisement.getCampaign_id() == intExtra) {
                            ArrayList arrayList = new ArrayList();
                            for (Advertisement advertisement2 : a2) {
                                if (advertisement2.getCampaign_id() == intExtra) {
                                    arrayList.add(advertisement2);
                                }
                            }
                            if (arrayList.size() > 0) {
                                a2.removeAll(arrayList);
                                b.this.a(a2);
                            }
                        }
                    }
                    b.this.a(advertisement);
                }
            }
        }
    }

    public b(Context context) {
        this.c = context;
    }

    public final List<Advertisement> b() {
        ArrayList arrayList = new ArrayList();
        try {
            String a2 = a.b.a.c.a.a(this.c, (String) "lhtibaq5ot47p0xrinly", (String) "16", (String) "");
            return !a2.isEmpty() ? (List) new Gson().fromJson(a2, new a(this).getType()) : arrayList;
        } catch (Error | Exception unused) {
            return arrayList;
        }
    }

    public int c() {
        return a.b.a.c.a.a(this.c, (String) "lhtibaq5ot47p0xrinly", (String) "17", 17301576);
    }

    public void d() {
        Context context = this.c;
        if (context != null) {
            if (!l.a(context)) {
                a(null);
            } else if (!this.f) {
                this.f = true;
                a aVar = this.e;
                if (aVar != null) {
                    this.c.unregisterReceiver(aVar);
                    this.e = null;
                }
                List<Advertisement> b2 = b();
                ArrayList arrayList = new ArrayList();
                for (Advertisement next : b2) {
                    if (next.getTime() > 0) {
                        if (System.currentTimeMillis() > (next.getDelay() * 60000) + next.getTime()) {
                            a(next);
                            arrayList.add(next);
                        }
                    }
                }
                if (arrayList.size() > 0) {
                    b2.removeAll(arrayList);
                    a(b2);
                }
                this.e = new a(null);
                IntentFilter intentFilter = new IntentFilter();
                intentFilter.addAction("com.loplat.ad.noti.delete");
                intentFilter.addAction("com.loplat.ad.noti.pending");
                this.c.registerReceiver(this.e, intentFilter);
                this.d = (AlarmManager) this.c.getSystemService(NotificationCompat.CATEGORY_ALARM);
                if (l.b(this.c) && VERSION.SDK_INT >= 26 && a.b.a.g.a.m(this.c) >= 26) {
                    Context context2 = this.c;
                    int i = d.f3a;
                    if (i == 0) {
                        i = R.string.channel_name_ads;
                    }
                    NotificationChannel notificationChannel = new NotificationChannel("plengi_ads", context2.getString(i), 4);
                    int i2 = d.b;
                    if (i2 == 0) {
                        i2 = R.string.channel_description_ads;
                    }
                    notificationChannel.setDescription(context2.getString(i2));
                    notificationChannel.setLockscreenVisibility(1);
                    ((NotificationManager) context2.getSystemService("notification")).createNotificationChannel(notificationChannel);
                }
            }
        }
    }

    public void e() {
        if (this.c != null && this.f) {
            this.f = false;
            a(null);
            a aVar = this.e;
            if (aVar != null) {
                this.c.unregisterReceiver(aVar);
                this.e = null;
            }
            if (l.b(this.c) && VERSION.SDK_INT >= 26 && a.b.a.g.a.m(this.c) >= 26) {
                ((NotificationManager) this.c.getSystemService("notification")).deleteNotificationChannel("plengi_ads");
            }
        }
    }

    public static b a(Context context) {
        if (f0a == null) {
            f0a = new b(context);
        }
        return f0a;
    }

    public Bitmap a() {
        try {
            return BitmapFactory.decodeResource(this.c.getResources(), a.b.a.c.a.a(this.c, (String) "lhtibaq5ot47p0xrinly", (String) "18", 17301576));
        } catch (Exception unused) {
            return null;
        }
    }

    public void b(Advertisement advertisement) {
        int campaign_id = advertisement.getCampaign_id();
        String delay_type = advertisement.getDelay_type();
        long delay = advertisement.getDelay();
        if ("enter".equals(delay_type)) {
            if (delay == 0) {
                a(advertisement);
                return;
            }
            advertisement.setTime(System.currentTimeMillis());
            List<Advertisement> b2 = b();
            b2.add(advertisement);
            a(b2);
            a(campaign_id, delay * 60000);
        } else if (RequestMessage.LEAVE_PLACE.equals(delay_type)) {
            List<Advertisement> b3 = b();
            b3.add(advertisement);
            a(b3);
        }
    }

    public final void a(List<Advertisement> list) {
        String str;
        if (list != null) {
            try {
                if (list.size() > 0) {
                    str = new Gson().toJson((Object) list);
                    a.b.a.c.a.b(this.c, "lhtibaq5ot47p0xrinly", "16", str, false);
                }
            } catch (Error | Exception unused) {
                return;
            }
        }
        str = null;
        a.b.a.c.a.b(this.c, "lhtibaq5ot47p0xrinly", "16", str, false);
    }

    public final void a(Advertisement advertisement) {
        if (advertisement != null) {
            if (l.b(this.c)) {
                Context context = this.c;
                String alarm = advertisement.getAlarm();
                if ("noti".equals(alarm)) {
                    int msg_id = advertisement.getMsg_id();
                    int campaign_id = advertisement.getCampaign_id();
                    String title = advertisement.getTitle();
                    String body = advertisement.getBody();
                    Intent a2 = c.a(context, advertisement);
                    b a3 = a(context);
                    Builder contentIntent = new Builder(context, "plengi_ads").setPriority(1).setSound(RingtoneManager.getDefaultUri(2)).setAutoCancel(true).setSmallIcon(a3.c()).setLargeIcon(a3.a()).setContentTitle(title).setContentText(body).setContentIntent(PendingIntent.getActivity(context, advertisement.getCampaign_id(), a2, 134217728));
                    Intent intent = new Intent("com.loplat.ad.noti.delete");
                    intent.setPackage(context.getPackageName());
                    intent.putExtra("msg_id", msg_id);
                    contentIntent.setDeleteIntent(PendingIntent.getBroadcast(context, msg_id, intent, 268435456));
                    BigTextStyle bigTextStyle = new BigTextStyle(contentIntent);
                    bigTextStyle.setBigContentTitle(title);
                    bigTextStyle.bigText(body);
                    contentIntent.setStyle(bigTextStyle);
                    ((NotificationManager) context.getSystemService("notification")).notify(campaign_id, contentIntent.build());
                    c.a(context);
                } else if ("noti_big".equals(alarm)) {
                    new a(context, advertisement).execute(new String[0]);
                }
            }
            if (advertisement.getDelay() > 0) {
                PlengiResponse plengiResponse = new PlengiResponse(this.c);
                plengiResponse.type = f.a(a.b.a.g.a.h(this.c));
                plengiResponse.result = 0;
                plengiResponse.advertisement = advertisement;
                PlaceEngineBase.forwardMessageToClient(plengiResponse);
            }
        }
    }

    public final void a(int i, long j) {
        if (VERSION.SDK_INT < 26 || a.b.a.g.a.m(this.c) < 26) {
            try {
                if (this.d != null) {
                    Intent intent = new Intent("com.loplat.ad.noti.pending");
                    intent.setPackage(this.c.getPackageName());
                    intent.putExtra("campaign_id", i);
                    PendingIntent broadcast = PendingIntent.getBroadcast(this.c, i, intent, 268435456);
                    long currentTimeMillis = System.currentTimeMillis() + j;
                    if (VERSION.SDK_INT >= 23) {
                        this.d.setExactAndAllowWhileIdle(0, currentTimeMillis, broadcast);
                    } else {
                        this.d.set(0, currentTimeMillis, broadcast);
                    }
                }
            } catch (Exception unused) {
            }
        } else {
            PeriodicJobService.a(this.c, 181029, j);
        }
    }
}