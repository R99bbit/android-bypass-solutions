package com.loplat.placeengine.service;

import a.b.a.h.d;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.icu.text.SimpleDateFormat;
import android.os.Binder;
import android.os.Build;
import android.os.Build.VERSION;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.core.app.NotificationManagerCompat;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.wifi.WifiType;
import com.plengi.app.MainActivity;
import java.io.Serializable;
import java.lang.Thread.State;
import java.util.List;

@RequiresApi(api = 26)
public class ForegroundService extends Service {

    /* renamed from: a reason: collision with root package name */
    public static final String f56a = "ForegroundService";
    public static HandlerThread b = null;
    public static Handler c = null;
    public static ForegroundService d = null;
    public static boolean e = false;
    public static boolean f = false;
    public static ServiceConnection g = new g();
    public Context h;
    public boolean i = false;
    public int j = 0;
    public IBinder k = new a();

    class a extends Binder {
        public a() {
        }
    }

    public void c() {
        if (VERSION.SDK_INT < 28 || !this.i) {
            stopForeground(true);
            return;
        }
        stopForeground(false);
        if (this.j == 0) {
            NotificationManagerCompat.from(this.h).cancel(141224);
        } else {
            new Handler().postDelayed(new e(this), (long) this.j);
        }
        new Handler().postDelayed(new f(this), (long) (this.j + 70));
    }

    public IBinder onBind(Intent intent) {
        return this.k;
    }

    public void onCreate() {
        this.h = getApplicationContext();
        f = true;
        a.b.a.f.a.a(this.h);
        bindService(new Intent(getApplicationContext(), ForegroundService.class), g, 1);
        a();
        super.onCreate();
    }

    public void onDestroy() {
        d = null;
        if (e) {
            ServiceConnection serviceConnection = g;
            if (serviceConnection != null) {
                unbindService(serviceConnection);
                e = false;
            }
        }
        super.onDestroy();
    }

    public int onStartCommand(Intent intent, int i2, int i3) {
        b(intent);
        return 2;
    }

    public boolean onUnbind(Intent intent) {
        return super.onUnbind(intent);
    }

    @RequiresApi(26)
    public final void b(Intent intent) {
        if (f && intent != null && this.h.getPackageName().equals(intent.getPackage())) {
            HandlerThread handlerThread = b;
            if (handlerThread == null || handlerThread.getState() != State.RUNNABLE) {
                b = null;
                b = new HandlerThread("mForegroundThread");
                b.start();
                c = null;
            }
            if (c == null) {
                c = new Handler(b.getLooper());
            }
            c.post(new c(this, intent));
        }
    }

    public static void a(Context context, int i2) {
        Intent intent = new Intent(context, ForegroundService.class);
        intent.putExtra("engine_progress", i2);
        intent.setPackage(context.getPackageName());
        if (e) {
            a(intent);
        } else {
            context.startForegroundService(intent);
        }
    }

    public static void a(Context context, List<WifiType> list, int i2, @Nullable String str) {
        Intent intent = new Intent(context, ForegroundService.class);
        intent.putExtra("update_gps_progress", (Serializable) list);
        intent.putExtra("engine_progress_type", i2);
        if (str != null) {
            intent.putExtra("activity_recognition_log", str);
        }
        intent.setPackage(context.getPackageName());
        if (e) {
            a(intent);
        } else {
            context.startForegroundService(intent);
        }
    }

    public void b() {
        try {
            startForeground(141224, a.b.a.f.a.b(this.h));
        } catch (Exception unused) {
        }
    }

    public void a() {
        boolean z = false;
        try {
            String fgsNotiPatchedDate = PlaceEngineBase.getFgsNotiPatchedDate(this.h);
            if (fgsNotiPatchedDate == null || fgsNotiPatchedDate.isEmpty()) {
                if (Build.MANUFACTURER.equalsIgnoreCase("Google")) {
                    fgsNotiPatchedDate = "2019-12-05";
                }
            }
            if (fgsNotiPatchedDate != null) {
                if (!fgsNotiPatchedDate.isEmpty()) {
                    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
                    if (simpleDateFormat.parse(VERSION.SECURITY_PATCH).compareTo(simpleDateFormat.parse(fgsNotiPatchedDate)) >= 0) {
                        z = true;
                        this.j = PlaceEngineBase.getFgsStopFgDelay(this.h);
                    }
                }
            }
        } catch (Error | Exception unused) {
        } catch (Throwable th) {
            this.i = false;
            throw th;
        }
        this.i = z;
    }

    public static /* synthetic */ void a(ForegroundService foregroundService, int i2) {
        Context context = foregroundService.h;
        int i3 = VERSION.SDK_INT;
        if (i3 >= 23 && i3 <= 28 && PlaceEngineBase.isAvoidAppStandbyEnabled(context)) {
            a.b.a.h.d.a a2 = d.a(context);
            int i4 = a2.f46a;
            if (!(i4 == 5 || i4 == 10)) {
                StringBuilder a3 = a.a.a.a.a.a("previous standby bucket, index: ");
                a3.append(a2.f46a);
                a3.append(", state: ");
                a3.append(a2.b);
                a3.toString();
                Intent intent = new Intent(context, MainActivity.class);
                intent.setAction("com.loplat.placeengine.MAIN");
                intent.setFlags(1342177280);
                context.startActivity(intent);
            }
        }
        if (PlaceEngineBase.scanWiFi(foregroundService.h, i2) == 0) {
            String str = f56a;
            new Object[1][0] = "------> Request WiFi Scan";
        }
    }

    public final void a(List<WifiType> list, int i2, @Nullable String str) {
        String str2 = f56a;
        new Object[1][0] = "------> Request Update Gps";
        new a.b.a.d.d(this.h, i2, str, list).c();
    }

    public static void a(Intent intent) {
        ForegroundService foregroundService = d;
        if (foregroundService != null) {
            foregroundService.b(intent);
            return;
        }
        String str = f56a;
        new Object[1][0] = "fs is null";
    }
}