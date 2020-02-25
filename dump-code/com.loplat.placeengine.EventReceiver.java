package com.loplat.placeengine;

import a.b.a.b.l;
import a.b.a.c.a;
import a.b.a.e.e;
import a.b.a.f;
import a.b.a.g;
import a.b.a.h;
import a.b.a.h.c;
import a.b.a.h.d;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.WifiManager;
import android.os.Build.VERSION;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.PowerManager;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.core.os.EnvironmentCompat;
import com.embrain.panelpower.IConstValue.SavedMoney;
import com.google.android.gms.location.ActivityTransitionResult;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.service.ForegroundService;
import com.loplat.placeengine.service.PeriodicJobService;
import com.loplat.placeengine.wifi.WifiScanManager;
import com.loplat.placeengine.wifi.WifiType;
import java.lang.Thread.State;
import java.util.List;

public class EventReceiver extends BroadcastReceiver {

    /* renamed from: a reason: collision with root package name */
    public static final String f52a = "EventReceiver";
    public static EventReceiver b;
    public static HandlerThread c;
    public static Handler d;

    @RequiresApi(api = 16)
    public void onReceive(Context context, Intent intent) {
        if (context != null && intent != null && intent.getAction() != null) {
            HandlerThread handlerThread = c;
            if (handlerThread == null || handlerThread.getState() != State.RUNNABLE) {
                c = null;
                c = new HandlerThread("mReceiverThread");
                c.start();
                d = null;
            }
            if (d == null) {
                d = new Handler(c.getLooper());
            }
            d.post(new b(this, context, intent));
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:318:0x0890, code lost:
        if (r15 != 5) goto L_0x08b8;
     */
    /* JADX WARNING: Removed duplicated region for block: B:165:0x02d2  */
    /* JADX WARNING: Removed duplicated region for block: B:312:0x0874  */
    /* JADX WARNING: Removed duplicated region for block: B:366:0x0982  */
    public final void a(@NonNull Context context, @NonNull String str, @NonNull Intent intent) {
        long j;
        Place n;
        List list;
        int i;
        List list2;
        int i2;
        h hVar;
        int i3;
        int i4;
        float f;
        int i5;
        boolean z;
        int i6;
        List list3;
        int i7;
        int i8;
        float f2;
        int i9;
        int i10;
        Context context2 = context;
        String str2 = str;
        Intent intent2 = intent;
        Context applicationContext = context.getApplicationContext();
        if (PlaceEngineBase.isPlaceEngineAvailable(context, str) || PlaceEngineBase.isPlaceEngineInProgress(context)) {
            String str3 = f52a;
            new Object[1][0] = str2;
            char c2 = 65535;
            switch (str.hashCode()) {
                case -2140526353:
                    if (str2.equals("com.loplat.placeengine.event.activity_recognition")) {
                        c2 = 10;
                        break;
                    }
                    break;
                case -2128145023:
                    if (str2.equals("android.intent.action.SCREEN_OFF")) {
                        c2 = 6;
                        break;
                    }
                    break;
                case -1886648615:
                    if (str2.equals("android.intent.action.ACTION_POWER_DISCONNECTED")) {
                        c2 = 8;
                        break;
                    }
                    break;
                case -1676458352:
                    if (str2.equals("android.intent.action.HEADSET_PLUG")) {
                        c2 = 7;
                        break;
                    }
                    break;
                case -1454123155:
                    if (str2.equals("android.intent.action.SCREEN_ON")) {
                        c2 = 5;
                        break;
                    }
                    break;
                case 495305082:
                    if (str2.equals(PlaceEngineBase.ENGINE_EVENT_SCAN_WIFI)) {
                        c2 = 1;
                        break;
                    }
                    break;
                case 798292259:
                    if (str2.equals("android.intent.action.BOOT_COMPLETED")) {
                        c2 = 0;
                        break;
                    }
                    break;
                case 823795052:
                    if (str2.equals("android.intent.action.USER_PRESENT")) {
                        c2 = 4;
                        break;
                    }
                    break;
                case 870701415:
                    if (str2.equals("android.os.action.DEVICE_IDLE_MODE_CHANGED")) {
                        c2 = 9;
                        break;
                    }
                    break;
                case 1035786382:
                    if (str2.equals("com.loplat.placeengine.testevent.SCAN_RESULTS")) {
                        c2 = 2;
                        break;
                    }
                    break;
                case 1580442797:
                    if (str2.equals("android.intent.action.PACKAGE_FULLY_REMOVED")) {
                        c2 = 11;
                        break;
                    }
                    break;
                case 1737074039:
                    if (str2.equals("android.intent.action.MY_PACKAGE_REPLACED")) {
                        c2 = 12;
                        break;
                    }
                    break;
                case 1878357501:
                    if (str2.equals("android.net.wifi.SCAN_RESULTS")) {
                        c2 = 3;
                        break;
                    }
                    break;
            }
            switch (c2) {
                case 0:
                    a.b(applicationContext).b();
                    a.b(applicationContext).e();
                    a.b(applicationContext).f();
                    a.b(applicationContext).c();
                    a.b(applicationContext).d();
                    int h = a.b.a.g.a.h(context);
                    if (h != 0) {
                        if (h == 1) {
                            g.c(context2, 0);
                            Place k = g.k(context);
                            if (k != null) {
                                j = 0;
                                k.setDuration_time(0);
                                g.d(context2, k);
                            } else {
                                j = 0;
                            }
                            int j2 = g.j(context);
                            if (j2 == 1 || j2 == 2) {
                                g.b(context2, j);
                            }
                            n = a.b(context).n();
                            if (n != null) {
                                n.setDuration_time(j);
                                a.b(context).c(n);
                                break;
                            }
                        }
                    } else {
                        f.a(context2, 0);
                    }
                    j = 0;
                    n = a.b(context).n();
                    if (n != null) {
                    }
                    break;
                case 1:
                    if (context.getPackageName().equals(intent.getPackage())) {
                        if (2 != PlaceEngineBase.getEngineStatus(applicationContext)) {
                            PlaceEngineBase.startWiFiScan(applicationContext, 3);
                            break;
                        } else {
                            PlaceEngineBase.checkForceStopConfig(applicationContext);
                            break;
                        }
                    }
                    break;
                case 2:
                case 3:
                    int engineInProgress = PlaceEngineBase.getEngineInProgress(context);
                    PlaceEngineBase.clearEngineInProgress(context);
                    if ("com.loplat.placeengine.testevent.SCAN_RESULTS".equals(str2)) {
                        if (context.getPackageName().equals(intent.getPackage())) {
                            a.b(context).b();
                            list = intent2.getParcelableArrayListExtra("scan_result");
                            i = 3;
                            if (list != null) {
                                if (PlaceEngineBase.isPlaceEngineStarted(applicationContext)) {
                                    hVar = new h(list.size());
                                    int h2 = a.b.a.g.a.h(context);
                                    float f3 = 0.05f;
                                    if (h2 == 1) {
                                        if (!f.a(applicationContext, 1, g.j(applicationContext), i)) {
                                            hVar.f42a = 1;
                                        } else {
                                            hVar = WifiScanManager.a(applicationContext, hVar, list);
                                            if (hVar.a()) {
                                                if (a.b(applicationContext).q() > 0) {
                                                    long currentTimeMillis = System.currentTimeMillis();
                                                    StringBuilder a2 = a.a.a.a.a.a("\uc74c\uc601\uc9c0\uc5ed \ubc97\uc5b4\ub0a8 - ");
                                                    a2.append(d.a(currentTimeMillis));
                                                    a2.toString();
                                                    a.b(applicationContext).f();
                                                }
                                                List<WifiType> list4 = hVar.c;
                                                int i11 = hVar.b;
                                                int j3 = g.j(applicationContext);
                                                String str4 = j3 != 1 ? j3 != 2 ? j3 != 3 ? j3 != 4 ? "MOVE" : "STATIONARY_CHECK" : "PREMIUM" : "PLACE(STAY)" : "STATIONARY";
                                                if (list4 != null) {
                                                    StringBuilder sb = new StringBuilder();
                                                    sb.append("----Tracker Status: ");
                                                    sb.append(str4);
                                                    sb.append(", scan size: ");
                                                    sb.append(list4.size());
                                                    sb.toString();
                                                    StringBuilder sb2 = new StringBuilder();
                                                    sb2.append("----Tracker Status: ");
                                                    sb2.append(str4);
                                                    sb2.append(", original scan size: ");
                                                    sb2.append(i11);
                                                    sb2.toString();
                                                }
                                                a.b(applicationContext).a(SystemClock.elapsedRealtime());
                                                Place k2 = g.k(applicationContext);
                                                StringBuilder a3 = a.a.a.a.a.a("check unknown place ---------------:");
                                                a3.append(k2 != null ? EnvironmentCompat.MEDIA_UNKNOWN : "empty");
                                                a3.toString();
                                                if (k2 != null) {
                                                    List<WifiType> a4 = a.b(applicationContext).a((String) "unknown_place_footprint");
                                                    StringBuilder a5 = a.a.a.a.a.a("unknown place footprint size: ");
                                                    a5.append(a4.size());
                                                    a5.toString();
                                                    if (!a4.isEmpty()) {
                                                        float a6 = a.b.a.i.a.a(list4, a4);
                                                        StringBuilder sb3 = new StringBuilder();
                                                        sb3.append("compared wifi scans: ");
                                                        sb3.append(a6);
                                                        sb3.append("/");
                                                        sb3.append(0.05f);
                                                        sb3.toString();
                                                        if (a6 < 0.05f) {
                                                            g.c(applicationContext, k2);
                                                        } else {
                                                            f.a(applicationContext, 1, k2);
                                                        }
                                                    }
                                                }
                                                if (j3 != 0) {
                                                    if (j3 != 1) {
                                                        if (j3 == 2) {
                                                            float a7 = a.b.a.i.a.a(list4, f.e(applicationContext));
                                                            float b2 = g.b(applicationContext, 2);
                                                            StringBuilder sb4 = new StringBuilder();
                                                            sb4.append(a7);
                                                            sb4.append("/");
                                                            sb4.append(b2);
                                                            sb4.toString();
                                                            StringBuilder sb5 = new StringBuilder();
                                                            sb5.append("[TRACKER] place: ");
                                                            sb5.append(a7);
                                                            sb5.append("/");
                                                            sb5.append(b2);
                                                            sb5.toString();
                                                            if (a7 <= b2) {
                                                                l.a(applicationContext, list4, true, i);
                                                            }
                                                        } else if (j3 != 3) {
                                                            if (j3 == 4) {
                                                                g.c(applicationContext, 1);
                                                            }
                                                        }
                                                    }
                                                    float a8 = a.b.a.i.a.a(list4, f.e(applicationContext));
                                                    float b3 = g.b(applicationContext, 1);
                                                    StringBuilder sb6 = new StringBuilder();
                                                    sb6.append(a8);
                                                    sb6.append("/");
                                                    sb6.append(b3);
                                                    sb6.toString();
                                                    StringBuilder sb7 = new StringBuilder();
                                                    sb7.append("[TRACKER] stationary: ");
                                                    sb7.append(a8);
                                                    sb7.append("/");
                                                    sb7.append(b3);
                                                    sb7.toString();
                                                    if (a8 <= b3) {
                                                        g.c(applicationContext, 0);
                                                        if (a8 < 0.05f) {
                                                            l.a(applicationContext, list4, true, i);
                                                        }
                                                    }
                                                } else {
                                                    List<WifiType> storedScan = WifiScanManager.getStoredScan(applicationContext);
                                                    int a9 = WifiScanManager.a(applicationContext);
                                                    float a10 = a.b.a.i.a.a(list4, storedScan);
                                                    int max = Math.max(i11, a9);
                                                    if (max < 80) {
                                                        f3 = 0.2f;
                                                    } else if (max < 400) {
                                                        f3 = ((((float) (max - 80)) * -0.15f) / ((float) 320)) + 0.2f;
                                                    }
                                                    StringBuilder sb8 = new StringBuilder();
                                                    sb8.append("previousWifiSize=");
                                                    sb8.append(a9);
                                                    sb8.append(", currentWifiSize=");
                                                    sb8.append(i11);
                                                    sb8.append(", similarity=");
                                                    sb8.append(a10);
                                                    sb8.append(", threshold=");
                                                    sb8.append(f3);
                                                    sb8.toString();
                                                    if (a10 >= f3) {
                                                        g.c(applicationContext, 4);
                                                        l.a(applicationContext, list4, true, i);
                                                    }
                                                }
                                                WifiScanManager.a(applicationContext, i11, list4);
                                                hVar.f42a = 3;
                                            } else if (hVar.f42a != 0) {
                                                hVar.f42a = 2;
                                                if (!list.isEmpty()) {
                                                    StringBuilder a11 = a.a.a.a.a.a("processWifiScan - INVALID_SCAN_RESULTS\n");
                                                    a11.append(list.toString());
                                                    a11.toString();
                                                }
                                                if (a.b(applicationContext).q() == 0) {
                                                    long currentTimeMillis2 = System.currentTimeMillis();
                                                    int size = list.size();
                                                    StringBuilder a12 = a.a.a.a.a.a("\uc74c\uc601\uc9c0\uc5ed \uc9c4\uc785\ud568 - ");
                                                    a12.append(d.a(currentTimeMillis2));
                                                    a12.append(" (Original Count = ");
                                                    a12.append(size);
                                                    a12.append(")");
                                                    a12.toString();
                                                    a.b(applicationContext).d(System.currentTimeMillis());
                                                }
                                                if (PlaceEngineBase.isActivityRecognitionEnabled(applicationContext) && e.c != null) {
                                                    e.a(applicationContext).a(e.c);
                                                }
                                            }
                                        }
                                    } else if (h2 == 0) {
                                        if (!f.a(applicationContext, 0, f.f(applicationContext), i)) {
                                            hVar.f42a = 1;
                                        } else {
                                            h a13 = WifiScanManager.a(applicationContext, hVar, list);
                                            if (!a13.a()) {
                                                if (a13.f42a != 0) {
                                                    a13.f42a = 2;
                                                    if (a.b(applicationContext).q() == 0) {
                                                        long currentTimeMillis3 = System.currentTimeMillis();
                                                        int size2 = list.size();
                                                        StringBuilder a14 = a.a.a.a.a.a("\uc74c\uc601\uc9c0\uc5ed \uc9c4\uc785\ud568 - ");
                                                        a14.append(d.a(currentTimeMillis3));
                                                        a14.append(" (Original Count = ");
                                                        a14.append(size2);
                                                        a14.append(")");
                                                        a14.toString();
                                                        a.b(applicationContext).d(System.currentTimeMillis());
                                                    }
                                                    if (PlaceEngineBase.isActivityRecognitionEnabled(applicationContext) && e.c != null) {
                                                        e.a(applicationContext).a(e.c);
                                                    }
                                                }
                                                i2 = i;
                                                list2 = list;
                                            } else {
                                                if (a.b(applicationContext).q() > 0) {
                                                    long currentTimeMillis4 = System.currentTimeMillis();
                                                    StringBuilder a15 = a.a.a.a.a.a("\uc74c\uc601\uc9c0\uc5ed \ubc97\uc5b4\ub0a8 - ");
                                                    a15.append(d.a(currentTimeMillis4));
                                                    a15.toString();
                                                    a.b(applicationContext).f();
                                                }
                                                List<WifiType> list5 = a13.c;
                                                int i12 = a13.b;
                                                int f4 = f.f(applicationContext);
                                                if (list5 != null) {
                                                    StringBuilder sb9 = new StringBuilder();
                                                    sb9.append("----Place Status: ");
                                                    sb9.append(f4);
                                                    sb9.append(", scan size: ");
                                                    sb9.append(list5.size());
                                                    sb9.toString();
                                                }
                                                long elapsedRealtime = SystemClock.elapsedRealtime();
                                                a.b(applicationContext).a(elapsedRealtime);
                                                float f5 = a13.d;
                                                List list6 = list;
                                                float a16 = a.b.a.g.a.a(f5);
                                                if (f4 != 0) {
                                                    if (f4 == 1) {
                                                        i6 = f4;
                                                        float a17 = a.b.a.i.a.a(list5, WifiScanManager.getStoredScan(applicationContext));
                                                        StringBuilder sb10 = new StringBuilder();
                                                        sb10.append("STATIONARY similarity: ");
                                                        sb10.append(a17);
                                                        sb10.append(", energy: ");
                                                        sb10.append(f5);
                                                        sb10.append(", threshold: ");
                                                        sb10.append(a16);
                                                        sb10.toString();
                                                        StringBuilder sb11 = new StringBuilder();
                                                        sb11.append(a17);
                                                        sb11.append("/");
                                                        sb11.append(a16);
                                                        sb11.toString();
                                                        if (a17 >= a16) {
                                                            long g = elapsedRealtime - f.g(applicationContext);
                                                            StringBuilder sb12 = new StringBuilder();
                                                            sb12.append("time diff: ");
                                                            sb12.append(g);
                                                            sb12.toString();
                                                            i5 = g > 120000 ? 2 : 1;
                                                            list2 = list6;
                                                            i3 = i12;
                                                            i2 = i;
                                                            f = a16;
                                                            i4 = i6;
                                                            if (i4 != i5) {
                                                            }
                                                            WifiScanManager.a(applicationContext, i3, list5);
                                                            a13.f42a = 3;
                                                        }
                                                    } else if (f4 != 2) {
                                                        if (f4 == 3) {
                                                            float a18 = a.b.a.i.a.a(list5, f.e(applicationContext));
                                                            float a19 = ((a.b.a.g.a.a(a.b.a.g.a.a(list5)) * 0.6f) + (a.a(applicationContext, (String) "lhtibaq5ot47p0xrinly", (String) "13", 0.4f) * 0.4f)) * 0.9f;
                                                            String d2 = a.b.a.g.a.d(applicationContext);
                                                            StringBuilder sb13 = new StringBuilder();
                                                            i6 = f4;
                                                            sb13.append("STAY similarity: ");
                                                            sb13.append(a18);
                                                            sb13.append(", energy: ");
                                                            sb13.append(f5);
                                                            sb13.append(", dynamic_threshold: ");
                                                            sb13.append(a19);
                                                            sb13.append(", client_code: ");
                                                            sb13.append(d2);
                                                            sb13.toString();
                                                            StringBuilder sb14 = new StringBuilder();
                                                            sb14.append(a18);
                                                            sb14.append("/");
                                                            sb14.append(a19);
                                                            sb14.append(", ");
                                                            sb14.append(d2);
                                                            sb14.toString();
                                                            if (a18 < a19) {
                                                                if (a.b.a.g.a.d(applicationContext) != null && a18 > 0.05f) {
                                                                    l.a(applicationContext, list5, true, i);
                                                                    list2 = list6;
                                                                    i3 = i12;
                                                                    i2 = i;
                                                                    f = a16;
                                                                    i4 = i6;
                                                                }
                                                            }
                                                            list2 = list6;
                                                            i3 = i12;
                                                            i2 = i;
                                                            f = a16;
                                                            i4 = i6;
                                                            i5 = 2;
                                                            if (i4 != i5) {
                                                            }
                                                            WifiScanManager.a(applicationContext, i3, list5);
                                                            a13.f42a = 3;
                                                        } else if (f4 == 4) {
                                                            i6 = f4;
                                                        } else if (f4 != 5) {
                                                            list3 = list6;
                                                            i9 = f4;
                                                            i7 = i12;
                                                            i8 = i;
                                                            f2 = a16;
                                                            i5 = i4;
                                                            if (i4 != i5) {
                                                                StringBuilder sb15 = new StringBuilder();
                                                                sb15.append("--- PlaceStatus Changed to --> ");
                                                                sb15.append(i5);
                                                                sb15.toString();
                                                                f.a(applicationContext, i5);
                                                                if (i5 == 2) {
                                                                    if (i4 != 0) {
                                                                        z = true;
                                                                        if (i4 != 1) {
                                                                            break;
                                                                        }
                                                                    } else {
                                                                        z = true;
                                                                    }
                                                                    f.a(applicationContext, list5);
                                                                    f.a(applicationContext, 0);
                                                                    a.a(applicationContext, (String) "lhtibaq5ot47p0xrinly", (String) "13", f, z);
                                                                    Place place = new Place();
                                                                    place.setLoplatid(0);
                                                                    place.setName(EnvironmentCompat.MEDIA_UNKNOWN);
                                                                    a.b(applicationContext).c(place);
                                                                    l.a(applicationContext, list5, z, i2);
                                                                }
                                                                if (i5 == 0 && (i4 == 2 || i4 == 3 || i4 == 4)) {
                                                                    f.h(applicationContext);
                                                                    f.a(applicationContext, list5);
                                                                    l.a(applicationContext, list5, true, i2);
                                                                }
                                                            }
                                                            WifiScanManager.a(applicationContext, i3, list5);
                                                            a13.f42a = 3;
                                                        } else {
                                                            float a20 = a.b.a.i.a.a(list5, WifiScanManager.getStoredScan(applicationContext));
                                                            StringBuilder sb16 = new StringBuilder();
                                                            sb16.append("RECOGNIZER_LEAVING_STATIONARY similarity: ");
                                                            sb16.append(a20);
                                                            sb16.append(", energy: ");
                                                            sb16.append(f5);
                                                            sb16.append(", threshold: ");
                                                            sb16.append(a16);
                                                            sb16.toString();
                                                            StringBuilder sb17 = new StringBuilder();
                                                            sb17.append(a20);
                                                            sb17.append("/");
                                                            sb17.append(a16);
                                                            sb17.toString();
                                                            if (a20 >= a16) {
                                                                i6 = f4;
                                                                list2 = list6;
                                                                i3 = i12;
                                                                i2 = i;
                                                                f = a16;
                                                                i4 = i6;
                                                                i5 = 2;
                                                                if (i4 != i5) {
                                                                }
                                                                WifiScanManager.a(applicationContext, i3, list5);
                                                                a13.f42a = 3;
                                                            } else {
                                                                l.a(applicationContext, list5, true, i);
                                                                list2 = list6;
                                                                i4 = f4;
                                                                i3 = i12;
                                                                i2 = i;
                                                                f = a16;
                                                            }
                                                        }
                                                        i5 = 4;
                                                        if (i4 != i5) {
                                                        }
                                                        WifiScanManager.a(applicationContext, i3, list5);
                                                        a13.f42a = 3;
                                                    } else {
                                                        i6 = f4;
                                                        float a21 = a.b.a.i.a.a(list5, f.e(applicationContext));
                                                        float a22 = (0.6f * a16) + (a.a(applicationContext, (String) "lhtibaq5ot47p0xrinly", (String) "13", 0.4f) * 0.4f);
                                                        StringBuilder sb18 = new StringBuilder();
                                                        sb18.append("STAY similarity: ");
                                                        sb18.append(a21);
                                                        sb18.append(", energy: ");
                                                        sb18.append(f5);
                                                        sb18.append(", dynamic_threshold: ");
                                                        sb18.append(a22);
                                                        sb18.toString();
                                                        StringBuilder sb19 = new StringBuilder();
                                                        sb19.append(a21);
                                                        sb19.append("/");
                                                        sb19.append(a22);
                                                        sb19.toString();
                                                        if (a21 < a22) {
                                                            if (a21 >= 0.05f) {
                                                                PlaceEngineBase.startWiFiScan(applicationContext, 3);
                                                                list2 = list6;
                                                                i3 = i12;
                                                                i2 = i;
                                                                f = a16;
                                                                i4 = i6;
                                                                i5 = 3;
                                                                if (i4 != i5) {
                                                                }
                                                                WifiScanManager.a(applicationContext, i3, list5);
                                                                a13.f42a = 3;
                                                            }
                                                        }
                                                    }
                                                    list2 = list6;
                                                    i3 = i12;
                                                    i2 = i;
                                                    f = a16;
                                                    i4 = i6;
                                                    i5 = 0;
                                                    if (i4 != i5) {
                                                    }
                                                    WifiScanManager.a(applicationContext, i3, list5);
                                                    a13.f42a = 3;
                                                } else {
                                                    i6 = f4;
                                                    float a23 = a.b.a.i.a.a(list5, WifiScanManager.getStoredScan(applicationContext));
                                                    StringBuilder sb20 = new StringBuilder();
                                                    sb20.append("MOVE similarity: ");
                                                    sb20.append(a23);
                                                    sb20.append(", energy: ");
                                                    sb20.append(f5);
                                                    sb20.append(", threshold: ");
                                                    sb20.append(a16);
                                                    sb20.toString();
                                                    StringBuilder sb21 = new StringBuilder();
                                                    sb21.append(a23);
                                                    sb21.append("/");
                                                    sb21.append(a16);
                                                    sb21.toString();
                                                    if (a23 >= a16) {
                                                        if (((double) a23) >= 0.8d) {
                                                            StringBuilder sb22 = new StringBuilder();
                                                            sb22.append("MOVE ---> STAY: similarity=");
                                                            sb22.append(a23);
                                                            sb22.toString();
                                                            i10 = 2;
                                                        } else {
                                                            i10 = 1;
                                                        }
                                                        i4 = i6;
                                                        i3 = i12;
                                                        int i13 = i10;
                                                        i2 = i;
                                                        long j4 = elapsedRealtime;
                                                        list2 = list6;
                                                        f = a16;
                                                        a.a(applicationContext, (String) "lhtibaq5ot47p0xrinly", (String) SavedMoney.GIVE_TP_GIFT_CARD_MOBILE, j4, true);
                                                        i5 = i13;
                                                        if (i4 != i5) {
                                                        }
                                                        WifiScanManager.a(applicationContext, i3, list5);
                                                        a13.f42a = 3;
                                                    }
                                                }
                                                list3 = list6;
                                                i7 = i12;
                                                i8 = i;
                                                f2 = a16;
                                                i9 = i6;
                                                i5 = i4;
                                                if (i4 != i5) {
                                                }
                                                WifiScanManager.a(applicationContext, i3, list5);
                                                a13.f42a = 3;
                                            }
                                            hVar = a13;
                                        }
                                    }
                                    i2 = i;
                                    list2 = list;
                                } else {
                                    i2 = i;
                                    list2 = list;
                                    hVar = null;
                                }
                                if (f.b(i2)) {
                                    if (hVar == null) {
                                        hVar = PlaceEngineBase.processWifiScanIfNeeded(applicationContext, new h(list2.size()), list2);
                                    }
                                    PlaceEngineBase.postProcessingWifiScan(applicationContext, i2, hVar);
                                }
                                if (PlaceEngineBase.isPlaceEngineStarted(context) && hVar != null && hVar.f42a > 1) {
                                    c.c(context);
                                    break;
                                }
                            }
                        }
                    } else if ("android.net.wifi.SCAN_RESULTS".equals(str2)) {
                        if (intent2.getBooleanExtra("resultsUpdated", true)) {
                            if (VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26) {
                                PeriodicJobService.a(applicationContext);
                            }
                            if (a.b.a.g.a.q(applicationContext)) {
                                a.b.a.e.f.a(applicationContext).a(1);
                                if (!PlaceEngineBase.isBackground() || !PlaceEngineBase.isBackgroundWifiScanNotAllowed(context)) {
                                    if (VERSION.SDK_INT < 29 || f.b(engineInProgress) || !PlaceEngineBase.isBackground() || context2.checkSelfPermission("android.permission.ACCESS_BACKGROUND_LOCATION") == 0) {
                                        try {
                                            WifiManager wifiManager = (WifiManager) applicationContext.getSystemService("wifi");
                                            if (wifiManager != null) {
                                                list = wifiManager.getScanResults();
                                            }
                                        } catch (Exception unused) {
                                        }
                                    } else {
                                        ForegroundService foregroundService = ForegroundService.d;
                                        if (foregroundService != null) {
                                            foregroundService.b();
                                            try {
                                                WifiManager wifiManager2 = (WifiManager) foregroundService.h.getSystemService("wifi");
                                                List scanResults = wifiManager2 != null ? wifiManager2.getScanResults() : null;
                                                foregroundService.c();
                                                if (VERSION.SDK_INT >= 28) {
                                                    new Handler().postDelayed(new a.b.a.f.d(foregroundService), 1000);
                                                }
                                                list = scanResults;
                                            } catch (Error unused2) {
                                                foregroundService.c();
                                                if (VERSION.SDK_INT >= 28) {
                                                    new Handler().postDelayed(new a.b.a.f.d(foregroundService), 1000);
                                                }
                                            } catch (Exception unused3) {
                                                foregroundService.c();
                                                if (VERSION.SDK_INT >= 28) {
                                                    new Handler().postDelayed(new a.b.a.f.d(foregroundService), 1000);
                                                }
                                            } catch (Throwable unused4) {
                                                foregroundService.c();
                                                if (VERSION.SDK_INT >= 28) {
                                                    new Handler().postDelayed(new a.b.a.f.d(foregroundService), 1000);
                                                }
                                            }
                                        }
                                    }
                                    i = engineInProgress;
                                    if (list != null) {
                                    }
                                }
                            } else {
                                a.b.a.e.f.a(applicationContext).a(2);
                                if ((VERSION.SDK_INT <= 26 ? a.b.a.g.a.e(context) : null) == null) {
                                    f.c(applicationContext);
                                }
                            }
                        }
                    }
                    i = engineInProgress;
                    list = null;
                    if (list != null) {
                    }
                    break;
                case 4:
                    if (!a.b.a.g.a.o(applicationContext) && PlaceEngineBase.isPlaceEngineStarted(context) && PlaceEngineBase.isUnlockScreenScanEnabled(context)) {
                        a.b.a.e.f.a(applicationContext).b();
                        break;
                    }
                case 5:
                    a.b.a.e.f.a(applicationContext).a(true);
                    if (VERSION.SDK_INT >= 28 && ForegroundService.e) {
                        ForegroundService foregroundService2 = ForegroundService.d;
                        if (foregroundService2 != null) {
                            foregroundService2.c();
                        } else {
                            String str5 = ForegroundService.f56a;
                            new Object[1][0] = "fs is null";
                        }
                    }
                    if (a.b.a.e.f.a(applicationContext).a()) {
                        f.i(context);
                        break;
                    }
                    break;
                case 6:
                    a.b.a.e.f.a(applicationContext).a(false);
                    break;
                case 7:
                    if (intent2.getIntExtra("state", -1) == 1) {
                        f.i(context);
                        break;
                    }
                    break;
                case 8:
                    f.i(context);
                    break;
                case 9:
                    if (VERSION.SDK_INT >= 23 && PlaceEngineBase.isAvoidDozeEnabled(context)) {
                        PowerManager powerManager = (PowerManager) context2.getSystemService("power");
                        if (powerManager != null) {
                            boolean isDeviceIdleMode = powerManager.isDeviceIdleMode();
                            if (isDeviceIdleMode != a.a(context2, (String) "lhtibaq5ot47p0xrinly", (String) SavedMoney.GIVE_TP_GIFT_CARD_ONLINE, false)) {
                                a.a(context2, (String) "lhtibaq5ot47p0xrinly", (String) SavedMoney.GIVE_TP_GIFT_CARD_ONLINE, isDeviceIdleMode, true);
                                c.c(context);
                                break;
                            }
                        }
                    }
                    break;
                case 10:
                    ActivityTransitionResult extractResult = ActivityTransitionResult.extractResult(intent);
                    if (extractResult != null) {
                        e.a(applicationContext).a(extractResult.getTransitionEvents());
                        break;
                    }
                    break;
                case 11:
                    intent.getData();
                    break;
                case 12:
                    if (VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26) {
                        StringBuilder a24 = a.a.a.a.a.a("update my app, package name: ");
                        a24.append(context.getPackageName());
                        a24.toString();
                        PeriodicJobService.b(context);
                        break;
                    }
            }
            return;
        }
        String str6 = f52a;
        new Object[1][0] = "PlaceEngine is stopped";
        if (PlaceEngineBase.getEngineStatus(applicationContext) != 2 && context.getPackageName().equals(intent.getPackage())) {
            c.a(context);
        }
    }

    public static void a(Context context) {
        if (b == null) {
            try {
                int engineStatus = PlaceEngineBase.getEngineStatus(context);
                if (engineStatus == 1 || engineStatus == 2) {
                    if (VERSION.SDK_INT >= 26) {
                        if (a.b.a.g.a.m(context) >= 26) {
                            b = new EventReceiver();
                            IntentFilter intentFilter = new IntentFilter();
                            intentFilter.addAction(PlaceEngineBase.ENGINE_EVENT_SCAN_WIFI);
                            intentFilter.addAction("android.net.wifi.SCAN_RESULTS");
                            intentFilter.addAction("android.intent.action.USER_PRESENT");
                            intentFilter.addAction("android.intent.action.SCREEN_ON");
                            intentFilter.addAction("android.intent.action.SCREEN_OFF");
                            intentFilter.addAction("android.intent.action.HEADSET_PLUG");
                            intentFilter.addAction("com.loplat.placeengine.event.activity_recognition");
                            intentFilter.addAction("android.intent.action.ACTION_POWER_DISCONNECTED");
                            intentFilter.addAction("android.os.action.DEVICE_IDLE_MODE_CHANGED");
                            context.registerReceiver(b, intentFilter);
                            EventReceiver eventReceiver = b;
                        }
                    }
                    if (VERSION.SDK_INT >= 23) {
                        b = new EventReceiver();
                        IntentFilter intentFilter2 = new IntentFilter();
                        intentFilter2.addAction("android.intent.action.SCREEN_ON");
                        intentFilter2.addAction("android.os.action.DEVICE_IDLE_MODE_CHANGED");
                        context.registerReceiver(b, intentFilter2);
                    }
                    EventReceiver eventReceiver2 = b;
                } else if (VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26) {
                    b = new EventReceiver();
                    IntentFilter intentFilter3 = new IntentFilter();
                    intentFilter3.addAction("android.net.wifi.SCAN_RESULTS");
                    context.registerReceiver(b, intentFilter3);
                }
            } catch (Error | Exception unused) {
            }
        }
    }
}