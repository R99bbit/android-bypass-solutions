package com.loplat.placeengine.wifi;

import a.b.a.f;
import a.b.a.g;
import a.b.a.h;
import android.content.Context;
import android.net.wifi.ScanResult;
import android.os.Build.VERSION;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

public class WifiScanManager {

    /* renamed from: a reason: collision with root package name */
    public static long f60a = 15000;
    public static Pattern b = Pattern.compile("(.*i((phone)|(mac)|(pad)|(road_)).*|.*android.*|.*macbook.*|.*((olleh)|_|(kt))egg.*|.*egg_.*|.*wibro.*|.*u\\+ router.*|.*lgu\\+\\-.*|.*skt_4g_lte_bridge.*|.*g flex.*|.*galaxy.*|.*g[3456]_.*|.*vivo x.*|.*huawei.*|.*v[123]0_.*|.*roamingman.*|.*skyroam.*|.*janus_bb.*|.*smartfine.*|.*gnet_bb_gi.*|.*mb wlan.*|.*audi_mmi.*|.*smartfiat.*|.*rtl8186-default.*|.*portable.*|.*mobile ?hotspot.*|.*pocket.*|.*50[12]hwa.*|.*30((3zt)|(4zta)|(5zta)).*|.*203z.*|.*hwd1[15].*|.*ots00.*|.*((etourwi)|(mew)|(mi)|(roamwi))fi.*|.*glocalme.*)");
    public static int c = 80;
    public static final Comparator<a> d = new b();

    private static final class a {

        /* renamed from: a reason: collision with root package name */
        public String f61a;
        public String b;
        public int c;
        public int d;

        public a(String str, String str2, int i, int i2, long j) {
            this.f61a = str;
            this.b = str2;
            this.c = i;
            this.d = i2;
        }
    }

    static {
        Pattern.compile("(.*cvs4u.*|.*skp_4e21.*|.*ministop.*|.*withme.*|.*korea7.*|.*ofc_wlan.*)");
    }

    /* JADX WARNING: Removed duplicated region for block: B:14:0x0041  */
    /* JADX WARNING: Removed duplicated region for block: B:41:0x00c2 A[ADDED_TO_REGION] */
    /* JADX WARNING: Removed duplicated region for block: B:46:0x00ee  */
    /* JADX WARNING: Removed duplicated region for block: B:50:0x0103  */
    /* JADX WARNING: Removed duplicated region for block: B:59:0x012a  */
    /* JADX WARNING: Removed duplicated region for block: B:73:0x00fd A[SYNTHETIC] */
    public static h a(Context context, @NonNull List<ScanResult> list, h hVar) {
        ArrayList arrayList;
        ArrayList<a> arrayList2;
        int size;
        int i;
        boolean z;
        boolean z2;
        int i2;
        boolean z3;
        long j;
        h hVar2 = hVar;
        long elapsedRealtime = SystemClock.elapsedRealtime();
        long j2 = f60a;
        if (a.b.a.g.a.h(context) == 0) {
            if (f.f(context) == 2) {
                j = f60a;
            }
            arrayList = new ArrayList();
            arrayList2 = new ArrayList<>();
            int i3 = 0;
            for (ScanResult next : list) {
                if (next.level >= -90) {
                    Iterator it = arrayList2.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            z2 = false;
                            break;
                        }
                        a aVar = (a) it.next();
                        if (aVar.f61a.equals(next.BSSID) && aVar.d / 1000 == next.frequency / 1000) {
                            z2 = true;
                            break;
                        }
                    }
                    long j3 = VERSION.SDK_INT > 16 ? next.timestamp : 0;
                    if (j3 <= 0 || elapsedRealtime - (j3 / 1000) <= j2) {
                        i2 = i3;
                        z3 = false;
                    } else {
                        i2 = i3 + 1;
                        z3 = true;
                    }
                    if (!z2 && !z3) {
                        a aVar2 = new a(next.BSSID, next.SSID, next.level, next.frequency, j3);
                        arrayList2.add(aVar2);
                    }
                    i3 = i2;
                }
            }
            list.clear();
            if (arrayList2.size() == 0 || i3 <= 0) {
                Collections.sort(arrayList2, d);
                size = arrayList2.size();
                i = c;
                if (size > i) {
                    arrayList2.subList(i, arrayList2.size()).clear();
                }
                for (a aVar3 : arrayList2) {
                    String str = aVar3.b;
                    if (str != null && !str.isEmpty()) {
                        if (b.matcher(aVar3.b.toLowerCase()).matches()) {
                            z = true;
                            if (z) {
                                arrayList.add(new WifiType(aVar3.f61a, aVar3.b, aVar3.c, aVar3.d));
                            }
                        }
                    }
                    z = false;
                    if (z) {
                    }
                }
                arrayList2.clear();
                StringBuilder sb = new StringBuilder();
                sb.append("scan result after filtering and sorting: ");
                sb.append(arrayList.toString());
                sb.toString();
                hVar2.c = arrayList;
                hVar2.d = a.b.a.g.a.a(hVar2.c);
                return hVar2;
            }
            hVar2.c = arrayList;
            hVar2.d = a.b.a.g.a.a(hVar2.c);
            hVar2.f42a = 0;
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Scan Time Out: ");
            sb2.append(i3);
            sb2.toString();
            return hVar2;
        }
        if (g.j(context) == 1 || g.j(context) == 2) {
            j = f60a;
        }
        arrayList = new ArrayList();
        arrayList2 = new ArrayList<>();
        int i32 = 0;
        for (ScanResult next2 : list) {
        }
        list.clear();
        if (arrayList2.size() == 0) {
        }
        Collections.sort(arrayList2, d);
        size = arrayList2.size();
        i = c;
        if (size > i) {
        }
        for (a aVar32 : arrayList2) {
        }
        arrayList2.clear();
        StringBuilder sb3 = new StringBuilder();
        sb3.append("scan result after filtering and sorting: ");
        sb3.append(arrayList.toString());
        sb3.toString();
        hVar2.c = arrayList;
        hVar2.d = a.b.a.g.a.a(hVar2.c);
        return hVar2;
        j2 = j * 2;
        arrayList = new ArrayList();
        arrayList2 = new ArrayList<>();
        int i322 = 0;
        for (ScanResult next22 : list) {
        }
        list.clear();
        if (arrayList2.size() == 0) {
        }
        Collections.sort(arrayList2, d);
        size = arrayList2.size();
        i = c;
        if (size > i) {
        }
        for (a aVar322 : arrayList2) {
        }
        arrayList2.clear();
        StringBuilder sb32 = new StringBuilder();
        sb32.append("scan result after filtering and sorting: ");
        sb32.append(arrayList.toString());
        sb32.toString();
        hVar2.c = arrayList;
        hVar2.d = a.b.a.g.a.a(hVar2.c);
        return hVar2;
    }

    public static void a(int i) {
    }

    public static void deleteOldScan(Context context) {
        a.b.a.c.a.b(context).a(context);
    }

    public static List<WifiType> getStoredScan(Context context) {
        return a.b.a.c.a.b(context).a((String) "wifiscans");
    }

    public static void a(Context context, int i, List<WifiType> list) {
        a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "76", i, true);
        a.b.a.c.a.b(context).a((String) "wifiscans", list);
    }

    public static int a(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "76", 0);
    }

    public static h a(Context context, h hVar, List<ScanResult> list) {
        if (list != null && list.size() > 0) {
            return a(context, list, hVar);
        }
        if (VERSION.SDK_INT > 26) {
            return hVar;
        }
        WifiType e = a.b.a.g.a.e(context);
        if (e != null) {
            ArrayList arrayList = new ArrayList();
            arrayList.add(e);
            hVar.c = arrayList;
            hVar.d = a.b.a.g.a.a(hVar.c);
            return hVar;
        }
        hVar.a(null);
        return hVar;
    }
}