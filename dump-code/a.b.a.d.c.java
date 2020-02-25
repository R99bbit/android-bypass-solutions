package a.b.a.d;

import a.b.a.b.h;
import a.b.a.b.i;
import a.b.a.b.l;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build.VERSION;
import android.os.SystemClock;
import android.telephony.CellLocation;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyManager;
import androidx.core.app.NotificationCompat;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import com.google.gson.Gson;
import com.loplat.placeengine.OnPlengiListener;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.cloud.CloudService;
import com.loplat.placeengine.cloud.RequestMessage;
import com.loplat.placeengine.cloud.RequestMessage.CellEntity;
import com.loplat.placeengine.cloud.RequestMessage.CellTowerInfo;
import com.loplat.placeengine.cloud.RequestMessage.Location;
import com.loplat.placeengine.cloud.RequestMessage.SearchPlaceReq;
import com.loplat.placeengine.cloud.RequestMessage.UplusLbmsReq;
import com.loplat.placeengine.cloud.ResponseMessage.UplusLbmsRes;
import com.loplat.placeengine.utils.LoplatLogger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import retrofit2.Call;

/* compiled from: CellLocationUpdater */
public class c {

    /* renamed from: a reason: collision with root package name */
    public static c f21a = null;
    public static final String b = "c";
    public static int c = 120000;
    public static int d = 1800000;
    public static int e = 180903;
    public static int f = 180904;
    public final String g = c.class.getSimpleName();
    public TelephonyManager h;
    public a i;
    public boolean j = false;
    public Context k;
    public AlarmManager l;
    public b m = null;
    public LinkedHashMap n = new CellLocationUpdater$1(this, 10, 0.75f, true);

    /* compiled from: CellLocationUpdater */
    private class a extends PhoneStateListener {
        public /* synthetic */ a(CellLocationUpdater$1 cellLocationUpdater$1) {
        }

        public void onCellLocationChanged(CellLocation cellLocation) {
            super.onCellLocationChanged(cellLocation);
            CellTowerInfo b = a.b.a.g.a.b(c.this.k);
            if (b != null && c.this.n != null) {
                int intValue = b.getCellId().intValue();
                c.a(c.this, intValue);
                CellEntity cellEntity = new CellEntity();
                cellEntity.setCellId(b.getCellId());
                cellEntity.setLac(b.getLac());
                cellEntity.setDbm(b.getDbm());
                cellEntity.setTime(SystemClock.elapsedRealtime());
                c.this.n.put(Integer.valueOf(intValue), cellEntity);
                c.this.a();
            }
        }
    }

    /* compiled from: CellLocationUpdater */
    private class b extends BroadcastReceiver {
        public /* synthetic */ b(CellLocationUpdater$1 cellLocationUpdater$1) {
        }

        public void onReceive(Context context, Intent intent) {
            if (intent != null && context != null && a.b.a.g.a.a(context).equals(intent.getPackage())) {
                String action = intent.getAction();
                CellTowerInfo b = a.b.a.g.a.b(c.this.k);
                if (b != null) {
                    int intValue = b.getCellId().intValue();
                    if ("com.loplat.cell.stay_check".equals(action)) {
                        c.this.a(b, (OnPlengiListener) null);
                    } else if ("com.loplat.cell.move_check".equals(action) && c.a(c.this, intValue) == 0) {
                        c.this.a(b, (OnPlengiListener) null);
                    }
                }
            }
        }
    }

    /* renamed from: a.b.a.d.c$c reason: collision with other inner class name */
    /* compiled from: CellLocationUpdater */
    public interface C0000c {
    }

    public c(Context context) {
        this.k = context;
        this.h = (TelephonyManager) context.getSystemService("phone");
        this.l = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
    }

    public final void a() {
    }

    public static c b(Context context) {
        if (f21a == null) {
            f21a = new c(context);
        }
        return f21a;
    }

    public void c() {
        if (this.j) {
            this.j = false;
            Context context = this.k;
            b bVar = this.m;
            if (bVar != null) {
                context.unregisterReceiver(bVar);
                this.m = null;
            }
            LinkedHashMap linkedHashMap = this.n;
            if (linkedHashMap != null && !linkedHashMap.isEmpty()) {
                this.n.clear();
            }
            a(1);
            a(0);
            a(this.k, 1);
            TelephonyManager telephonyManager = this.h;
            if (telephonyManager != null) {
                a aVar = this.i;
                if (aVar != null) {
                    telephonyManager.listen(aVar, 0);
                }
            }
        }
    }

    public final void d(Context context) {
        this.m = new b(null);
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction("com.loplat.cell.stay_check");
        intentFilter.addAction("com.loplat.cell.move_check");
        context.registerReceiver(this.m, intentFilter);
    }

    public final void a(int i2) {
        try {
            if (this.l != null) {
                int i3 = e;
                String str = "com.loplat.cell.stay_check";
                if (i2 == 1) {
                    i3 = e;
                } else if (i2 == 1) {
                    i3 = f;
                    str = "com.loplat.cell.move_check";
                }
                PendingIntent broadcast = PendingIntent.getBroadcast(this.k, i3, new Intent(str), 536870912);
                if (broadcast != null) {
                    this.l.cancel(broadcast);
                    broadcast.cancel();
                }
            }
        } catch (Error | Exception unused) {
        }
    }

    public final void b(int i2) {
        try {
            if (this.l != null) {
                c = a.b.a.c.a.a(this.k, (String) "lhtibaq5ot47p0xrinly", (String) "49", (int) SignalLibConsts.REBOOT_DELAY_TIMER);
                d = a.b.a.c.a.a(this.k, (String) "lhtibaq5ot47p0xrinly", (String) "48", 1800000);
                int i3 = c;
                int i4 = e;
                String str = "com.loplat.cell.stay_check";
                if (i2 == 1) {
                    String str2 = this.g;
                    Object[] objArr = new Object[1];
                    StringBuilder sb = new StringBuilder();
                    sb.append("STAY_CHECK timer start:");
                    sb.append(c / 1000);
                    objArr[0] = sb.toString();
                    i3 = c;
                    i4 = e;
                } else if (i2 == 0) {
                    String str3 = this.g;
                    Object[] objArr2 = new Object[1];
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("MOVE_REQ timer start:");
                    sb2.append(d / 1000);
                    objArr2[0] = sb2.toString();
                    i3 = d;
                    i4 = f;
                    str = "com.loplat.cell.move_check";
                }
                Intent intent = new Intent(str);
                intent.setPackage(a.b.a.g.a.a(this.k));
                PendingIntent broadcast = PendingIntent.getBroadcast(this.k, i4, intent, 268435456);
                if (VERSION.SDK_INT >= 23) {
                    this.l.setExactAndAllowWhileIdle(0, System.currentTimeMillis() + ((long) i3), broadcast);
                } else {
                    this.l.set(0, System.currentTimeMillis() + ((long) i3), broadcast);
                }
            }
        } catch (Exception unused) {
        }
    }

    public static /* synthetic */ int a(c cVar, int i2) {
        LinkedHashMap linkedHashMap = cVar.n;
        if (linkedHashMap != null) {
            if (!linkedHashMap.containsKey(Integer.valueOf(i2))) {
                if (a(cVar.k) == 1) {
                    a(cVar.k, 0);
                    cVar.a(1);
                    cVar.b(0);
                    return 0;
                }
            } else if (a(cVar.k) == 0) {
                a(cVar.k, 1);
                cVar.a(0);
                cVar.b(1);
                return 1;
            }
        }
        return -1;
    }

    public static String c(Context context) {
        return a.b.a.c.a.a(context, b, (String) "4", (String) "");
    }

    public final void a(Location location, OnPlengiListener onPlengiListener) {
        LinkedHashMap linkedHashMap = this.n;
        if (linkedHashMap != null && !linkedHashMap.isEmpty()) {
            ArrayList<CellEntity> arrayList = new ArrayList<>(this.n.values());
            ArrayList<CellEntity> arrayList2 = new ArrayList<>();
            String str = this.g;
            new Object[1][0] = "-----------------------------------------------";
            CellTowerInfo cellInfo = location.getCellInfo();
            for (CellEntity cellEntity : arrayList) {
                if (cellInfo.getTime() - cellEntity.getTime() < 600000) {
                    arrayList2.add(cellEntity);
                }
            }
            if (!arrayList2.isEmpty()) {
                int intValue = cellInfo.getCellId().intValue();
                int a2 = a(this.k);
                CellEntity cellEntity2 = null;
                for (CellEntity cellEntity3 : arrayList2) {
                    if (intValue == cellEntity3.getCellId().intValue()) {
                        cellEntity2 = cellEntity3;
                    }
                }
                if (cellEntity2 != null) {
                    arrayList2.remove(cellEntity2);
                }
                if (arrayList2.size() > 0) {
                    cellInfo.setCellList(arrayList2);
                }
                Context context = this.k;
                b bVar = new b(this, onPlengiListener, a2, intValue);
                l.j = context;
                SearchPlaceReq searchPlaceReq = new SearchPlaceReq(context, RequestMessage.SEARCH_PLACE_CELL);
                if (a.b.a.g.a.p(context)) {
                    location.setVpn(Integer.valueOf(1));
                }
                searchPlaceReq.setLocation(location);
                if (LoplatLogger.DEBUG) {
                    new Gson().toJson((Object) searchPlaceReq);
                }
                new i(context).a(searchPlaceReq, (OnPlengiListener) bVar);
            }
        }
    }

    public void b() {
        if (PlaceEngineBase.isCellPositioningEnabled(this.k) && PlaceEngineBase.isPlaceEngineStarted(this.k)) {
            try {
                if (VERSION.SDK_INT < 23) {
                    return;
                }
                if (this.k.checkSelfPermission("android.permission.ACCESS_COARSE_LOCATION") == 0 && this.h != null && !this.j) {
                    this.j = true;
                    this.i = new a(null);
                    this.h.listen(this.i, 16);
                    d(this.k);
                }
            } catch (Error | Exception unused) {
            }
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:17:0x006d  */
    /* JADX WARNING: Removed duplicated region for block: B:23:0x008d  */
    /* JADX WARNING: Removed duplicated region for block: B:27:? A[RETURN, SYNTHETIC] */
    public final void a(CellTowerInfo cellTowerInfo, OnPlengiListener onPlengiListener) {
        String str;
        Call<UplusLbmsRes> call;
        if (c(this.k).isEmpty() || cellTowerInfo.getMnc().intValue() != 6) {
            Location location = new Location();
            location.setCellInfo(cellTowerInfo);
            a(location, onPlengiListener);
            return;
        }
        int cellType = cellTowerInfo.getCellType();
        if (cellType != 1) {
            if (cellType == 2) {
                str = "3G";
            } else if (!(cellType == 3 || cellType == 4)) {
                str = "ETC";
            }
            Location location2 = new Location();
            location2.setCellInfo(cellTowerInfo);
            Context context = this.k;
            String ip = cellTowerInfo.getIp();
            a aVar = new a(this, location2, onPlengiListener);
            l.j = context;
            UplusLbmsReq uplusLbmsReq = new UplusLbmsReq(context, RequestMessage.UPLUS_LBS_REQUEST);
            uplusLbmsReq.setDeviceIp(ip);
            uplusLbmsReq.setNwInfo(str);
            StringBuilder sb = new StringBuilder();
            sb.append("[UplusLbmsReq] request ");
            sb.append(ip);
            sb.append(", ");
            sb.append(str);
            sb.toString();
            if (LoplatLogger.DEBUG) {
                new Gson().toJson((Object) uplusLbmsReq);
            }
            i iVar = new i(context);
            CloudService a2 = l.a(uplusLbmsReq.getType());
            call = null;
            uplusLbmsReq.setType(null);
            call = a2.postUplusLBMS(uplusLbmsReq);
            if (call == null) {
                call.enqueue(new h(iVar, aVar));
                return;
            }
            return;
        }
        str = "4G";
        Location location22 = new Location();
        location22.setCellInfo(cellTowerInfo);
        Context context2 = this.k;
        String ip2 = cellTowerInfo.getIp();
        a aVar2 = new a(this, location22, onPlengiListener);
        l.j = context2;
        UplusLbmsReq uplusLbmsReq2 = new UplusLbmsReq(context2, RequestMessage.UPLUS_LBS_REQUEST);
        uplusLbmsReq2.setDeviceIp(ip2);
        uplusLbmsReq2.setNwInfo(str);
        StringBuilder sb2 = new StringBuilder();
        sb2.append("[UplusLbmsReq] request ");
        sb2.append(ip2);
        sb2.append(", ");
        sb2.append(str);
        sb2.toString();
        if (LoplatLogger.DEBUG) {
        }
        i iVar2 = new i(context2);
        CloudService a22 = l.a(uplusLbmsReq2.getType());
        call = null;
        uplusLbmsReq2.setType(null);
        try {
            call = a22.postUplusLBMS(uplusLbmsReq2);
        } catch (Error | Exception unused) {
        }
        if (call == null) {
        }
    }

    public static void a(Context context, int i2) {
        a.b.a.c.a.a(context, b, (String) "3", i2, true);
    }

    public static int a(Context context) {
        return a.b.a.c.a.a(context, b, (String) "3", 0);
    }

    public static void a(Context context, String str) {
        a.b.a.c.a.b(context, b, "4", str, true);
    }
}