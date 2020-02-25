package a.b.a.e;

import a.b.a.b.l;
import a.b.a.c.a;
import a.b.a.d.c;
import android.content.Context;
import android.os.Build.VERSION;
import android.os.SystemClock;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.cloud.RequestMessage;

/* compiled from: DeviceMonitor */
public class f {

    /* renamed from: a reason: collision with root package name */
    public static f f31a;
    public Context b;
    public long c;
    public long d;

    public f(Context context) {
        this.b = context;
    }

    public static f a(Context context) {
        if (f31a == null) {
            f31a = new f(context);
        }
        return f31a;
    }

    public void a(boolean z) {
    }

    public void b() {
        long elapsedRealtime = SystemClock.elapsedRealtime();
        if (elapsedRealtime - this.c > 60000) {
            PlaceEngineBase.getPlaceInfoAfterUnlockScreen(this.b);
            this.c = elapsedRealtime;
        }
    }

    public boolean a() {
        long elapsedRealtime = SystemClock.elapsedRealtime();
        if (elapsedRealtime - this.d <= 60000) {
            return false;
        }
        this.d = elapsedRealtime;
        return true;
    }

    public void a(int i) {
        int a2 = a.a(this.b, (String) "lhtibaq5ot47p0xrinly", (String) "7", 3);
        if (!((i == 0 && (a2 == 1 || a2 == 2)) || i == a2)) {
            a.a(this.b, (String) "lhtibaq5ot47p0xrinly", (String) "7", i, true);
            if (i == 0) {
                l.b(this.b, RequestMessage.ENGINE_STATUS_START);
            } else if (i != 1) {
                if (i != 2) {
                    if (i == 3) {
                        l.b(this.b, "stop");
                    }
                } else if (VERSION.SDK_INT >= 23) {
                    c.b(this.b).b();
                    l.b(this.b, RequestMessage.ENGINE_STATUS_GPS_OFF);
                }
            } else if (VERSION.SDK_INT >= 23) {
                c.b(this.b).c();
                l.b(this.b, RequestMessage.ENGINE_STATUS_GPS_ON);
            }
        }
    }
}