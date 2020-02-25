package a.b.a;

import a.a.a.a.a;
import a.b.a.h.c;
import android.content.Context;
import android.os.SystemClock;
import androidx.annotation.Nullable;
import androidx.core.os.EnvironmentCompat;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import com.loplat.placeengine.PlengiResponse.Location;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.wifi.WifiScanManager;
import com.loplat.placeengine.wifi.WifiType;
import java.util.List;

/* compiled from: PlaceTracker */
public class g extends f {

    /* renamed from: a reason: collision with root package name */
    public static long f40a = 720000;

    public static boolean a(Context context, @Nullable Place place, Location location) {
        List<WifiType> storedScan = WifiScanManager.getStoredScan(context);
        Place k = k(context);
        StringBuilder a2 = a.a("place: ");
        a2.append(k != null ? EnvironmentCompat.MEDIA_UNKNOWN : "empty");
        a2.append("scan size: ");
        a2.append(storedScan.size());
        a2.toString();
        if (k != null || storedScan.isEmpty()) {
            return false;
        }
        b(context, storedScan);
        Place place2 = new Place();
        place2.setLoplatid(0);
        place2.setName(EnvironmentCompat.MEDIA_UNKNOWN);
        if (place != null) {
            try {
                place2.setTags(Long.toString(place.getLoplatid()));
            } catch (Exception unused) {
            }
        }
        long elapsedRealtime = SystemClock.elapsedRealtime();
        place2.setDuration_time(elapsedRealtime);
        if (location != null) {
            place2.lat = location.lat;
            place2.lng = location.lng;
        }
        d(context, place2);
        b(context, elapsedRealtime);
        return true;
    }

    public static void b(Context context, Place place, Location location) {
        int j = j(context);
        if (place != null) {
            c(context, 2);
            f.a(context, WifiScanManager.getStoredScan(context));
            if (place.accuracy < place.threshold && a(context, place, location)) {
                StringBuilder a2 = a.a("unknown place(");
                a2.append(place.loplatid);
                a2.append(")");
                a2.toString();
            }
            if (0 == a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) SignalLibConsts.MISSED_DATA_BEFORE_DAYTIME, 0)) {
                b(context, SystemClock.elapsedRealtime());
            }
            f.a(context, place.loplatid);
            a.b.a.c.a.b(context).c(place);
        } else if (j == 2) {
            f.b(context);
            c(context, 0);
        } else if (j == 4) {
            a(context, null, location);
            c(context, 1);
            f.a(context, WifiScanManager.getStoredScan(context));
            c.c(context);
        }
    }

    public static void c(Context context, Place place) {
        f.a(context, place);
        d(context, null);
        b(context, null);
        b(context, 0);
    }

    public static void d(Context context, Place place) {
        f.a(context, 0);
        a.b.a.c.a.b(context).a(place);
    }

    public static int j(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "14", 0);
    }

    public static Place k(Context context) {
        return a.b.a.c.a.b(context).s();
    }

    public static void c(Context context, int i) {
        a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "14", i, true);
    }

    public static void b(Context context, List<WifiType> list) {
        StringBuilder a2 = a.a("set unknown foot print: ");
        a2.append(list == null ? "empty(null)" : Integer.valueOf(list.size()));
        a2.toString();
        a.b.a.c.a.b(context).a((String) "unknown_place_footprint", list);
    }

    public static float b(Context context, int i) {
        float f = i == 1 ? 0.5f : 0.7f;
        float f2 = (f - 0.2f) / 5.0f;
        long a2 = a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) SignalLibConsts.MISSED_DATA_BEFORE_DAYTIME, 0);
        if (a2 == 0) {
            b(context, SystemClock.elapsedRealtime());
        } else {
            int min = Math.min(5, (int) (Math.max(0, SystemClock.elapsedRealtime() - a2) / f40a));
            StringBuilder sb = new StringBuilder();
            sb.append("adjust step: ");
            sb.append(min);
            sb.toString();
            f = Math.max(0.2f, f - (f2 * ((float) min)));
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append("adjust threshold: ");
        sb2.append(f);
        sb2.toString();
        return f;
    }

    public static void b(Context context, long j) {
        a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) SignalLibConsts.MISSED_DATA_BEFORE_DAYTIME, j < 0 ? 0 : j, true);
    }
}