package a.b.a.c;

import a.b.a.a.a.b;
import a.b.a.b.l;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.location.Location;
import com.google.gson.Gson;
import com.kakao.network.ServerProtocol;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.PlengiResponse.Visit;
import com.loplat.placeengine.cloud.RequestMessage.CheckPlaceInfo;
import com.loplat.placeengine.cloud.RequestMessage.Specialty;
import com.loplat.placeengine.cloud.ResponseMessage.ActivityRecognition;
import com.loplat.placeengine.wifi.WifiType;
import java.util.ArrayList;
import java.util.List;

/* compiled from: SharedDataHandler */
public class a {

    /* renamed from: a reason: collision with root package name */
    public static Context f18a = null;
    public static a b = null;
    public static SharedPreferences c = null;
    public static Editor d = null;
    public static String e = "1";
    public static String f = "2";
    public static String g = "\t";
    public CheckPlaceInfo h;

    static {
        a.class.getSimpleName();
    }

    public static synchronized a b(Context context) {
        a aVar;
        synchronized (a.class) {
            try {
                c(context);
                if (b == null) {
                    b = new a();
                }
                aVar = b;
            }
        }
        return aVar;
    }

    public static void c(Context context) {
        if (f18a == null || c == null || d == null) {
            f18a = context;
            c = f18a.getSharedPreferences("lhtibaq5ot47p0xrinly", 0);
            d = c.edit();
        }
    }

    public void a(double d2, double d3, float f2, float f3) {
        Place place = new Place();
        place.setLat(d2);
        place.setLng(d3);
        place.setAccuracy(f2);
        place.setThreshold(f3);
        c(b(place));
    }

    public void d(long j) {
        try {
            d.putLong("72", j);
            d.commit();
        } catch (Exception unused) {
        }
    }

    public void e() {
        try {
            d.remove(f);
            d.commit();
        } catch (Exception unused) {
        }
    }

    public void f() {
        try {
            d.remove("72");
            d.commit();
        } catch (Exception unused) {
        }
    }

    public void g() {
        try {
            d.remove("places");
            d.apply();
        } catch (Exception unused) {
        }
    }

    public int h() {
        return c.getInt("58", 0);
    }

    public int i() {
        return c.getInt("59", 0);
    }

    public long j() {
        try {
            return c.getLong(e, 0);
        } catch (Exception unused) {
            return 0;
        }
    }

    public long k() {
        try {
            return c.getLong("57", 0);
        } catch (Exception unused) {
            return 0;
        }
    }

    public Location l() {
        try {
            double parseDouble = Double.parseDouble(c.getString("73", null));
            double parseDouble2 = Double.parseDouble(c.getString("74", null));
            Location location = new Location("");
            try {
                location.setLatitude(parseDouble);
                location.setLongitude(parseDouble2);
            } catch (Exception unused) {
            }
            return location;
        } catch (Exception unused2) {
            return null;
        }
    }

    public long m() {
        try {
            return c.getLong(f, 0);
        } catch (Exception unused) {
            return 0;
        }
    }

    public Place n() {
        try {
            String string = c.getString("places", null);
            if (string != null) {
                return (Place) new Gson().fromJson(string, Place.class);
            }
            return null;
        } catch (Error | Exception unused) {
            return null;
        }
    }

    public ArrayList<Place> o() {
        ArrayList<Place> arrayList = new ArrayList<>();
        Place n = n();
        if (n != null) {
            arrayList.add(n);
        }
        return arrayList;
    }

    public ArrayList<Visit> p() {
        return new ArrayList<>();
    }

    public long q() {
        try {
            return c.getLong("72", 0);
        } catch (Exception unused) {
            return 0;
        }
    }

    public Specialty r() {
        try {
            String string = c.getString("specialty", null);
            if (string != null) {
                return (Specialty) new Gson().fromJson(string, Specialty.class);
            }
            return null;
        } catch (Error | Exception unused) {
            return null;
        }
    }

    public Place s() {
        try {
            String string = c.getString("unknown_place", null);
            if (string != null) {
                return (Place) new Gson().fromJson(string, Place.class);
            }
            return null;
        } catch (Error | Exception unused) {
            return null;
        }
    }

    public boolean t() {
        return c.getInt("58", -1) > 0 && c.getInt("59", -1) > 0;
    }

    public void u() {
        int i;
        int i2;
        a(f18a, l.o, (String) "useadnetwork", (String) "19", false);
        a(f18a, l.o, (String) "useadnoti", (String) "20", false);
        a(f18a, l.o, (String) "loplat_use_ad_by_cell", (String) "21", false);
        a(f18a, b.b, (String) "small_icon_res_id", (String) "17", 17301576);
        a(f18a, b.b, (String) "large_icon_res_id", (String) "18", 17301576);
        try {
            SharedPreferences sharedPreferences = f18a.getSharedPreferences(b.b, 0);
            if (sharedPreferences.contains("pending_ad_list")) {
                String string = sharedPreferences.getString("pending_ad_list", "");
                StringBuilder sb = new StringBuilder();
                sb.append("migrate: ");
                sb.append("pending_ad_list");
                sb.append(" -> ");
                sb.append("16");
                sb.append(", ");
                sb.append(string);
                sb.toString();
                Editor edit = sharedPreferences.edit();
                edit.remove("pending_ad_list");
                edit.apply();
                d.putString("16", string);
                d.commit();
            }
        } catch (Error | Exception unused) {
        }
        a(f18a, (String) PlaceEngineBase.PE_PREFS_NAME, (String) PlaceEngineBase.PREFS_OLD_KEY_ENGINE_STATUS, (String) "24", -1);
        if (PlaceEngineBase.isManualApiCallEnabled(f18a)) {
            a(f18a, (String) PlaceEngineBase.PE_PREFS_NAME, (String) "monitoringType", (String) "45", 0);
            int h2 = a.b.a.g.a.h(f18a);
            if (h2 == 0) {
                i2 = a.b.a.g.a.i(f18a);
                i = a(f18a, (String) "lhtibaq5ot47p0xrinly", (String) "41", 240000);
            } else {
                i2 = a.b.a.g.a.k(f18a);
                i = i2 * 2;
            }
            if (h2 == 0) {
                PlaceEngineBase.setScanPeriod(f18a, i2, i, true);
            } else if (h2 == 1) {
                PlaceEngineBase.setScanPeriodTracking(f18a, i2, true);
            }
        }
    }

    public void d() {
        try {
            d.remove("73");
            d.remove("74");
            d.commit();
        } catch (Exception unused) {
        }
    }

    public final Place b(Place place) {
        Place n = n();
        if (n == null) {
            return null;
        }
        float accuracy = n.getAccuracy();
        if (accuracy <= 0.0f) {
            accuracy = 300.0f;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("updateLocation: ");
        sb.append(accuracy);
        sb.append(" --> ");
        sb.append(place.accuracy);
        sb.toString();
        if (!(place.lat == 0.0d && place.lng == 0.0d)) {
            float f2 = place.accuracy;
            if ((f2 < 1.0f && (f2 > accuracy || accuracy == 300.0f)) || place.accuracy < accuracy) {
                n.setLat(place.lat);
                n.setLng(place.lng);
                n.setAccuracy(place.accuracy);
                n.setThreshold(place.threshold);
                return n;
            }
        }
        return null;
    }

    public void c(Place place) {
        if (place != null) {
            try {
                d.putString("places", new Gson().toJson((Object) place));
                d.commit();
            } catch (Error | Exception unused) {
            }
        }
    }

    public final void a(String str, List<WifiType> list) {
        if (list != null) {
            try {
                if (!list.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (WifiType next : list) {
                        String str2 = next.SSID;
                        if (str2.contains(g)) {
                            str2 = str2.replace(g, ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                        }
                        sb.append(next.BSSID);
                        sb.append(g);
                        sb.append(str2);
                        sb.append(g);
                        sb.append(next.level);
                        sb.append(g);
                        sb.append(next.frequency);
                        sb.append(g);
                    }
                    d.putString(str, sb.toString());
                    d.apply();
                }
            } catch (Error | Exception unused) {
                return;
            }
        }
        d.remove(str);
        d.apply();
    }

    public void c() {
        try {
            d.remove("57");
            d.commit();
        } catch (Exception unused) {
        }
    }

    public void c(long j) {
        try {
            d.putLong(f, j);
            d.commit();
        } catch (Exception unused) {
        }
    }

    public void b(long j) {
        try {
            d.putLong("57", j);
            d.commit();
        } catch (Exception unused) {
        }
    }

    public void b() {
        try {
            d.remove(e);
            d.commit();
        } catch (Exception unused) {
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:10:0x001b A[Catch:{ Exception -> 0x0023 }] */
    /* JADX WARNING: Removed duplicated region for block: B:11:0x0020 A[Catch:{ Exception -> 0x0023 }] */
    public static boolean b(Context context, String str, String str2, String str3, boolean z) {
        try {
            Editor edit = context.getSharedPreferences(str, 0).edit();
            if (str3 != null) {
                if (!str3.isEmpty()) {
                    edit.putString(str2, str3);
                    if (!z) {
                        return edit.commit();
                    }
                    edit.apply();
                    return false;
                }
            }
            edit.remove(str2);
            if (!z) {
            }
        } catch (Exception unused) {
            return false;
        }
    }

    public final List<WifiType> a(String str) {
        ArrayList arrayList = new ArrayList();
        try {
            String string = c.getString(str, null);
            if (string != null) {
                String[] split = string.split(g);
                if (split.length >= 4 && split.length % 4 == 0) {
                    for (int i = 0; i < split.length; i += 4) {
                        arrayList.add(new WifiType(split[i], split[i + 1], Integer.parseInt(split[i + 2]), Integer.parseInt(split[i + 3])));
                    }
                }
            }
        } catch (Error unused) {
            arrayList.clear();
        } catch (Exception unused2) {
            arrayList.clear();
        }
        return arrayList;
    }

    public void a(List<WifiType> list) {
        a((String) "wifi_connection", list);
    }

    public void a(Context context) {
        try {
            a(context, (String) "lhtibaq5ot47p0xrinly", (String) "76", 0, true);
            d.remove("wifiscans");
            d.apply();
        } catch (Exception unused) {
        }
    }

    public void a(Specialty specialty) {
        if (specialty != null) {
            try {
                d.putString("specialty", new Gson().toJson((Object) specialty));
            } catch (Error | Exception unused) {
                return;
            }
        } else {
            d.remove("specialty");
        }
        d.apply();
    }

    public void a(double d2, double d3) {
        try {
            d.putString("73", Double.toString(d2));
            d.putString("74", Double.toString(d3));
            d.commit();
        } catch (Exception unused) {
        }
    }

    public boolean a(ActivityRecognition activityRecognition) {
        try {
            d.putInt("58", activityRecognition.getCheckDistance());
            d.putInt("59", activityRecognition.getCheckInterval());
            return d.commit();
        } catch (Exception unused) {
            return false;
        }
    }

    public boolean a() {
        try {
            d.remove("58");
            d.remove("59");
            return d.commit();
        } catch (Exception unused) {
            return false;
        }
    }

    public void a(long j) {
        try {
            d.putLong(e, j);
            d.commit();
        } catch (Exception unused) {
        }
    }

    public void a(Place place) {
        if (place != null) {
            try {
                d.putString("unknown_place", new Gson().toJson((Object) place));
            } catch (Error | Exception unused) {
                return;
            }
        } else {
            d.remove("unknown_place");
        }
        d.apply();
    }

    public static boolean a(Context context, String str, String str2, String str3, boolean z) {
        try {
            SharedPreferences sharedPreferences = context.getSharedPreferences(str, 0);
            if (!sharedPreferences.contains(str2)) {
                return false;
            }
            boolean z2 = sharedPreferences.getBoolean(str2, z);
            StringBuilder sb = new StringBuilder();
            sb.append("migrate: ");
            sb.append(str2);
            sb.append(" -> ");
            sb.append(str3);
            sb.append(", ");
            sb.append(z2);
            sb.toString();
            Editor edit = sharedPreferences.edit();
            edit.remove(str2);
            edit.apply();
            d.putBoolean(str3, z2);
            return d.commit();
        } catch (Error | Exception unused) {
            return false;
        }
    }

    public static boolean a(Context context, String str, String str2, boolean z) {
        try {
            return context.getSharedPreferences(str, 0).getBoolean(str2, z);
        } catch (Exception unused) {
            return z;
        }
    }

    public static boolean a(Context context, String str, String str2, boolean z, boolean z2) {
        try {
            Editor edit = context.getSharedPreferences(str, 0).edit();
            edit.putBoolean(str2, z);
            if (z2) {
                return edit.commit();
            }
            edit.apply();
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    public static boolean a(Context context, String str, String str2, String str3, int i) {
        try {
            SharedPreferences sharedPreferences = context.getSharedPreferences(str, 0);
            if (!sharedPreferences.contains(str2)) {
                return false;
            }
            int i2 = sharedPreferences.getInt(str2, i);
            StringBuilder sb = new StringBuilder();
            sb.append("migrate: ");
            sb.append(str2);
            sb.append(" -> ");
            sb.append(str3);
            sb.append(", ");
            sb.append(i2);
            sb.toString();
            Editor edit = sharedPreferences.edit();
            edit.remove(str2);
            edit.apply();
            d.putInt(str3, i2);
            return d.commit();
        } catch (Error | Exception unused) {
            return false;
        }
    }

    public static int a(Context context, String str, String str2, int i) {
        try {
            return context.getSharedPreferences(str, 0).getInt(str2, i);
        } catch (Exception unused) {
            return i;
        }
    }

    public static boolean a(Context context, String str, String str2, int i, boolean z) {
        try {
            Editor edit = context.getSharedPreferences(str, 0).edit();
            edit.putInt(str2, i);
            if (z) {
                return edit.commit();
            }
            edit.apply();
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    public static long a(Context context, String str, String str2, long j) {
        try {
            return context.getSharedPreferences(str, 0).getLong(str2, j);
        } catch (Exception unused) {
            return j;
        }
    }

    public static boolean a(Context context, String str, String str2, long j, boolean z) {
        try {
            Editor edit = context.getSharedPreferences(str, 0).edit();
            edit.putLong(str2, j);
            if (z) {
                return edit.commit();
            }
            edit.apply();
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    public static float a(Context context, String str, String str2, float f2) {
        try {
            return context.getSharedPreferences(str, 0).getFloat(str2, f2);
        } catch (Exception unused) {
            return f2;
        }
    }

    public static boolean a(Context context, String str, String str2, float f2, boolean z) {
        try {
            Editor edit = context.getSharedPreferences(str, 0).edit();
            edit.putFloat(str2, f2);
            if (z) {
                return edit.commit();
            }
            edit.apply();
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    public static String a(Context context, String str, String str2, String str3) {
        try {
            return context.getSharedPreferences(str, 0).getString(str2, str3);
        } catch (Exception unused) {
            return str3;
        }
    }
}