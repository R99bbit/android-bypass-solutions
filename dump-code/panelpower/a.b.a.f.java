package a.b.a;

import a.b.a.a.a.b;
import a.b.a.b.l;
import a.b.a.d.d;
import a.b.a.d.i;
import a.b.a.g.a;
import android.content.Context;
import android.location.Location;
import android.location.LocationManager;
import android.os.Build.VERSION;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.os.EnvironmentCompat;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import com.embrain.panelpower.IConstValue.SavedMoney;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.location.LocationServices;
import com.kakao.network.ServerProtocol;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.cloud.RequestMessage;
import com.loplat.placeengine.cloud.ResponseMessage.Advertisement;
import com.loplat.placeengine.service.ForegroundService;
import com.loplat.placeengine.wifi.WifiScanManager;
import com.loplat.placeengine.wifi.WifiType;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* compiled from: PlaceMonitorMode */
public abstract class f {
    public static int a(int i) {
        if (i != 0) {
            return i != 1 ? 1 : 3;
        }
        return 2;
    }

    public static void a(Context context, PlengiResponse plengiResponse) {
        plengiResponse.type = 1;
        Place place = plengiResponse.place;
        if (place != null) {
            String name = place.getName();
            float accuracy = place.getAccuracy();
            float threshold = place.getThreshold();
            double lat = place.getLat();
            double lng = place.getLng();
            int h = a.h(context);
            Place currentPlace = PlaceEngineBase.getCurrentPlace(context);
            a(place, currentPlace);
            if (PlaceEngineBase.isPlaceEngineStarted(context)) {
                a(context, h, place, currentPlace);
            }
            if (h == 0) {
                if (accuracy > threshold && accuracy < 1.0f) {
                    a(context, 2);
                    b(context, place);
                    StringBuilder sb = new StringBuilder();
                    sb.append("Update placename: ");
                    sb.append(name);
                    sb.toString();
                }
                if (f(context) == 2 && !(lat == 0.0d && lng == 0.0d)) {
                    a.b.a.c.a.b(context).a(lat, lng, accuracy, threshold);
                }
                PlaceEngineBase.setSpecialtyRequest(context, null);
                l.h = true;
            } else if (h == 1 && (accuracy > threshold || "opensurvey".equals(l.k))) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("Update placename: ");
                sb2.append(name);
                sb2.toString();
                g.b(context, place, plengiResponse.location);
            }
        }
        PlaceEngineBase.forwardMessageToClient(plengiResponse);
    }

    public static void b(Context context) {
        a(context, 0);
        a.b.a.c.a.b(context).g();
    }

    public static boolean b(int i) {
        return i == 1 || i == 5 || i == 4;
    }

    public static void c(Context context) {
        Place currentPlace = PlaceEngineBase.getCurrentPlace(context);
        if (currentPlace != null) {
            a(context, currentPlace);
        }
        b(context);
        WifiScanManager.deleteOldScan(context);
        a(context, null);
        int h = a.h(context);
        if (h == 0) {
            a.a(context, (String) null);
            a(context, 0);
        } else if (h == 1) {
            Place k = g.k(context);
            if (k != null) {
                g.c(context, k);
            }
            g.c(context, 0);
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:54:0x00b5, code lost:
        if (r8 == false) goto L_0x00be;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:57:0x00bc, code lost:
        if (r10 != false) goto L_0x00be;
     */
    /* JADX WARNING: Removed duplicated region for block: B:60:0x00c1  */
    /* JADX WARNING: Removed duplicated region for block: B:66:0x001f A[SYNTHETIC] */
    public static Location d(Context context) {
        if (!a(context)) {
            return null;
        }
        Location location = new Location("dummy_provider");
        try {
            LocationManager locationManager = (LocationManager) context.getSystemService("location");
            for (String lastKnownLocation : locationManager.getAllProviders()) {
                Location lastKnownLocation2 = locationManager.getLastKnownLocation(lastKnownLocation);
                if (lastKnownLocation2 != null) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("location provider: ");
                    sb.append(lastKnownLocation2.getProvider());
                    sb.toString();
                    boolean z = false;
                    if (location != null) {
                        if (!location.getProvider().equals("dummy_provider")) {
                            long time = lastKnownLocation2.getTime() - location.getTime();
                            boolean z2 = time > 60000;
                            boolean z3 = time < -60000;
                            boolean z4 = time > 0;
                            if (!z2) {
                                if (!z3) {
                                    int accuracy = (int) (lastKnownLocation2.getAccuracy() - location.getAccuracy());
                                    boolean z5 = accuracy > 0;
                                    boolean z6 = accuracy < 0;
                                    boolean z7 = accuracy > 200;
                                    String provider = lastKnownLocation2.getProvider();
                                    String provider2 = location.getProvider();
                                    boolean z8 = provider == null ? provider2 == null : provider.equals(provider2);
                                    if (!z6) {
                                        if (z4) {
                                        }
                                        if (z4) {
                                            if (!z7) {
                                            }
                                        }
                                    }
                                }
                                if (!z) {
                                    location = lastKnownLocation2;
                                }
                            }
                        }
                    }
                    z = true;
                    if (!z) {
                    }
                }
            }
        } catch (Exception unused) {
        }
        return location;
    }

    public static List<WifiType> e(Context context) {
        return a.b.a.c.a.b(context).a((String) "footprint");
    }

    public static int f(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "12", 0);
    }

    public static long g(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) SavedMoney.GIVE_TP_GIFT_CARD_MOBILE, 0);
    }

    public static void h(Context context) {
        a(context, PlaceEngineBase.getCurrentPlace(context));
        b(context);
        a.a(context, (String) null);
    }

    public static void i(Context context) {
        int h = a.h(context);
        if (h == 0) {
            if (f(context) == 2) {
                Place currentPlace = PlaceEngineBase.getCurrentPlace(context);
                if (currentPlace != null && currentPlace.loplatid == 0) {
                    a(context, 0, currentPlace);
                }
            }
        } else if (1 == h) {
            int j = g.j(context);
            if (j == 1 || j == 2) {
                g.b(context, 0);
            }
        }
    }

    public static void b(Context context, PlengiResponse plengiResponse) {
        if (a.h(context) != 0) {
            Place currentPlace = PlaceEngineBase.getCurrentPlace(context);
            if (currentPlace != null) {
                a(context, currentPlace);
            }
            g.b(context, null, plengiResponse.location);
        } else if (f(context) == 4) {
            a(context, 0);
            h(context);
        }
    }

    public static void b(Context context, Place place) {
        if (f(context) == 2) {
            a.b.a.c.a b = a.b.a.c.a.b(context);
            Place b2 = b.b(place);
            if (b2 != null) {
                place.setAccuracy(b2.getAccuracy());
                place.setLat(b2.getLat());
                place.setLng(b2.getLng());
                place.setThreshold(b2.getThreshold());
            }
            b.c(place);
            a.a(context, place.client_code);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:27:0x005a A[RETURN] */
    /* JADX WARNING: Removed duplicated region for block: B:28:0x005b A[RETURN] */
    public static boolean a(Context context, int i, int i2, int i3) {
        int k;
        if (i3 == 1 || i3 == 2 || i3 == 5 || i3 == 4) {
            return true;
        }
        if (i == 0 && i2 == 3) {
            return true;
        }
        long elapsedRealtime = SystemClock.elapsedRealtime();
        long j = 0;
        if (i != 0) {
            if (i == 1) {
                if (i2 == 1) {
                    k = a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "42", (int) SignalLibConsts.REBOOT_DELAY_TIMER) * 2;
                } else {
                    k = a.k(context);
                }
            }
            if (elapsedRealtime - a.b.a.c.a.b(context).j() > j) {
            }
        } else if (i2 == 0) {
            k = a.i(context);
        } else {
            j = 60000;
            return elapsedRealtime - a.b.a.c.a.b(context).j() > j;
        }
        j = (long) (((double) k) * 0.7d);
        if (elapsedRealtime - a.b.a.c.a.b(context).j() > j) {
        }
    }

    @Deprecated
    public static void a(Context context, long j) {
        a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) SavedMoney.GIVE_TP_SURVEY, j, true);
    }

    public static void a(Place place, Place place2) {
        if (place != null) {
            if (place2 != null && place2.loplatid == place.loplatid) {
                long duration_time = place2.getDuration_time();
                if (duration_time > 0) {
                    place.setDuration_time(duration_time);
                    return;
                }
            }
            float accuracy = place.getAccuracy();
            if (accuracy > place.getThreshold() && accuracy < 1.0f) {
                long elapsedRealtime = SystemClock.elapsedRealtime();
                if (elapsedRealtime > 0) {
                    place.setDuration_time(elapsedRealtime);
                }
            }
        }
    }

    public static void a(@NonNull Context context, @NonNull String str, String str2) {
        StringBuilder sb = new StringBuilder();
        sb.append("Cloud Error: (");
        sb.append(str);
        sb.append(")");
        sb.append(str2);
        sb.toString();
        if (str.startsWith(RequestMessage.SEARCH_PLACE)) {
            PlengiResponse plengiResponse = new PlengiResponse(context);
            plengiResponse.type = a(a.h(context));
            plengiResponse.result = -4;
            plengiResponse.errorReason = str2;
            PlaceEngineBase.forwardMessageToClient(plengiResponse);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:16:0x0057  */
    /* JADX WARNING: Removed duplicated region for block: B:18:0x0068  */
    /* JADX WARNING: Removed duplicated region for block: B:55:0x0169  */
    /* JADX WARNING: Removed duplicated region for block: B:56:0x017a  */
    public static void a(Context context, Place place) {
        long j;
        long j2;
        if (!(place == null || place.name == null)) {
            long j3 = place.loplatid;
            StringBuilder sb = new StringBuilder();
            sb.append("LEFT ---------------------------: ");
            sb.append(j3);
            sb.toString();
            int h = a.h(context);
            if (place.loplatid > 0) {
                if (place.accuracy > place.threshold) {
                    if (place.getDuration_time() > 0) {
                        if (h == 1) {
                            j2 = (SystemClock.elapsedRealtime() - place.getDuration_time()) / 1000;
                        } else if (h == 0) {
                            j2 = (SystemClock.elapsedRealtime() - g(context)) / 1000;
                        }
                        if (j2 >= 0) {
                            StringBuilder sb2 = new StringBuilder();
                            sb2.append("[LEAVE] duration error:");
                            sb2.append(j2);
                            sb2.toString();
                            return;
                        }
                        place.setDuration_time(j2);
                        l.a(context, place);
                        StringBuilder sb3 = new StringBuilder();
                        sb3.append("Leave Event: ");
                        sb3.append(j3);
                        sb3.append(", ");
                        sb3.append(place.name);
                        sb3.append(", duration time(sec):");
                        sb3.append(j2);
                        sb3.toString();
                        PlengiResponse plengiResponse = new PlengiResponse(context);
                        plengiResponse.type = a(h);
                        plengiResponse.placeEvent = 2;
                        plengiResponse.place = place;
                        Advertisement advertisement = place.advertisement;
                        if (advertisement != null && RequestMessage.LEAVE_PLACE.equals(advertisement.getDelay_type())) {
                            if (place.advertisement.getDelay() <= 0) {
                                plengiResponse.advertisement = place.advertisement;
                            }
                            b a2 = b.a(context);
                            int campaign_id = place.advertisement.getCampaign_id();
                            boolean z = false;
                            List<Advertisement> b = a2.b();
                            Iterator<Advertisement> it = b.iterator();
                            while (true) {
                                if (!it.hasNext()) {
                                    break;
                                }
                                Advertisement next = it.next();
                                if (next.getCampaign_id() == campaign_id && RequestMessage.LEAVE_PLACE.equals(next.getDelay_type())) {
                                    long delay = next.getDelay();
                                    int i = (delay > 0 ? 1 : (delay == 0 ? 0 : -1));
                                    if (i <= 0) {
                                        a2.a(next);
                                        b.remove(next);
                                    } else if (i > 0) {
                                        next.setTime(System.currentTimeMillis());
                                        a2.a(next.getCampaign_id(), delay * 60000);
                                    }
                                    z = true;
                                }
                            }
                            if (z) {
                                a2.a(b);
                            }
                            place.advertisement = null;
                        }
                        StringBuilder a3 = a.a.a.a.a.a("[LEAVE PLACE INFORMATION] -> ");
                        a3.append(place.loplatid);
                        a3.append(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                        a3.append(place.name);
                        a3.toString();
                        PlaceEngineBase.forwardMessageToClient(plengiResponse);
                    }
                    j2 = 0;
                    if (j2 >= 0) {
                    }
                }
                if (a.h(context) == 1) {
                    b(context);
                }
            } else {
                int h2 = a.h(context);
                if (h2 == 1) {
                    if (place.getDuration_time() > 0) {
                        j = (SystemClock.elapsedRealtime() - place.getDuration_time()) / 1000;
                        if (j < 0) {
                            StringBuilder sb4 = new StringBuilder();
                            sb4.append("[LEAVE] unknown duration error:");
                            sb4.append(j);
                            sb4.toString();
                        } else {
                            place.setLoplatid(0);
                            place.setName(EnvironmentCompat.MEDIA_UNKNOWN);
                            place.setDuration_time(j);
                            place.setCategory_code(null);
                            if (j > 1200) {
                                l.a(context, place);
                            }
                            a.b.a.c.a.b(context).a(null);
                        }
                    }
                } else if (h2 == 0) {
                    j = (SystemClock.elapsedRealtime() - g(context)) / 1000;
                    if (j < 0) {
                    }
                }
                j = 0;
                if (j < 0) {
                }
            }
        }
    }

    public static boolean a(Context context) {
        return (VERSION.SDK_INT >= 23 && context.checkSelfPermission("android.permission.ACCESS_FINE_LOCATION") == -1 && context.checkSelfPermission("android.permission.ACCESS_COARSE_LOCATION") == -1) ? false : true;
    }

    public static void a(@NonNull Context context, PlengiResponse plengiResponse, @NonNull String str, String str2) {
        StringBuilder sb = new StringBuilder();
        sb.append("Response Fail: (");
        sb.append(str);
        sb.append(")");
        sb.append(str2);
        sb.toString();
        if (plengiResponse == null) {
            plengiResponse = new PlengiResponse(context);
        }
        plengiResponse.result = -1;
        plengiResponse.errorReason = str2;
        if (PlengiResponse.NOT_ALLOWED_CLIENT.equals(str2)) {
            PlaceEngineBase.stopPlaceEngine(context);
            PlaceEngineBase.forwardMessageToClient(plengiResponse);
            return;
        }
        if (RequestMessage.SEARCH_PLACE.equals(str)) {
            if (PlaceEngineBase.getSpecialtyRequest(context) != null) {
                a.b.a.c.a b = a.b.a.c.a.b(context);
                ArrayList arrayList = (ArrayList) b.a((String) "subway_ap_candidate");
                ArrayList arrayList2 = (ArrayList) b.a((String) "wifiscans");
                if (arrayList.size() == 0) {
                    b.a((String) "subway_ap_candidate", (List<WifiType>) arrayList2);
                } else {
                    ArrayList arrayList3 = new ArrayList();
                    Iterator it = arrayList.iterator();
                    while (it.hasNext()) {
                        WifiType wifiType = (WifiType) it.next();
                        StringBuilder a2 = a.a.a.a.a.a("ap: ");
                        a2.append(wifiType.BSSID);
                        a2.append(", ");
                        a2.append(wifiType.SSID);
                        a2.toString();
                        int i = 0;
                        while (true) {
                            if (i >= arrayList2.size()) {
                                break;
                            } else if (((WifiType) arrayList2.get(i)).equals(wifiType)) {
                                arrayList3.add(wifiType);
                                break;
                            } else {
                                i++;
                            }
                        }
                    }
                    if (arrayList3.size() > 0) {
                        StringBuilder a3 = a.a.a.a.a.a("store subway Ap candidate list, size: ");
                        a3.append(arrayList.size());
                        a3.toString();
                        b.a((String) "subway_ap_candidate", (List<WifiType>) arrayList3);
                    } else if (arrayList2.size() > 0) {
                        b.a((String) "subway_ap_candidate", (List<WifiType>) arrayList2);
                    }
                }
            }
        } else if (!RequestMessage.SEARCH_PLACE_GPS.equals(str) && str.startsWith(RequestMessage.SEARCH_PLACE)) {
            b(context, plengiResponse);
        }
        PlaceEngineBase.forwardMessageToClient(plengiResponse);
    }

    public static void a(Context context, List<WifiType> list, int i, @Nullable String str) {
        if (!PlaceEngineBase.isBackground() || VERSION.SDK_INT < 26 || a.m(context) < 26) {
            new d(context, i, str, list).c();
        } else {
            ForegroundService.a(context, list, i, str);
        }
    }

    public static PlengiResponse a(Context context, Throwable th, String str) {
        PlengiResponse plengiResponse = new PlengiResponse(context);
        plengiResponse.result = -3;
        plengiResponse.errorReason = PlengiResponse.NETWORK_FAIL;
        PlaceEngineBase.forwardMessageToClient(plengiResponse);
        StringBuilder sb = new StringBuilder();
        sb.append(th.getMessage());
        sb.append(":");
        sb.append(str);
        sb.append("\n");
        sb.append(th.getStackTrace());
        sb.toString();
        return plengiResponse;
    }

    public static void a(Context context, int i, Place place) {
        e eVar = new e(place, i, context);
        if (a(context)) {
            try {
                if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context) == 0) {
                    LocationServices.getFusedLocationProviderClient(context).getLastLocation().addOnSuccessListener(new i(eVar));
                } else {
                    eVar.a(d(context));
                }
            } catch (Exception unused) {
                eVar.a(d(context));
            } catch (Error unused2) {
                eVar.a(d(context));
            }
        }
    }

    public static void a(Context context, int i, Place place, Place place2) {
        if (place2 != null && place2.loplatid > 0 && place2.getAccuracy() > place2.getThreshold()) {
            if (place != null) {
                float accuracy = place.getAccuracy();
                float threshold = place.getThreshold();
                int i2 = (place2.loplatid > place.loplatid ? 1 : (place2.loplatid == place.loplatid ? 0 : -1));
                if (i2 != 0 || (i2 == 0 && accuracy <= threshold)) {
                    if (i == 0) {
                        a(context, 0);
                    }
                    a(context, place2);
                    return;
                }
                return;
            }
            a(context, place2);
        }
    }

    public static void a(Context context, int i) {
        a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "12", i, true);
    }

    public static void a(Context context, List<WifiType> list) {
        a.b.a.c.a.b(context).a((String) "footprint", list);
    }
}