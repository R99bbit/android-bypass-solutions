package a.b.a.b;

import a.b.a.a.a.b;
import a.b.a.d.c;
import a.b.a.f;
import a.b.a.f.h;
import a.b.a.g;
import a.b.a.h.e;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources.NotFoundException;
import android.os.Build;
import android.os.Build.VERSION;
import android.os.Handler;
import androidx.core.app.NotificationCompat.Builder;
import androidx.core.app.NotificationManagerCompat;
import com.embrain.panelpower.IConstValue.SavedMoney;
import com.google.gson.Gson;
import com.loplat.placeengine.OnPlengiListener;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.cloud.RequestMessage;
import com.loplat.placeengine.cloud.RequestMessage.BaseMessage;
import com.loplat.placeengine.cloud.RequestMessage.Connection;
import com.loplat.placeengine.cloud.RequestMessage.Location;
import com.loplat.placeengine.cloud.RequestMessage.SearchPlaceReq;
import com.loplat.placeengine.cloud.RequestMessage.Specialty;
import com.loplat.placeengine.cloud.ResponseMessage.Advertisement;
import com.loplat.placeengine.cloud.ResponseMessage.SdkConfig;
import com.loplat.placeengine.cloud.ResponseMessage.SearchPlaceRes;
import com.loplat.placeengine.cloud.ResponseMessage.Station;
import com.loplat.placeengine.service.ForegroundService;
import com.loplat.placeengine.utils.LoplatLogger;
import com.loplat.placeengine.wifi.WifiType;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import retrofit2.Call;
import retrofit2.Callback;

/* compiled from: CloudEndpoint */
public class i {

    /* renamed from: a reason: collision with root package name */
    public static Context f13a;

    /* compiled from: CloudEndpoint */
    public abstract class a<T> implements Callback<T> {
        public a(i iVar) {
        }

        /* JADX WARNING: Removed duplicated region for block: B:109:0x029b  */
        /* JADX WARNING: Removed duplicated region for block: B:113:0x02b8  */
        /* JADX WARNING: Removed duplicated region for block: B:18:0x0041  */
        /* JADX WARNING: Removed duplicated region for block: B:86:0x022a  */
        /* JADX WARNING: Removed duplicated region for block: B:90:0x0234  */
        public void a(SearchPlaceReq searchPlaceReq, Specialty specialty) {
            double d;
            Place place;
            String str;
            ArrayList<WifiType> arrayList;
            Station station;
            String str2;
            ArrayList arrayList2;
            ArrayList<String> arrayList3;
            String str3;
            e eVar;
            e eVar2;
            e eVar3;
            float f;
            float f2;
            e eVar4;
            String str4;
            ArrayList arrayList4;
            if (specialty != null) {
                Location location = searchPlaceReq.getLocation();
                double d2 = 0.0d;
                if (location != null) {
                    double lat = location.getLat();
                    d2 = location.getLng();
                    d = lat;
                } else {
                    d = 0.0d;
                }
                ArrayList arrayList5 = (ArrayList) searchPlaceReq.getScan();
                String str5 = a.b.a.g.a.d;
                if (str5 != null) {
                    String str6 = str5;
                    int i = 0;
                    e eVar5 = null;
                    while (i < 3) {
                        if (str != null) {
                            HashMap<String, Station> hashMap = a.b.a.g.a.f41a;
                            if (hashMap != null && hashMap.size() > 0) {
                                station = a.b.a.g.a.f41a.get(str);
                                if (station == null) {
                                    e eVar6 = new e();
                                    ArrayList<WifiType> scanned_fp = station.getScanned_fp();
                                    float f3 = 0.0f;
                                    if (arrayList == null || !arrayList.isEmpty() || scanned_fp == null || scanned_fp.isEmpty()) {
                                        arrayList2 = arrayList;
                                        str2 = str;
                                        eVar3 = eVar5;
                                        f = 0.0f;
                                    } else {
                                        HashMap hashMap2 = new HashMap();
                                        boolean z = false;
                                        for (WifiType wifiType : arrayList) {
                                            int i2 = wifiType.level;
                                            if (i2 > -91) {
                                                arrayList4 = arrayList;
                                                str4 = str;
                                                eVar4 = eVar5;
                                                hashMap2.put(wifiType.BSSID, new C0001a(i2 + 91, 0, wifiType.frequency, wifiType.SSID));
                                                if (wifiType.frequency > 5000) {
                                                    arrayList = arrayList4;
                                                    str = str4;
                                                    eVar5 = eVar4;
                                                    z = true;
                                                }
                                            } else {
                                                arrayList4 = arrayList;
                                                str4 = str;
                                                eVar4 = eVar5;
                                            }
                                            arrayList = arrayList4;
                                            str = str4;
                                            eVar5 = eVar4;
                                        }
                                        arrayList2 = arrayList;
                                        str2 = str;
                                        eVar3 = eVar5;
                                        for (WifiType next : scanned_fp) {
                                            int i3 = next.level;
                                            if (i3 > -91) {
                                                int i4 = i3 + 91;
                                                C0001a aVar = (C0001a) hashMap2.get(next.BSSID);
                                                if (aVar != null) {
                                                    aVar.b = i4;
                                                    hashMap2.put(next.BSSID, aVar);
                                                } else if (z || next.frequency < 5000) {
                                                    hashMap2.put(next.BSSID, new C0001a(0, i4, next.frequency, next.SSID));
                                                }
                                            }
                                        }
                                        float f4 = 0.0f;
                                        float f5 = 0.0f;
                                        float f6 = 0.0f;
                                        for (Entry value : hashMap2.entrySet()) {
                                            C0001a aVar2 = (C0001a) value.getValue();
                                            if (aVar2 != null) {
                                                float f7 = (float) aVar2.f49a;
                                                float f8 = (float) aVar2.b;
                                                if (f7 > 0.0f && f8 > 0.0f) {
                                                    float f9 = (f7 + f8) / 2.0f;
                                                    if (Math.abs(f7 - f9) <= 2.0f) {
                                                        f8 = f9;
                                                    } else {
                                                        f9 = f7;
                                                    }
                                                    f2 = f9;
                                                    f6 = (f9 * f8) + f6;
                                                } else if (aVar2.c > 5000) {
                                                    float f10 = a.b.a.i.a.f48a;
                                                    f8 *= f10;
                                                    f2 = f7 * f10;
                                                } else {
                                                    float f11 = a.b.a.i.a.b;
                                                    f2 = f7 * f11;
                                                    f8 = (float) ((((double) f11) + 0.1d) * ((double) f8));
                                                }
                                                f4 = (f2 * f2) + f4;
                                                f5 += f8 * f8;
                                            }
                                        }
                                        float f12 = (f4 + f5) - f6;
                                        float f13 = f12 > 0.0f ? f6 / f12 : 0.0f;
                                        float sqrt = (float) (Math.sqrt((double) f5) * Math.sqrt((double) f4));
                                        if (sqrt != 0.0f) {
                                            f3 = f6 / sqrt;
                                        }
                                        f = (f3 * 0.7f) + (f13 * 0.3f);
                                        if (f > 0.99f) {
                                            f = 0.99f;
                                        }
                                    }
                                    eVar6.f47a = f;
                                    double lat2 = station.getLat();
                                    eVar6.b = ((Math.acos((Math.cos(a.b.a.g.a.a(station.getLat() - d2)) * (Math.cos(a.b.a.g.a.a(d)) * Math.cos(a.b.a.g.a.a(lat2)))) + (Math.sin(a.b.a.g.a.a(d)) * Math.sin(a.b.a.g.a.a(lat2)))) * 180.0d) / 3.141592653589793d) * 60.0d * 1.1515d * 1.609344d;
                                    eVar6.c = station;
                                    if (i == 0) {
                                        e eVar7 = new e();
                                        eVar7.f47a = eVar6.f47a;
                                        eVar7.b = eVar6.b;
                                        eVar7.c = eVar6.c;
                                        eVar2 = eVar7;
                                    } else {
                                        eVar = eVar3;
                                        if (!(eVar.f47a >= eVar6.f47a)) {
                                            eVar2 = eVar6;
                                        }
                                    }
                                    arrayList3 = a.b.a.g.a.c;
                                    if (arrayList3 != null || arrayList3.isEmpty()) {
                                        str3 = str2;
                                    } else {
                                        str3 = str2;
                                        int indexOf = a.b.a.g.a.c.indexOf(str3);
                                        if (indexOf < 0 || indexOf >= a.b.a.g.a.c.size() - 1) {
                                            if (indexOf == a.b.a.g.a.c.size() - 1) {
                                                break;
                                            }
                                        } else {
                                            str6 = a.b.a.g.a.c.get(indexOf + 1);
                                            i++;
                                            arrayList5 = arrayList2;
                                        }
                                    }
                                    str6 = str3;
                                    i++;
                                    arrayList5 = arrayList2;
                                } else {
                                    arrayList2 = arrayList;
                                    str2 = str;
                                    eVar = eVar5;
                                }
                                eVar2 = eVar;
                                arrayList3 = a.b.a.g.a.c;
                                if (arrayList3 != null) {
                                }
                                str3 = str2;
                                str6 = str3;
                                i++;
                                arrayList5 = arrayList2;
                            }
                        }
                        station = null;
                        if (station == null) {
                        }
                        eVar2 = eVar;
                        arrayList3 = a.b.a.g.a.c;
                        if (arrayList3 != null) {
                        }
                        str3 = str2;
                        str6 = str3;
                        i++;
                        arrayList5 = arrayList2;
                    }
                    e eVar8 = eVar5;
                    if (eVar8 != null && eVar8.f47a >= 0.3f) {
                        place = new Place();
                        Station station2 = eVar8.c;
                        place.setName(station2.getPlacename());
                        place.setClient_code(station2.getClient_code());
                        place.setAccuracy(eVar8.f47a);
                        place.setThreshold(0.3f);
                        if (place == null) {
                            PlengiResponse plengiResponse = new PlengiResponse();
                            plengiResponse.echo_code = searchPlaceReq.getEcho_code();
                            plengiResponse.place = place;
                            String client_code = plengiResponse.place.getClient_code();
                            if (client_code != null) {
                                a.b.a.g.a.d = client_code;
                            }
                            f.a(i.f13a, plengiResponse);
                            return;
                        }
                        f.a(i.f13a, (PlengiResponse) null, searchPlaceReq.getType(), (String) PlengiResponse.LOCATION_ACQUISITION_FAIL);
                        return;
                    }
                }
                place = null;
                if (place == null) {
                }
            }
        }
    }

    public i(Context context) {
        f13a = context;
    }

    public void a(SearchPlaceReq searchPlaceReq, OnPlengiListener onPlengiListener) {
        if (a((BaseMessage) searchPlaceReq)) {
            PlengiResponse plengiResponse = new PlengiResponse();
            plengiResponse.echo_code = searchPlaceReq.getEcho_code();
            Location location = searchPlaceReq.getLocation();
            if (location != null) {
                String provider = location.getProvider();
                if (provider != null && !"dummy_provider".equals(provider)) {
                    PlengiResponse.Location location2 = new PlengiResponse.Location();
                    location2.setLat(location.getLat());
                    location2.setLng(location.getLng());
                    location2.setTime(location.getTime());
                    location2.setAccuracy(location.getAccuracy());
                    location2.setProvider("loplat");
                    plengiResponse.location = location2;
                }
            }
            Connection connection = searchPlaceReq.getConnection();
            if (connection != null) {
                ArrayList arrayList = new ArrayList();
                arrayList.add(new WifiType(connection.getBssid(), connection.getSsid(), connection.getRss(), connection.getFrequency()));
                a.b.a.c.a.b(f13a).a((String) "wifi_connection", (List<WifiType>) arrayList);
            }
            Call<SearchPlaceRes> call = null;
            try {
                call = l.a(searchPlaceReq.getType()).postSearchPlace(searchPlaceReq);
            } catch (Error | Exception unused) {
            }
            if (call != null) {
                if (VERSION.SDK_INT >= 29 && a.b.a.f.i.b && PlaceEngineBase.isBackground()) {
                    Context context = f13a;
                    if (a.b.a.f.i.f39a == null) {
                        String str = a.b.a.f.i.c;
                        if (!(str == null || a.b.a.f.i.d == 0 || a.b.a.f.i.f == 0)) {
                            try {
                                Builder showWhen = new Builder(context, str).setContentTitle(context.getString(a.b.a.f.i.d)).setSmallIcon(a.b.a.f.i.f).setProgress(0, 0, true).setShowWhen(false);
                                if (a.b.a.f.i.e != 0) {
                                    showWhen.setContentText(context.getString(a.b.a.f.i.e));
                                }
                                Intent launchIntentForPackage = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
                                if (launchIntentForPackage != null) {
                                    showWhen.setContentIntent(PendingIntent.getActivity(context, 0, launchIntentForPackage, 0));
                                }
                                a.b.a.f.i.f39a = showWhen.build();
                            } catch (NotFoundException e) {
                                e.printStackTrace();
                            } catch (Exception e2) {
                                e2.printStackTrace();
                            }
                        }
                    }
                    NotificationManagerCompat.from(context).notify(190828, a.b.a.f.i.f39a);
                    new Handler().postDelayed(new h(context), 3000);
                }
                call.enqueue(new a(this, searchPlaceReq, onPlengiListener, plengiResponse));
            }
        }
    }

    public void a(SearchPlaceRes searchPlaceRes, PlengiResponse plengiResponse, OnPlengiListener onPlengiListener) {
        String type = searchPlaceRes.getType();
        if (l.a(f13a)) {
            Advertisement ad = searchPlaceRes.getAd();
            if (ad != null) {
                plengiResponse.advertisement = ad;
                Context context = f13a;
                String alarm = ad.getAlarm();
                if ("noti".equals(alarm) || "noti_big".equals(alarm)) {
                    b.a(context).b(ad);
                }
            }
        }
        if ("success".equals(searchPlaceRes.getStatus())) {
            plengiResponse.result = 0;
            plengiResponse.place = searchPlaceRes.getPlace();
            plengiResponse.area = searchPlaceRes.getArea();
            plengiResponse.district = searchPlaceRes.getDistrict();
            plengiResponse.complex = searchPlaceRes.getComplex();
            plengiResponse.nearbys = searchPlaceRes.getNearbys();
            plengiResponse.geoFence = searchPlaceRes.getGeoFence();
            plengiResponse.requestId = searchPlaceRes.getRequestId();
            PlengiResponse.Location location = searchPlaceRes.getLocation();
            if (location != null) {
                plengiResponse.location = location;
            }
            Advertisement advertisement = plengiResponse.advertisement;
            if (!(advertisement == null || plengiResponse.place == null)) {
                long delay = advertisement.getDelay();
                if (RequestMessage.LEAVE_PLACE.equals(plengiResponse.advertisement.getDelay_type())) {
                    plengiResponse.place.advertisement = plengiResponse.advertisement;
                    plengiResponse.advertisement = null;
                } else if ("enter".equals(plengiResponse.advertisement.getDelay_type()) && delay > 0) {
                    plengiResponse.advertisement = null;
                }
            }
            if (RequestMessage.SEARCH_PLACE.equals(type) || RequestMessage.SEARCH_PLACE_CHECK.equals(type)) {
                if (a.b.a.g.a.o(f13a)) {
                    if (searchPlaceRes.getStations() != null) {
                        ArrayList<Station> stations = searchPlaceRes.getStations();
                        a.b.a.g.a.b = stations;
                        if (a.b.a.g.a.b != null) {
                            if (a.b.a.g.a.f41a == null) {
                                a.b.a.g.a.f41a = new HashMap<>();
                            }
                            if (a.b.a.g.a.c == null) {
                                a.b.a.g.a.c = new ArrayList<>();
                            }
                            if (stations.size() > 0) {
                                a.b.a.g.a.d = stations.get(0).getClient_code();
                            }
                            a.b.a.g.a.f41a.clear();
                            a.b.a.g.a.c.clear();
                            Iterator<Station> it = a.b.a.g.a.b.iterator();
                            while (it.hasNext()) {
                                Station next = it.next();
                                String client_code = next.getClient_code();
                                a.b.a.g.a.f41a.put(client_code, next);
                                a.b.a.g.a.c.add(client_code);
                            }
                        }
                    }
                    if (PlaceEngineBase.getSpecialtyRequest(f13a) != null) {
                        Place place = plengiResponse.place;
                        if (place != null) {
                            String client_code2 = place.getClient_code();
                            if (client_code2 != null) {
                                a.b.a.g.a.d = client_code2;
                            }
                        }
                    }
                }
                f.a(f13a, plengiResponse);
            } else if (RequestMessage.SEARCH_PLACE_CELL.equals(type) && onPlengiListener != null) {
                onPlengiListener.onSuccess(plengiResponse);
            } else if (RequestMessage.SEARCH_PLACE_GPS.equals(type)) {
                PlaceEngineBase.forwardMessageToClient(plengiResponse);
            } else {
                Context context2 = f13a;
                Place place2 = plengiResponse.place;
                int h = a.b.a.g.a.h(context2);
                plengiResponse.type = f.a(h);
                if (place2 != null) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(plengiResponse.type);
                    sb.append(":");
                    sb.append(place2.loplatid);
                    sb.append(", ");
                    sb.append(place2.name);
                    sb.append(", ");
                    sb.append(place2.accuracy);
                    sb.append("/");
                    sb.append(place2.threshold);
                    sb.toString();
                    Place place3 = plengiResponse.place;
                    if (place3 != null) {
                        String client_code3 = place3.getClient_code();
                        float accuracy = place3.getAccuracy();
                        float threshold = place3.getThreshold();
                        String d = a.b.a.g.a.d(context2);
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("client_code: ");
                        sb2.append(client_code3);
                        sb2.append(", previous: ");
                        sb2.append(d);
                        sb2.toString();
                        Place currentPlace = PlaceEngineBase.getCurrentPlace(context2);
                        f.a(place3, currentPlace);
                        if (h == 0) {
                            int f = f.f(context2);
                            if (f == 4) {
                                if (d == null || d.isEmpty() || !d.equals(client_code3)) {
                                    f.a(context2, 0);
                                    f.h(context2);
                                } else {
                                    f.a(context2, 5);
                                }
                            } else if (d == null && ((!"nexon".equals(l.k)) || (!(!"nexon".equals(l.k)) && accuracy > threshold && accuracy < 1.0f))) {
                                if (accuracy < threshold) {
                                    plengiResponse.placeEvent = 3;
                                    Place n = a.b.a.c.a.b(context2).n();
                                    if (n != null) {
                                        try {
                                            n.setTags(Long.toString(place3.getLoplatid()));
                                            a.b.a.c.a.b(context2).c(n);
                                        } catch (Exception unused) {
                                        }
                                    }
                                } else if (accuracy < threshold || accuracy >= 1.0f) {
                                    plengiResponse.placeEvent = 1;
                                } else {
                                    plengiResponse.placeEvent = 1;
                                    if (f == 0) {
                                        f.a(context2, 2);
                                    }
                                    f.b(context2, place3);
                                }
                                StringBuilder a2 = a.a.a.a.a.a("SEND SECOND ENTER EVENT --------------:");
                                a2.append(place3.name);
                                a2.toString();
                            }
                        } else if (h == 1) {
                            f.a(context2, h, place3, currentPlace);
                            if (accuracy > threshold) {
                                plengiResponse.placeEvent = 1;
                            } else {
                                plengiResponse.placeEvent = 3;
                            }
                            g.b(context2, place3, plengiResponse.location);
                        }
                    }
                } else {
                    f.b(context2, plengiResponse);
                }
                PlaceEngineBase.forwardMessageToClient(plengiResponse);
            }
        } else if (!RequestMessage.SEARCH_PLACE_CELL.equals(type) || onPlengiListener == null) {
            f.a(f13a, plengiResponse, type, searchPlaceRes.getReason());
        } else {
            plengiResponse.result = -1;
            plengiResponse.errorReason = searchPlaceRes.getReason();
            onPlengiListener.onFail(plengiResponse);
        }
        a(searchPlaceRes.getConfig(), false);
        a(searchPlaceRes.getAnid());
        if (LoplatLogger.DEBUG) {
            new Gson().toJson((Object) searchPlaceRes);
        }
    }

    public final void a(Throwable th, String str) {
        StringBuilder sb = new StringBuilder();
        sb.append(th.getMessage());
        sb.append(":");
        sb.append(str);
        sb.append("\n");
        sb.append(th.getStackTrace());
        sb.toString();
    }

    public final void a(String str) {
        if (str != null && !str.isEmpty()) {
            Context context = f13a;
            StringBuilder sb = new StringBuilder();
            sb.append("[ANID]");
            sb.append(str);
            sb.toString();
            PlaceEngineBase.setANID(f13a, str);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:101:0x01d6  */
    /* JADX WARNING: Removed duplicated region for block: B:103:0x01e2  */
    /* JADX WARNING: Removed duplicated region for block: B:128:? A[RETURN, SYNTHETIC] */
    /* JADX WARNING: Removed duplicated region for block: B:38:0x0089  */
    /* JADX WARNING: Removed duplicated region for block: B:39:0x008b  */
    /* JADX WARNING: Removed duplicated region for block: B:46:0x00a2  */
    /* JADX WARNING: Removed duplicated region for block: B:47:0x00a4  */
    /* JADX WARNING: Removed duplicated region for block: B:50:0x00b3  */
    /* JADX WARNING: Removed duplicated region for block: B:53:0x00c0  */
    /* JADX WARNING: Removed duplicated region for block: B:56:0x00cd  */
    /* JADX WARNING: Removed duplicated region for block: B:59:0x00d4  */
    /* JADX WARNING: Removed duplicated region for block: B:66:0x0139  */
    /* JADX WARNING: Removed duplicated region for block: B:69:0x015b  */
    /* JADX WARNING: Removed duplicated region for block: B:71:0x015e  */
    /* JADX WARNING: Removed duplicated region for block: B:81:0x018a  */
    /* JADX WARNING: Removed duplicated region for block: B:84:0x0197  */
    /* JADX WARNING: Removed duplicated region for block: B:93:0x01b9  */
    /* JADX WARNING: Removed duplicated region for block: B:96:0x01c0  */
    /* JADX WARNING: Removed duplicated region for block: B:99:0x01ce  */
    public final void a(SdkConfig sdkConfig, boolean z) {
        boolean z2;
        String adUrl;
        String placeUrl;
        boolean isManualApi;
        int sdkMode;
        boolean z3;
        String str;
        int i;
        if (sdkConfig == null) {
            return;
        }
        if (PlaceEngineBase.getEngineStatus(f13a) != 0 || z) {
            boolean z4 = false;
            if (VERSION.SDK_INT >= 28) {
                ArrayList<String> fgsNotiPatched = sdkConfig.getFgsNotiPatched();
                if (fgsNotiPatched != null && fgsNotiPatched.size() > 0) {
                    Iterator<String> it = fgsNotiPatched.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            break;
                        }
                        String[] split = it.next().split(":");
                        if (split.length >= 2 && Build.MANUFACTURER.equals(split[0])) {
                            str = split[1];
                            if (split.length == 3) {
                                try {
                                    i = Integer.parseInt(split[2]);
                                } catch (NumberFormatException unused) {
                                }
                            }
                        }
                    }
                }
                str = "";
                i = 0;
                PlaceEngineBase.saveFgsStopFgDelay(f13a, i);
                if (!PlaceEngineBase.saveFgsNotiPatchedDate(f13a, str)) {
                    z2 = true;
                    adUrl = sdkConfig.getAdUrl();
                    if (adUrl != null && !adUrl.isEmpty()) {
                        if (PlaceEngineBase.saveAdUrl(f13a, adUrl)) {
                            z2 = true;
                        } else {
                            l.c(1);
                        }
                    }
                    placeUrl = sdkConfig.getPlaceUrl();
                    if (placeUrl != null && !placeUrl.isEmpty()) {
                        if (PlaceEngineBase.savePlaceUrl(f13a, placeUrl)) {
                            z2 = true;
                        } else {
                            l.c(0);
                        }
                    }
                    isManualApi = sdkConfig.isManualApi();
                    if (!PlaceEngineBase.enableManualApiCall(f13a, isManualApi)) {
                        z2 = true;
                    }
                    if (!PlaceEngineBase.setUseADID(f13a, sdkConfig.isUseAdid())) {
                        z2 = true;
                    }
                    if (!PlaceEngineBase.enableCellPositioning(f13a, sdkConfig.isCellLocation())) {
                        z2 = true;
                    }
                    if (!sdkConfig.isCellLocation()) {
                        int periodCellMove = sdkConfig.getCellLoc().getPeriodCellMove() * 1000;
                        if (periodCellMove > 0) {
                            a.b.a.c.a.a(f13a, (String) "lhtibaq5ot47p0xrinly", (String) "48", periodCellMove, true);
                        }
                        int periodCellStay = sdkConfig.getCellLoc().getPeriodCellStay() * 1000;
                        if (periodCellStay > 0) {
                            a.b.a.c.a.a(f13a, (String) "lhtibaq5ot47p0xrinly", (String) "49", periodCellStay, true);
                        }
                        l.a(f13a, sdkConfig.getCellLoc().isAdByCell());
                        c.a(f13a, sdkConfig.getCellLoc().getLbsUrl());
                        a.b.a.c.a.b(f13a, c.b, SavedMoney.GIVE_TP_TELCOIN, sdkConfig.getCellLoc().getLbsId(), true);
                        a.b.a.c.a.b(f13a, c.b, "6", sdkConfig.getCellLoc().getLbsKey(), true);
                    } else {
                        l.a(f13a, false);
                        c.a(f13a, (String) "");
                    }
                    sdkMode = sdkConfig.getSdkMode();
                    int periodMove = sdkConfig.getPeriodMove() * 1000;
                    int periodStay = sdkConfig.getPeriodStay() * 1000;
                    if (!a.b.a.g.a.a(f13a, sdkMode, true)) {
                        z2 = true;
                    }
                    if (!isManualApi) {
                        if (sdkMode == 0) {
                            z3 = PlaceEngineBase.setScanPeriod(f13a, periodMove, periodStay, true);
                        } else if (sdkMode != 1) {
                            z3 = false;
                        } else {
                            z3 = PlaceEngineBase.setScanPeriodTracking(f13a, periodMove, true);
                        }
                        if (z3) {
                            a.b.a.c.a.b(f13a).b();
                        } else {
                            z2 = true;
                        }
                    }
                    if (!PlaceEngineBase.enableUnlockScreenScan(f13a, sdkConfig.isUnlockScreenScan())) {
                        z2 = true;
                    }
                    if (!PlaceEngineBase.enableAvoidDoze(f13a, sdkConfig.isAvoidDoze())) {
                        z2 = true;
                    }
                    int i2 = VERSION.SDK_INT;
                    if (i2 >= 23 && i2 <= 28 && !PlaceEngineBase.enableAvoidAppStandby(f13a, sdkConfig.isAvoidAppStandby())) {
                        z2 = true;
                    }
                    if (!PlaceEngineBase.enableActivityTransition(f13a, sdkConfig.getActivityRecognitionSetting())) {
                        z2 = true;
                    }
                    if (sdkConfig.isForceStop()) {
                        a.b.a.g.a.a(f13a, 0);
                    } else if (!a.b.a.g.a.a(f13a, sdkConfig.getUpdateCheckInterval())) {
                        z2 = true;
                    }
                    if (!z2) {
                        z4 = PlaceEngineBase.setConfigID(f13a, sdkConfig.getConfigID());
                    }
                    if (!z4) {
                        Context context = f13a;
                        StringBuilder a2 = a.a.a.a.a.a("Configuration Updated(ID:");
                        a2.append(sdkConfig.getConfigID());
                        a2.append(")");
                        a2.toString();
                        String userAdId = PlaceEngineBase.getUserAdId(f13a);
                        if (sdkConfig.isUseAdid()) {
                            if (userAdId == null) {
                                PlaceEngineBase.setANID(f13a, null);
                                PlaceEngineBase.updateADID(f13a);
                            }
                        } else if (userAdId != null) {
                            PlaceEngineBase.setANID(f13a, null);
                            PlaceEngineBase.setUserAdId(f13a, null);
                        }
                        if (!sdkConfig.isCellLocation()) {
                            c.b(f13a).c();
                        }
                        int engineStatus = PlaceEngineBase.getEngineStatus(f13a);
                        if (sdkConfig.isForceStop()) {
                            if (engineStatus == -1 || engineStatus == 1) {
                                PlaceEngineBase.stopPlaceEngineTemporarily(f13a);
                                return;
                            }
                            return;
                        } else if (engineStatus == 2) {
                            a.b.a.h.c.a(f13a);
                            PlaceEngineBase.reStartPlaceEngine(f13a);
                            return;
                        } else {
                            return;
                        }
                    } else {
                        return;
                    }
                } else {
                    ForegroundService foregroundService = ForegroundService.d;
                    if (foregroundService != null) {
                        foregroundService.a();
                    } else {
                        String str2 = ForegroundService.f56a;
                        new Object[1][0] = "fs is null";
                    }
                }
            }
            z2 = false;
            adUrl = sdkConfig.getAdUrl();
            if (PlaceEngineBase.saveAdUrl(f13a, adUrl)) {
            }
            placeUrl = sdkConfig.getPlaceUrl();
            if (PlaceEngineBase.savePlaceUrl(f13a, placeUrl)) {
            }
            isManualApi = sdkConfig.isManualApi();
            if (!PlaceEngineBase.enableManualApiCall(f13a, isManualApi)) {
            }
            if (!PlaceEngineBase.setUseADID(f13a, sdkConfig.isUseAdid())) {
            }
            if (!PlaceEngineBase.enableCellPositioning(f13a, sdkConfig.isCellLocation())) {
            }
            if (!sdkConfig.isCellLocation()) {
            }
            sdkMode = sdkConfig.getSdkMode();
            int periodMove2 = sdkConfig.getPeriodMove() * 1000;
            int periodStay2 = sdkConfig.getPeriodStay() * 1000;
            if (!a.b.a.g.a.a(f13a, sdkMode, true)) {
            }
            if (!isManualApi) {
            }
            if (!PlaceEngineBase.enableUnlockScreenScan(f13a, sdkConfig.isUnlockScreenScan())) {
            }
            if (!PlaceEngineBase.enableAvoidDoze(f13a, sdkConfig.isAvoidDoze())) {
            }
            int i22 = VERSION.SDK_INT;
            z2 = true;
            if (!PlaceEngineBase.enableActivityTransition(f13a, sdkConfig.getActivityRecognitionSetting())) {
            }
            if (sdkConfig.isForceStop()) {
            }
            if (!z2) {
            }
            if (!z4) {
            }
        }
    }

    public final boolean a(BaseMessage baseMessage) {
        String client_id = baseMessage.getClient_id();
        String client_secret = baseMessage.getClient_secret();
        if (client_id != null && !client_id.isEmpty() && client_secret != null && !client_secret.isEmpty()) {
            return true;
        }
        f.a(f13a, (PlengiResponse) null, baseMessage.getType(), (String) PlengiResponse.NOT_ENTERED_CLIENT_ACCOUNT);
        return false;
    }
}