package a.b.a.b;

import a.b.a.d.c;
import a.b.a.f;
import android.content.Context;
import android.content.SharedPreferences.Editor;
import android.location.Location;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.google.gson.Gson;
import com.loplat.placeengine.OnPlengiListener;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.RefinedPlengiResponse;
import com.loplat.placeengine.cloud.CloudService;
import com.loplat.placeengine.cloud.RequestMessage;
import com.loplat.placeengine.cloud.RequestMessage.BaseMessage;
import com.loplat.placeengine.cloud.RequestMessage.CellTowerInfo;
import com.loplat.placeengine.cloud.RequestMessage.CheckPlaceInfo;
import com.loplat.placeengine.cloud.RequestMessage.Connection;
import com.loplat.placeengine.cloud.RequestMessage.LeavePlaceReq;
import com.loplat.placeengine.cloud.RequestMessage.RegisterUserReq;
import com.loplat.placeengine.cloud.RequestMessage.ReportPlaceEngineStatus;
import com.loplat.placeengine.cloud.RequestMessage.SearchPlaceReq;
import com.loplat.placeengine.cloud.RequestMessage.SendAdResultReq;
import com.loplat.placeengine.cloud.RequestMessage.Specialty;
import com.loplat.placeengine.cloud.ResponseMessage.LeavePlaceRes;
import com.loplat.placeengine.cloud.ResponseMessage.RegisterUserRes;
import com.loplat.placeengine.cloud.ResponseMessage.ReportPlaceEngState;
import com.loplat.placeengine.cloud.ResponseMessage.SearchPlaceRes;
import com.loplat.placeengine.utils.LoplatLogger;
import com.loplat.placeengine.wifi.WifiType;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import okhttp3.Interceptor;
import okhttp3.Interceptor.Chain;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClient.Builder;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

/* compiled from: CloudManager */
public class l {

    /* renamed from: a reason: collision with root package name */
    public static String f15a = "";
    public static Retrofit b = null;
    public static CloudService c = null;
    public static Retrofit d = null;
    public static CloudService e = null;
    public static Retrofit f = null;
    public static CloudService g = null;
    public static boolean h = false;
    public static String i = null;
    public static Context j = null;
    public static String k = null;
    public static String l = null;
    public static boolean m = false;
    public static long n = 0;
    public static final String o = "l";

    /* compiled from: CloudManager */
    private static class a implements Interceptor {
        public /* synthetic */ a(j jVar) {
        }

        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            if (request.body() == null || request.header("Content-Encoding") != null) {
                return chain.proceed(request);
            }
            Request request2 = null;
            try {
                request2 = request.newBuilder().header("User-Agent", l.i).header("Content-Encoding", "gzip").method(request.method(), new k(this, request.body())).build();
            } catch (Error | Exception unused) {
            }
            if (request2 == null) {
                return chain.proceed(request);
            }
            return chain.proceed(request2);
        }
    }

    /* compiled from: CloudManager */
    private static class b implements Interceptor {

        /* renamed from: a reason: collision with root package name */
        public String f16a;
        public String b;

        public b(String str, String str2) {
            this.f16a = str;
            this.b = str2;
        }

        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            return chain.proceed(request.newBuilder().url(request.url().newBuilder().addQueryParameter(this.f16a, this.b).build()).build());
        }
    }

    public static CloudService a(String str) {
        return a(a(j, str));
    }

    public static Retrofit b(int i2) {
        OkHttpClient okHttpClient;
        if (i == null) {
            i = System.getProperty("http.agent");
        }
        String str = "https://place-api.loplat.com/";
        if (i2 == 1) {
            if (d == null) {
                if (m) {
                    Builder c2 = c();
                    c2.addInterceptor(new b("bG9wbGF0", "v6-dot-staging-test-dot-"));
                    c2.addInterceptor(new a(null));
                    okHttpClient = c2.build();
                    str = "https://v6-dot-staging-test-dot-loplat-beagle.appspot.com/";
                } else {
                    okHttpClient = a();
                    String a2 = a.b.a.c.a.a(j, (String) "lhtibaq5ot47p0xrinly", (String) "84", (String) null);
                    if (a2 != null) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(a2);
                        sb.append("/");
                        str = sb.toString();
                    }
                }
                d = new Retrofit.Builder().baseUrl(str).addConverterFactory(GsonConverterFactory.create()).client(okHttpClient).build();
            }
            return d;
        } else if (i2 == 2) {
            if (f == null) {
                String str2 = f15a;
                f = new Retrofit.Builder().baseUrl(str2).addConverterFactory(GsonConverterFactory.create()).client(c().build()).build();
            }
            return f;
        } else {
            if (b == null) {
                if (m) {
                    str = "https://v6-dot-staging-test-dot-banded-totality-629.appspot.com/";
                } else {
                    String a3 = a.b.a.c.a.a(j, (String) "lhtibaq5ot47p0xrinly", (String) "85", (String) null);
                    if (a3 != null) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append(a3);
                        sb2.append("/");
                        str = sb2.toString();
                    }
                }
                b = new Retrofit.Builder().baseUrl(str).addConverterFactory(GsonConverterFactory.create()).client(a()).build();
            }
            return b;
        }
    }

    public static void b() {
    }

    public static void c(int i2) {
        if (i2 == 0) {
            b = null;
            c = null;
            a(0);
        } else if (i2 == 1) {
            d = null;
            e = null;
            a(1);
        } else if (i2 == 2) {
            f = null;
            g = null;
            a(2);
        }
    }

    public static boolean d() {
        return false;
    }

    public static CloudService a(int i2) {
        if (i2 == 1) {
            if (e == null) {
                e = (CloudService) b(1).create(CloudService.class);
            }
            return e;
        } else if (i2 == 2) {
            String c2 = c.c(j);
            if (!f15a.equals(c2)) {
                f15a = c2;
                f = null;
                g = null;
            }
            if (g == null) {
                g = (CloudService) b(2).create(CloudService.class);
            }
            return g;
        } else {
            if (c == null) {
                c = (CloudService) b(i2).create(CloudService.class);
            }
            return c;
        }
    }

    public static Builder c() {
        Builder builder = new Builder();
        builder.readTimeout(30, TimeUnit.SECONDS);
        builder.connectTimeout(10, TimeUnit.SECONDS);
        builder.writeTimeout(30, TimeUnit.SECONDS);
        builder.retryOnConnectionFailure(false);
        return builder;
    }

    public static void c(Context context) {
        j = context;
        RegisterUserReq registerUserReq = new RegisterUserReq(context, RequestMessage.SDK_EVENT_REGISTER_USER);
        i iVar = new i(context);
        if (iVar.a((BaseMessage) registerUserReq)) {
            Call<RegisterUserRes> call = null;
            try {
                call = a(registerUserReq.getType()).postRegisterUser(registerUserReq);
            } catch (Error | Exception unused) {
            }
            if (call != null) {
                call.enqueue(new e(iVar, registerUserReq));
            }
        }
    }

    public static int a(Context context, String str) {
        if (str.startsWith(RequestMessage.SEARCH_PLACE)) {
            if (!(context != null ? a(context) : false)) {
                return 0;
            }
            if (RequestMessage.SEARCH_PLACE_CELL.equals(str) && !a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "21", false)) {
                return 0;
            }
        } else if (!RequestMessage.FEEDBACK_AD_RESULT.equals(str)) {
            if (RequestMessage.UPLUS_LBS_REQUEST.equals(str)) {
                return 2;
            }
            return 0;
        }
        return 1;
    }

    public static OkHttpClient a() {
        Builder c2 = c();
        c2.addInterceptor(new a(null));
        return c2.build();
    }

    public static void a(Context context, List<WifiType> list, boolean z, int i2) {
        j = context;
        if (!z || !f.b(i2)) {
            long elapsedRealtime = SystemClock.elapsedRealtime();
            if (elapsedRealtime - n >= 5000) {
                n = elapsedRealtime;
                f.a(context, list, i2, (String) null);
            }
        }
    }

    public static void a(Context context, List list, Location location, OnPlengiListener onPlengiListener) {
        j = context;
        SearchPlaceReq searchPlaceReq = new SearchPlaceReq(context, RequestMessage.SEARCH_PLACE_CHECK);
        if (location != null) {
            RequestMessage.Location location2 = new RequestMessage.Location();
            location2.setLat(location.getLatitude());
            location2.setLng(location.getLongitude());
            location2.setTime(location.getTime());
            location2.setAccuracy(location.getAccuracy());
            location2.setProvider(location.getProvider());
            CellTowerInfo b2 = a.b.a.g.a.b(context);
            if (b2 != null) {
                location2.setCellInfo(b2);
            }
            if (a.b.a.g.a.p(context)) {
                location2.setVpn(Integer.valueOf(1));
            }
            searchPlaceReq.setLocation(location2);
        }
        searchPlaceReq.setScan(list);
        Connection f2 = a.b.a.g.a.f(context);
        if (f2.getNetwork() != null) {
            searchPlaceReq.setConnection(f2);
        }
        if (LoplatLogger.DEBUG) {
            new Gson().toJson((Object) searchPlaceReq);
        }
        i iVar = new i(context);
        Call<SearchPlaceRes> call = null;
        try {
            call = a(searchPlaceReq.getType()).postSearchPlace(searchPlaceReq);
        } catch (Error | Exception unused) {
        }
        if (call != null) {
            PlengiResponse plengiResponse = new PlengiResponse();
            plengiResponse.echo_code = searchPlaceReq.getEcho_code();
            if (location != null) {
                PlengiResponse.Location location3 = new PlengiResponse.Location();
                location3.setLat(location.getLatitude());
                location3.setLng(location.getLongitude());
                location3.setTime(location.getTime());
                location3.setAccuracy(location.getAccuracy());
                location3.setProvider(location.getProvider());
                plengiResponse.location = location3;
            }
            if (searchPlaceReq.getScan().size() < 1) {
                plengiResponse.result = -1;
                plengiResponse.errorReason = PlengiResponse.INVALID_SCAN_RESULTS;
                onPlengiListener.onFail(plengiResponse);
                return;
            }
            call.enqueue(new b(iVar, onPlengiListener, plengiResponse, searchPlaceReq));
        }
    }

    public static void b(Context context, String str) {
        j = context;
        ReportPlaceEngineStatus reportPlaceEngineStatus = new ReportPlaceEngineStatus(context, RequestMessage.SDK_EVENT_STATE_LOG);
        reportPlaceEngineStatus.setState(str);
        i iVar = new i(context);
        if (iVar.a((BaseMessage) reportPlaceEngineStatus)) {
            Call<ReportPlaceEngState> call = null;
            try {
                call = a(reportPlaceEngineStatus.getType()).postPlaceEngineStatus(reportPlaceEngineStatus);
            } catch (Error | Exception unused) {
            }
            if (call != null) {
                call.enqueue(new d(iVar, reportPlaceEngineStatus));
            }
        }
    }

    public static boolean b(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "20", false);
    }

    public static void a(Context context, String str, @Nullable List<WifiType> list, @Nullable Location location, @Nullable String str2) {
        j = context;
        SearchPlaceReq searchPlaceReq = new SearchPlaceReq(context, str);
        Specialty specialtyRequest = PlaceEngineBase.getSpecialtyRequest(context);
        if (specialtyRequest != null) {
            searchPlaceReq.setSpecialty(specialtyRequest);
            if (h) {
                List<WifiType> a2 = a.b.a.c.a.b(context).a((String) "subway_ap_candidate");
                if (a2.size() > 0) {
                    specialtyRequest.setCarAp(a2);
                }
                h = false;
            }
        }
        if (RequestMessage.SEARCH_PLACE_CHECK.equals(str)) {
            CheckPlaceInfo checkPlaceInfo = a.b.a.c.a.b(context).h;
            if (checkPlaceInfo != null) {
                searchPlaceReq.setCheckPlaceInfo(checkPlaceInfo);
                a.b.a.c.a.b(context).h = null;
            }
        }
        if (location != null) {
            RequestMessage.Location location2 = new RequestMessage.Location();
            location2.setLat(location.getLatitude());
            location2.setLng(location.getLongitude());
            location2.setTime(location.getTime());
            location2.setAccuracy(location.getAccuracy());
            location2.setProvider(location.getProvider());
            CellTowerInfo b2 = a.b.a.g.a.b(context);
            if (b2 != null) {
                location2.setCellInfo(b2);
            }
            if (a.b.a.g.a.p(context)) {
                location2.setVpn(Integer.valueOf(1));
            }
            searchPlaceReq.setLocation(location2);
            Place n2 = a.b.a.c.a.b(context).n();
            if (n2 != null && n2.loplatid == 0) {
                n2.setLat(location.getLatitude());
                n2.setLng(location.getLongitude());
                a.b.a.c.a.b(context).c(n2);
            }
        }
        searchPlaceReq.setScan(list);
        if (str2 != null) {
            searchPlaceReq.setUserActivity(str2);
        }
        Connection f2 = a.b.a.g.a.f(context);
        if (f2.getNetwork() != null) {
            searchPlaceReq.setConnection(f2);
        }
        if (LoplatLogger.DEBUG) {
            new Gson().toJson((Object) searchPlaceReq);
        }
        new i(context).a(searchPlaceReq, (OnPlengiListener) null);
    }

    public static void a(Context context, @NonNull Place place) {
        j = context;
        long j2 = place.loplatid;
        long j3 = place.duration_time;
        String str = place.category_code;
        LeavePlaceReq leavePlaceReq = new LeavePlaceReq(context, RequestMessage.LEAVE_PLACE);
        RequestMessage.Location location = new RequestMessage.Location();
        location.setLat(place.getLat());
        location.setLng(place.getLng());
        leavePlaceReq.setLocation(location);
        int i2 = (j2 > 0 ? 1 : (j2 == 0 ? 0 : -1));
        if (i2 == 0) {
            leavePlaceReq.setScan(f.e(context));
        }
        List<WifiType> a2 = a.b.a.c.a.b(j).a((String) "wifi_connection");
        if (a2 != null && !a2.isEmpty()) {
            WifiType wifiType = a2.get(0);
            Connection connection = new Connection();
            connection.setBssid(wifiType.BSSID);
            connection.setSsid(wifiType.SSID);
            connection.setRss(wifiType.level);
            connection.setFrequency(wifiType.frequency);
            leavePlaceReq.setConnection(connection);
        }
        leavePlaceReq.setPlaceid(j2);
        if (i2 == 0 && place.getTags() != null) {
            try {
                leavePlaceReq.setNear(Long.parseLong(place.getTags()));
            } catch (Exception unused) {
            }
        }
        leavePlaceReq.setDuration_time(j3);
        leavePlaceReq.setCategory_code(str);
        i iVar = new i(context);
        if (iVar.a((BaseMessage) leavePlaceReq)) {
            Call<LeavePlaceRes> call = null;
            try {
                call = a(leavePlaceReq.getType()).postLeavePlace(leavePlaceReq);
            } catch (Error | Exception unused2) {
            }
            if (call != null) {
                call.enqueue(new c(iVar, leavePlaceReq));
            }
        }
    }

    public static void a(Context context, int i2, int i3) {
        Call<Void> call;
        j = context;
        SendAdResultReq sendAdResultReq = new SendAdResultReq(RequestMessage.FEEDBACK_AD_RESULT);
        sendAdResultReq.setClient_id(k);
        sendAdResultReq.setMsgID(i2);
        sendAdResultReq.setResult(i3);
        sendAdResultReq.setPackageName(a.b.a.g.a.a(context));
        sendAdResultReq.setVer("2.0.8.2");
        i iVar = new i(context);
        try {
            call = a(sendAdResultReq.getType()).postFeedbackAdResult(sendAdResultReq);
        } catch (Error | Exception unused) {
            call = null;
        }
        if (call != null) {
            StringBuilder a2 = a.a.a.a.a.a("feedbackAdResult msg_id:");
            a2.append(sendAdResultReq.getMsgID());
            a2.append(", result:");
            a2.append(sendAdResultReq.getResult());
            call.enqueue(new g(iVar, a2.toString()));
        }
    }

    public static boolean a(Context context, boolean z, boolean z2) {
        boolean z3 = false;
        if (!z) {
            z2 = false;
        }
        try {
            Editor edit = context.getSharedPreferences("lhtibaq5ot47p0xrinly", 0).edit();
            edit.putBoolean("19", z);
            edit.putBoolean("20", z2);
            z3 = edit.commit();
        } catch (Exception unused) {
        }
        d = null;
        e = null;
        if (z) {
            a(1);
        }
        if (z) {
            a.b.a.a.a.b.a(context).d();
        } else {
            a.b.a.a.a.b.a(context).e();
        }
        return z3;
    }

    public static boolean a(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "19", false);
    }

    public static boolean a(Context context, boolean z) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "21", z, true);
    }

    public static void a(Context context, PlengiResponse plengiResponse) {
        a.b.a.c.a.b(context, "lhtibaq5ot47p0xrinly", "96", new Gson().toJson((Object) new RefinedPlengiResponse(plengiResponse.result, plengiResponse.errorReason, plengiResponse.district, plengiResponse.location)), true);
    }
}