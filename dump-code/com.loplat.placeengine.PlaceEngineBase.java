package com.loplat.placeengine;

import a.b.a.b.i;
import a.b.a.b.l;
import a.b.a.e.e;
import a.b.a.f;
import a.b.a.g;
import a.b.a.h;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.Application;
import android.app.Application.ActivityLifecycleCallbacks;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.SystemClock;
import android.widget.Toast;
import androidx.annotation.RequiresApi;
import androidx.core.app.NotificationManagerCompat;
import co.habitfactory.signalfinance_embrain.comm.ResultCode;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import com.embrain.panelpower.IConstValue;
import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import com.google.android.gms.ads.identifier.AdvertisingIdClient.Info;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.PlengiResponse.Visit;
import com.loplat.placeengine.cloud.RequestMessage;
import com.loplat.placeengine.cloud.RequestMessage.Specialty;
import com.loplat.placeengine.cloud.RequestMessage.UpdateSdkConfigReq;
import com.loplat.placeengine.cloud.ResponseMessage.ActivityRecognition;
import com.loplat.placeengine.cloud.ResponseMessage.ConfigSdkEventRes;
import com.loplat.placeengine.service.ForegroundService;
import com.loplat.placeengine.service.PeriodicJobService;
import com.loplat.placeengine.wifi.WifiScanManager;
import com.loplat.placeengine.wifi.WifiType;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import retrofit2.Call;

public class PlaceEngineBase {
    public static final int DEFAULT_CONFIG_ID = 0;
    public static final String ENGINE_EVENT_SCAN_WIFI = "com.loplat.placeengine.event.scanwifi";
    public static final String PE_PREFS_NAME = "PLACEENGINE";
    public static final String PREFS_OLD_KEY_ENGINE_STATUS = "enginestatus";

    /* renamed from: a reason: collision with root package name */
    public static Set<Integer> f53a = null;
    public static boolean b = false;
    public static boolean c = false;
    public static boolean d = false;

    public class EngineInProgress {
        public static final int REQUEST_CELL_POSITIONING = 6;
        public static final int REQUEST_PLACE_CHECK = 4;
        public static final int REQUEST_PLACE_INFO = 1;
        public static final int REQUEST_PLACE_INFO_GPS = 7;
        public static final int REQUEST_PLACE_INFO_INTERNAL = 3;
        public static final int REQUEST_PLACE_INFO_UNLOCK_SCREEN = 2;
        public static final int REQUEST_UUIDP = 5;
        public static final int UNKNOWN = 0;

        public EngineInProgress(PlaceEngineBase placeEngineBase) {
        }
    }

    public class EngineProcessStatus {
        public static final int INVALID_SCAN_RESULTS = 2;
        public static final int INVALID_SCAN_TIME = 1;
        public static final int OLD_SCAN_RESULTS = 0;
        public static final int PROCESSED = 3;
        public static final int UNPROCESSED = -1;

        public EngineProcessStatus(PlaceEngineBase placeEngineBase) {
        }
    }

    public class EngineStatus {
        public static final int NOT_INITIALIZED = -1;
        public static final int STARTED = 1;
        public static final int STOPPED = 0;
        public static final int STOPPED_TEMP = 2;

        public EngineStatus(PlaceEngineBase placeEngineBase) {
        }
    }

    public class FpDataSource {
        public static final int ALL = 2;
        public static final int LOPLAT = 0;
        public static final int SELF = 1;

        public FpDataSource(PlaceEngineBase placeEngineBase) {
        }
    }

    private interface a {
    }

    private static class b implements ActivityLifecycleCallbacks {
        public b() {
            if (PlaceEngineBase.f53a == null) {
                PlaceEngineBase.f53a = new HashSet();
            }
        }

        public void onActivityCreated(Activity activity, Bundle bundle) {
        }

        public void onActivityDestroyed(Activity activity) {
        }

        public void onActivityPaused(Activity activity) {
        }

        public void onActivityResumed(Activity activity) {
        }

        public void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
        }

        public void onActivityStarted(Activity activity) {
            PlaceEngineBase.f53a.add(Integer.valueOf(activity.hashCode()));
        }

        public void onActivityStopped(Activity activity) {
            PlaceEngineBase.f53a.remove(Integer.valueOf(activity.hashCode()));
        }
    }

    private static class c extends AsyncTask<Void, Void, String> {

        /* renamed from: a reason: collision with root package name */
        public Context f54a;
        public a b;

        public c(Context context, a aVar) {
            this.f54a = context;
            this.b = aVar;
        }

        public Object doInBackground(Object[] objArr) {
            Void[] voidArr = (Void[]) objArr;
            try {
                Info advertisingIdInfo = AdvertisingIdClient.getAdvertisingIdInfo(this.f54a);
                if (advertisingIdInfo != null && !advertisingIdInfo.isLimitAdTrackingEnabled()) {
                    return advertisingIdInfo.getId();
                }
            } catch (Error | Exception unused) {
            }
            return null;
        }

        public void onPostExecute(Object obj) {
            String str = (String) obj;
            super.onPostExecute(str);
            if (str != null) {
                ((d) this.b).a(this.f54a, str);
                return;
            }
            ((d) this.b).a(this.f54a);
        }
    }

    public static void a(Context context) {
        f.c(context);
        a.b.a.e.f.a(context).a(3);
        e.a(context).b();
        if (VERSION.SDK_INT >= 26) {
            NotificationManagerCompat.from(context).cancel(141224);
            ((NotificationManager) context.getSystemService("notification")).deleteNotificationChannel("plengi_default_2");
        }
        a.b.a.g.a.h(context);
        if (l.a(context)) {
            a.b.a.a.a.b.a(context).e();
        }
        a.b.a.d.c.b(context).c();
    }

    public static void b(Context context) {
        if (getEngineStatus(context) == 2) {
            int a2 = a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "47", 0);
            if (a2 <= 0) {
                a.b.a.h.c.a(context);
                return;
            }
            int i = a2 * 3600000;
            if (VERSION.SDK_INT < 26 || a.b.a.g.a.m(context) < 26) {
                a.b.a.h.c.a(context, i);
            } else {
                PeriodicJobService.a(context, 28867, (long) i);
            }
        }
    }

    public static int checkDefaultEnvironment(Context context) {
        if (VERSION.SDK_INT < 14) {
            return -7;
        }
        return l.k == null ? -10 : 0;
    }

    public static void checkForceStopConfig(Context context) {
        Call<ConfigSdkEventRes> call;
        l.j = context;
        UpdateSdkConfigReq updateSdkConfigReq = new UpdateSdkConfigReq(context, RequestMessage.SDK_EVENT_UPDATE_CONFIG);
        i iVar = new i(context);
        try {
            call = l.a(updateSdkConfigReq.getType()).postConfigSdkEvent(updateSdkConfigReq);
        } catch (Error | Exception unused) {
            call = null;
        }
        if (call != null) {
            call.enqueue(new a.b.a.b.f(iVar, updateSdkConfigReq));
        }
        b(context);
    }

    public static void clearEngineInProgress(Context context) {
        a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "23", 0, true);
        a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "97", 0, true);
    }

    public static void disableForegroundMonitoring(boolean z) {
        c = z;
    }

    @TargetApi(23)
    public static boolean enableActivityTransition(Context context, ActivityRecognition activityRecognition) {
        if (activityRecognition == null || !activityRecognition.isValidSetting()) {
            e.a(context).b();
            return a.b.a.c.a.b(context).a();
        }
        if (1 == getEngineStatus(context)) {
            e.a(context).a();
        }
        return a.b.a.c.a.b(context).a(activityRecognition);
    }

    public static void enableAdNetwork(Context context, boolean z, boolean z2) {
        l.a(context, z, z2);
    }

    public static boolean enableAvoidAppStandby(Context context, boolean z) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_33, z, true);
    }

    public static boolean enableAvoidDoze(Context context, boolean z) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_32, z, true);
    }

    public static boolean enableCellPositioning(Context context, boolean z) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_30, z, true);
    }

    public static boolean enableManualApiCall(Context context, boolean z) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "39", z, true);
    }

    public static boolean enableUnlockScreenScan(Context context, boolean z) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_31, z, true);
    }

    public static int feedbackAdResult(Context context, int i, int i2) {
        if (!a.b.a.g.a.n(context)) {
            return -5;
        }
        l.a(context, i, i2);
        return 0;
    }

    public static void forwardMessageToClient(PlengiResponse plengiResponse) {
        Plengi instance = Plengi.getInstance(null);
        if (instance != null) {
            OnPlengiListener onPlengiListener = PlengiBase.mOnPlengiListener;
            if (onPlengiListener != null) {
                if (plengiResponse.result == 0) {
                    onPlengiListener.onSuccess(plengiResponse);
                } else {
                    onPlengiListener.onFail(plengiResponse);
                }
                if (plengiResponse.type != 9) {
                    PlengiBase.mOnPlengiListener = null;
                    return;
                }
                return;
            }
            PlengiListener listener = instance.getListener();
            if (listener != null) {
                listener.listen(plengiResponse);
            }
        }
    }

    public static String getANID(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "28", (String) null);
    }

    public static int getConfigId(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "37", 0);
    }

    public static Place getCurrentPlace(Context context) {
        int h = a.b.a.g.a.h(context);
        if (h == 0 || h == 1) {
            return a.b.a.c.a.b(context).n();
        }
        return null;
    }

    public static String getCurrentSdkVer(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "29", (String) null);
    }

    public static int getCurrentSdkVerCode(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "52", 0);
    }

    public static int getCurrentStatus(Context context) {
        if (a.b.a.g.a.h(context) == 0) {
            int f = f.f(context);
            if (f == 0 || f == 1) {
                return 0;
            }
        } else if (!(a.b.a.g.a.h(context) == 1 && g.j(context) == 2)) {
            return 0;
        }
        return 2;
    }

    public static String getEchoCode(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "26", (String) null);
    }

    public static int getEngineInProgress(Context context) {
        long elapsedRealtime = SystemClock.elapsedRealtime();
        long a2 = a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "97", 0);
        if (a2 >= elapsedRealtime || a2 <= elapsedRealtime - 5000) {
            return 0;
        }
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "23", 0);
    }

    public static int getEngineStatus(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "24", 0);
    }

    public static String getFgsNotiPatchedDate(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "101", (String) "");
    }

    public static int getFgsStopFgDelay(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "102", 0);
    }

    public static int getFpDataSource(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "38", 0);
    }

    public static int getMonitoringType(Context context) {
        return a.b.a.g.a.h(context);
    }

    public static int getPlaceInfoAfterUnlockScreen(Context context) {
        return startWiFiScan(context, 2);
    }

    public static int getPlaceInfoWithNewScan(Context context) {
        return getPlaceInfoWithNewScan(context, null);
    }

    public static ArrayList<Visit> getPlaceVisits(Context context) {
        return a.b.a.c.a.b(context).p();
    }

    public static ArrayList<Place> getPlaces(Context context) {
        return a.b.a.c.a.b(context).o();
    }

    public static Specialty getSpecialtyRequest(Context context) {
        return a.b.a.c.a.b(context).r();
    }

    public static boolean getUseADID(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "25", true);
    }

    public static String getUserAdId(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "27", (String) null);
    }

    /* JADX WARNING: Removed duplicated region for block: B:91:0x016f A[RETURN] */
    /* JADX WARNING: Removed duplicated region for block: B:92:0x0170  */
    public static int init(Context context, String str, String str2, String str3) {
        boolean z;
        if (VERSION.SDK_INT < 14) {
            return -7;
        }
        a.b.a.c.a.c(context);
        if (str == null || str.isEmpty() || str2 == null || str2.isEmpty()) {
            return -1;
        }
        if (61 != getCurrentSdkVerCode(context)) {
            setCurrentSdkVerCode(context, 61);
            setConfigID(context, 0);
            a.b.a.c.a.b(context).u();
        }
        if (VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26 && (context instanceof Application) && !b) {
            b = true;
            ((Application) context).registerActivityLifecycleCallbacks(new b());
            context.registerComponentCallbacks(new c(context));
        }
        l.j = context;
        l.k = str;
        l.l = str2;
        try {
            Editor edit = context.getSharedPreferences("lhtibaq5ot47p0xrinly", 0).edit();
            edit.remove("clientid").remove("clientsecret");
            edit.apply();
        } catch (Exception unused) {
        }
        l.f15a = a.b.a.d.c.c(l.j);
        a.b.a.c.a.b(context).b();
        int engineStatus = getEngineStatus(context);
        EventReceiver.a(context);
        if (engineStatus == 1 || engineStatus == 2) {
            if (VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26) {
                PeriodicJobService.b(context);
            }
            a.b.a.h.c.a(context);
            a.b.a.h.c.a(context, IConstValue.TIMEOUT);
            if (!a.b.a.g.a.q(context)) {
                a.b.a.e.f.a(context).a(2);
                a.b.a.d.c.b(context).b();
            }
            a.b.a.a.a.b.a(context).d();
            if (engineStatus == 1 && isActivityRecognitionEnabled(context)) {
                e.a(context).a();
            }
            if (engineStatus == 1) {
                a.b.a.f.a.a(context);
            }
        }
        try {
            PackageManager packageManager = context.getPackageManager();
            String packageName = context.getPackageName();
            if (packageManager != null) {
                if (packageManager.checkPermission("android.permission.INTERNET", packageName) == -1) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Permission denied. please check Manifest.permission.");
                    sb.append("INTERNET");
                    Toast.makeText(context, sb.toString(), 0).show();
                } else if (packageManager.checkPermission("android.permission.ACCESS_NETWORK_STATE", packageName) == -1) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("Permission denied. please check Manifest.permission.");
                    sb2.append("ACCESS_NETWORK_STATE");
                    Toast.makeText(context, sb2.toString(), 0).show();
                } else if (packageManager.checkPermission("android.permission.ACCESS_WIFI_STATE", packageName) == -1) {
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("Permission denied. please check Manifest.permission.");
                    sb3.append("ACCESS_WIFI_STATE");
                    Toast.makeText(context, sb3.toString(), 0).show();
                } else if (packageManager.checkPermission("android.permission.CHANGE_WIFI_STATE", packageName) == -1) {
                    StringBuilder sb4 = new StringBuilder();
                    sb4.append("Permission denied. please check Manifest.permission.");
                    sb4.append("CHANGE_WIFI_STATE");
                    Toast.makeText(context, sb4.toString(), 0).show();
                }
                z = false;
                if (z) {
                    return -1;
                }
                setEchoCode(context, str3);
                if (engineStatus == 2) {
                    checkForceStopConfig(context);
                }
                if (engineStatus != 0) {
                    if (getUseADID(context)) {
                        updateADID(context);
                    } else if (getANID(context) == null) {
                        l.c(context);
                    }
                    if (engineStatus == -1) {
                        setEngineStatus(context, 0);
                    }
                }
                if (VERSION.SDK_INT >= 26) {
                    NotificationManager notificationManager = (NotificationManager) context.getSystemService("notification");
                    if (notificationManager != null) {
                        for (NotificationChannel next : notificationManager.getNotificationChannels()) {
                            if ((a.b.a.f.a.a(next.getId(), KakaoTalkLinkProtocol.VALIDATION_DEFAULT) && a.b.a.f.a.a(next.getName(), a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "70", (String) KakaoTalkLinkProtocol.VALIDATION_DEFAULT)) && a.b.a.f.a.a(next.getDescription(), a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "71", (String) null))) || (a.b.a.f.a.a(next.getId(), "ads") && a.b.a.f.a.a(next.getName(), "alerts") && a.b.a.f.a.a(next.getDescription(), null)) || next.getId().equals("plengi_ongoing") || next.getId().equals("plengi_default")) {
                                notificationManager.deleteNotificationChannel(next.getId());
                            }
                        }
                    }
                }
                return 0;
            }
        } catch (Exception unused2) {
        }
        z = true;
        if (z) {
        }
    }

    public static boolean isActivityRecognitionEnabled(Context context) {
        return a.b.a.c.a.b(context).t();
    }

    public static boolean isAvoidAppStandbyEnabled(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_33, false);
    }

    public static boolean isAvoidDozeEnabled(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_32, false);
    }

    public static boolean isBackground() {
        Set<Integer> set = f53a;
        boolean z = true;
        if (set == null) {
            return VERSION.SDK_INT >= 26;
        }
        if (set.size() > 0) {
            z = false;
        }
        return z;
    }

    public static boolean isBackgroundWifiScanNotAllowed(Context context) {
        return VERSION.SDK_INT >= 29 && d && context.checkSelfPermission("android.permission.ACCESS_BACKGROUND_LOCATION") != 0;
    }

    public static boolean isCellPositioningEnabled(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_30, false);
    }

    public static boolean isEnabledAdNetwork(Context context) {
        return l.a(context);
    }

    public static boolean isManualApiCallEnabled(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "39", true);
    }

    public static boolean isPlaceEngineAvailable(Context context, String str) {
        int engineStatus = getEngineStatus(context);
        if (engineStatus == 2) {
            if (ENGINE_EVENT_SCAN_WIFI.equals(str)) {
                return true;
            }
        } else if (engineStatus == 1) {
            return true;
        }
        return false;
    }

    public static boolean isPlaceEngineInProgress(Context context) {
        return getEngineInProgress(context) != 0;
    }

    public static boolean isPlaceEngineStarted(Context context) {
        return 1 == getEngineStatus(context);
    }

    public static boolean isUnlockScreenScanEnabled(Context context) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_31, false);
    }

    public static void postProcessingWifiScan(Context context, int i, h hVar) {
        List<WifiType> list = hVar.c;
        int i2 = hVar.f42a;
        if (i2 == 3) {
            if (f.b(i)) {
                l.a(context, list, false, i);
            }
        } else if (i2 == 2) {
            PlengiResponse plengiResponse = new PlengiResponse(context);
            plengiResponse.type = 1;
            plengiResponse.result = -1;
            plengiResponse.errorReason = PlengiResponse.INVALID_SCAN_RESULTS;
            forwardMessageToClient(plengiResponse);
            setSpecialtyRequest(context, null);
        }
    }

    public static h processWifiScanIfNeeded(Context context, h hVar, List<ScanResult> list) {
        if (hVar.f42a == -1) {
            hVar = WifiScanManager.a(context, hVar, list);
            if (hVar.a()) {
                hVar.f42a = 3;
            } else {
                hVar.f42a = 2;
            }
        }
        return hVar;
    }

    public static int reStartPlaceEngine(Context context) {
        int checkDefaultEnvironment = checkDefaultEnvironment(context);
        if (checkDefaultEnvironment != 0) {
            return checkDefaultEnvironment;
        }
        if (getEngineStatus(context) != 2) {
            return -1;
        }
        EventReceiver.a(context);
        if (VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26) {
            PeriodicJobService.b(context);
        }
        a.b.a.a.a.b.a(context).d();
        a.b.a.c.a.b(context).b();
        int startWiFiScan = startWiFiScan(context, 3);
        StringBuilder sb = new StringBuilder();
        sb.append("reStartPlaceEngine:");
        sb.append(startWiFiScan);
        sb.toString();
        if (startWiFiScan == 0) {
            setEngineStatus(context, 1);
            a.b.a.e.f.a(context).a(0);
        }
        if (isActivityRecognitionEnabled(context)) {
            e.a(context).a();
        }
        a.b.a.f.a.a(context);
        return startWiFiScan;
    }

    public static boolean saveAdUrl(Context context, String str) {
        return a.b.a.c.a.b(context, "lhtibaq5ot47p0xrinly", "84", str, true);
    }

    public static boolean saveFgsNotiPatchedDate(Context context, String str) {
        return a.b.a.c.a.b(context, "lhtibaq5ot47p0xrinly", "101", str, true);
    }

    public static boolean saveFgsStopFgDelay(Context context, int i) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "102", i, true);
    }

    public static boolean savePlaceUrl(Context context, String str) {
        return a.b.a.c.a.b(context, "lhtibaq5ot47p0xrinly", "85", str, true);
    }

    /* JADX WARNING: Removed duplicated region for block: B:44:0x007d  */
    public static int scanWiFi(Context context, int i) {
        int i2 = -6;
        int i3 = 0;
        if (i == 3) {
            if (a.b.a.g.a.r(context) || !a.b.a.g.a.s(context)) {
                i3 = -6;
            }
            if (c && !isBackground()) {
                return -6;
            }
        } else if (!a.b.a.g.a.n(context)) {
            i3 = -5;
        } else if (a.b.a.g.a.r(context) || !a.b.a.g.a.s(context)) {
            i3 = -6;
        }
        if (i3 == 0) {
            try {
                WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
                if (wifiManager != null) {
                    if (!isPlaceEngineInProgress(context)) {
                        setEngineInProgress(context, i);
                        if (!wifiManager.startScan()) {
                            clearEngineInProgress(context);
                        } else {
                            a.b.a.c.a.b(context).c(SystemClock.elapsedRealtime());
                        }
                    }
                }
            } catch (Exception unused) {
            }
            if (i2 != 0 && isPlaceEngineStarted(context) && i == 3 && VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26) {
                a.b.a.h.c.c(context);
            }
            if (i2 != 0) {
                a.b.a.h.c.a(context, SignalLibConsts.REBOOT_DELAY_TIMER);
            }
            return i2;
        }
        i2 = i3;
        a.b.a.h.c.c(context);
        if (i2 != 0) {
        }
        return i2;
    }

    public static boolean setANID(Context context, String str) {
        return a.b.a.c.a.b(context, "lhtibaq5ot47p0xrinly", "28", str, true);
    }

    public static void setAdNotiLargeIcon(Context context, int i) {
        a.b.a.c.a.a(a.b.a.a.a.b.a(context).c, (String) "lhtibaq5ot47p0xrinly", (String) "18", i, true);
    }

    public static void setAdNotiSmallIcon(Context context, int i) {
        a.b.a.c.a.a(a.b.a.a.a.b.a(context).c, (String) "lhtibaq5ot47p0xrinly", (String) "17", i, true);
    }

    public static boolean setConfigID(Context context, int i) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "37", i, true);
    }

    public static boolean setCurrentSdkVer(Context context, String str) {
        return a.b.a.c.a.b(context, "lhtibaq5ot47p0xrinly", "29", str, true);
    }

    public static boolean setCurrentSdkVerCode(Context context, int i) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "52", i, true);
    }

    public static boolean setEchoCode(Context context, String str) {
        return a.b.a.c.a.b(context, "lhtibaq5ot47p0xrinly", "26", str, true);
    }

    public static void setEngineInProgress(Context context, int i) {
        a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "23", i, true);
        a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "97", SystemClock.elapsedRealtime(), true);
    }

    public static boolean setEngineStatus(Context context, int i) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "24", i, true);
    }

    public static boolean setFpDataSource(Context context, int i) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "38", i, true);
    }

    public static int setMonitoringType(Context context, int i, boolean z) {
        return a.b.a.g.a.a(context, i, z) ? 0 : -1;
    }

    public static boolean setScanPeriod(Context context, int i, int i2, boolean z) {
        boolean z2;
        boolean z3;
        if (z || (!z && isManualApiCallEnabled(context))) {
            if (i < 60000) {
                i = 60000;
            }
            z2 = a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) ResultCode.CODE_40, i, true);
            if (i2 < 120000) {
                i2 = SignalLibConsts.REBOOT_DELAY_TIMER;
            }
            z3 = a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "41", i2, true);
        } else {
            z3 = false;
            z2 = false;
        }
        if (!z2 || !z3) {
            return false;
        }
        return true;
    }

    public static boolean setScanPeriodTracking(Context context, int i, boolean z) {
        if (!z && (z || !isManualApiCallEnabled(context))) {
            return false;
        }
        if ("jinair".equals(l.k)) {
            if (i < 20000) {
                i = SignalLibConsts.NETWORK_TIMEOUT;
            }
        } else if (i < 60000) {
            i = 60000;
        }
        boolean z2 = true;
        if (a.b.a.g.a.k(context) != i) {
            if (isPlaceEngineStarted(context)) {
                a.b.a.h.c.c(context);
            }
            z2 = a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "42", i, true);
        }
        return z2;
    }

    public static void setSpecialtyRequest(Context context, Specialty specialty) {
        a.b.a.c.a.b(context).a(specialty);
    }

    public static boolean setUseADID(Context context, boolean z) {
        return a.b.a.c.a.a(context, (String) "lhtibaq5ot47p0xrinly", (String) "25", z, true);
    }

    public static void setUserAdId(Context context, String str) {
        a.b.a.c.a.b(context, "lhtibaq5ot47p0xrinly", "27", str, true);
    }

    @RequiresApi(26)
    public static void startForegroundServiceForLocation(Context context, Intent intent) {
        if (ForegroundService.e) {
            ForegroundService.a(intent);
        } else {
            context.startForegroundService(intent);
        }
    }

    public static int startPlaceEngine(Context context) {
        int checkDefaultEnvironment = checkDefaultEnvironment(context);
        if (checkDefaultEnvironment != 0) {
            return checkDefaultEnvironment;
        }
        int engineStatus = getEngineStatus(context);
        if (engineStatus != 0 && engineStatus != -1) {
            return engineStatus == 1 ? -8 : -1;
        }
        if (VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26) {
            PeriodicJobService.b(context);
        }
        a.b.a.a.a.b.a(context).d();
        a.b.a.c.a.b(context).b();
        int startWiFiScan = startWiFiScan(context, 3);
        StringBuilder sb = new StringBuilder();
        sb.append("startPlaceEngine:");
        sb.append(startWiFiScan);
        sb.toString();
        setEngineStatus(context, 1);
        a.b.a.e.f.a(context).a(0);
        if (isActivityRecognitionEnabled(context)) {
            e.a(context).a();
        }
        a.b.a.f.a.a(context);
        return 0;
    }

    public static int startWiFiScan(Context context, int i) {
        if (isBackground() && isBackgroundWifiScanNotAllowed(context)) {
            return -1;
        }
        if (!isBackground() || VERSION.SDK_INT < 26 || a.b.a.g.a.m(context) < 26) {
            return scanWiFi(context, i);
        }
        ForegroundService.a(context, i);
        return 0;
    }

    public static int stopPlaceEngine(Context context) {
        if (getEngineStatus(context) != 0) {
            if (VERSION.SDK_INT >= 26 && a.b.a.g.a.m(context) >= 26) {
                ForegroundService.f = false;
                PeriodicJobService.c(context);
            }
            setEngineStatus(context, 0);
            a.b.a.h.c.a(context);
            a(context);
            EventReceiver eventReceiver = EventReceiver.b;
            if (eventReceiver != null) {
                context.unregisterReceiver(eventReceiver);
                EventReceiver.b = null;
            }
            EventReceiver.a(context);
        }
        return 0;
    }

    public static int stopPlaceEngineTemporarily(Context context) {
        setEngineStatus(context, 2);
        b(context);
        a(context);
        return 0;
    }

    public static void updateADID(Context context) {
        new c(context, new d()).execute(new Void[0]);
    }

    public static int getPlaceInfoWithNewScan(Context context, Specialty specialty) {
        if (isBackground() || getEngineStatus(context) == 2) {
            return -1;
        }
        setSpecialtyRequest(context, specialty);
        int startWiFiScan = startWiFiScan(context, 1);
        if (startWiFiScan != 0) {
            setSpecialtyRequest(context, null);
        }
        return startWiFiScan;
    }
}