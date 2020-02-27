package com.loplat.placeengine;

import android.content.Context;
import android.content.SharedPreferences.Editor;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.util.Patterns;
import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import com.google.android.gms.ads.identifier.AdvertisingIdClient.Info;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.a.b;
import com.loplat.placeengine.d.c;
import com.loplat.placeengine.d.d;
import com.loplat.placeengine.utils.LoplatLogger;
import java.io.IOException;
import java.util.List;

/* compiled from: PlaceEngine */
public class a {

    /* renamed from: com.loplat.placeengine.a$a reason: collision with other inner class name */
    /* compiled from: PlaceEngine */
    private static class C0093a extends AsyncTask<Void, Void, String> {
        private Context a;

        public C0093a(Context context) {
            this.a = context.getApplicationContext();
        }

        /* access modifiers changed from: protected */
        /* renamed from: a */
        public String doInBackground(Void... voids) {
            Info info = null;
            try {
                Info info2 = AdvertisingIdClient.getAdvertisingIdInfo(this.a);
                if (info2 == null) {
                    return null;
                }
                String adId = info2.getId();
                LoplatLogger.writeLog("get advertisingId: " + adId);
                return adId;
            } catch (IOException e) {
                e.printStackTrace();
                if (info == null) {
                    return null;
                }
                String adId2 = info.getId();
                LoplatLogger.writeLog("get advertisingId: " + adId2);
                return adId2;
            } catch (GooglePlayServicesNotAvailableException e2) {
                e2.printStackTrace();
                if (info == null) {
                    return null;
                }
                String adId3 = info.getId();
                LoplatLogger.writeLog("get advertisingId: " + adId3);
                return adId3;
            } catch (GooglePlayServicesRepairableException e3) {
                e3.printStackTrace();
                if (info == null) {
                    return null;
                }
                String adId4 = info.getId();
                LoplatLogger.writeLog("get advertisingId: " + adId4);
                return adId4;
            } catch (IllegalStateException e4) {
                e4.printStackTrace();
                if (info == null) {
                    return null;
                }
                String adId5 = info.getId();
                LoplatLogger.writeLog("get advertisingId: " + adId5);
                return adId5;
            } catch (Throwable th) {
                if (info == null) {
                    return null;
                }
                String adId6 = info.getId();
                LoplatLogger.writeLog("get advertisingId: " + adId6);
                return adId6;
            }
        }

        /* access modifiers changed from: protected */
        /* renamed from: a */
        public void onPostExecute(String str) {
            super.onPostExecute(str);
            String adId = str;
            if (adId == null) {
                if (adId != null) {
                    try {
                        if (adId.equals("")) {
                            return;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        return;
                    }
                } else {
                    return;
                }
            }
            String storedAdId = a.p(this.a);
            if (storedAdId == null || ((storedAdId != null && storedAdId.equals("")) || (storedAdId != null && !storedAdId.equals(adId)))) {
                a.b(this.a, adId);
                LoplatLogger.writeLog("update advertisingId: " + adId);
                b.a(this.a, a.o(this.a), adId);
            }
        }
    }

    /* compiled from: PlaceEngine */
    private static class b extends AsyncTask<Void, Void, String> {
        private Context a;
        private boolean b = false;

        public b(Context context, boolean uniqueUserIdStatus) {
            this.a = context;
            this.b = uniqueUserIdStatus;
        }

        /* access modifiers changed from: protected */
        /* renamed from: a */
        public String doInBackground(Void... voids) {
            Info info = null;
            try {
                Info info2 = AdvertisingIdClient.getAdvertisingIdInfo(this.a);
                if (info2 != null) {
                    return info2.getId();
                }
                return null;
            } catch (IOException e) {
                e.printStackTrace();
                if (info != null) {
                    return info.getId();
                }
                return null;
            } catch (GooglePlayServicesNotAvailableException e2) {
                e2.printStackTrace();
                if (info != null) {
                    return info.getId();
                }
                return null;
            } catch (GooglePlayServicesRepairableException e3) {
                e3.printStackTrace();
                if (info != null) {
                    return info.getId();
                }
                return null;
            } catch (VerifyError e4) {
                LoplatLogger.printLog("verift error: " + e4);
                e4.printStackTrace();
                if (info != null) {
                    return info.getId();
                }
                return null;
            } catch (Throwable th) {
                if (info != null) {
                    return info.getId();
                }
                return null;
            }
        }

        /* access modifiers changed from: protected */
        /* JADX WARNING: Code restructure failed: missing block: B:6:0x0010, code lost:
            if (r0.equals("") == false) goto L_0x0012;
         */
        /* renamed from: a */
        public void onPostExecute(String advertisingID) {
            super.onPostExecute(advertisingID);
            String adId = advertisingID;
            boolean isUpdatingUserAdIdRequired = false;
            if (adId == null) {
                if (adId != null) {
                    try {
                    } catch (Exception e) {
                        e.printStackTrace();
                        if (this.b || 0 != 0) {
                            LoplatLogger.printLog("update user information");
                            com.loplat.placeengine.a.b.a(this.a, a.o(this.a), adId);
                            return;
                        }
                        return;
                    } catch (Throwable th) {
                        if (this.b || 0 != 0) {
                            LoplatLogger.printLog("update user information");
                            com.loplat.placeengine.a.b.a(this.a, a.o(this.a), adId);
                        }
                        throw th;
                    }
                }
                if (!this.b || isUpdatingUserAdIdRequired) {
                    LoplatLogger.printLog("update user information");
                    com.loplat.placeengine.a.b.a(this.a, a.o(this.a), adId);
                }
                return;
            }
            String storedAdId = a.p(this.a);
            LoplatLogger.printLog("advertisingId: " + adId);
            if (storedAdId == null || ((storedAdId != null && storedAdId.equals("")) || (storedAdId != null && !storedAdId.equals(adId)))) {
                a.b(this.a, adId);
                isUpdatingUserAdIdRequired = true;
                LoplatLogger.printLog("new advertisingId: " + adId);
            }
            if (!this.b) {
            }
            LoplatLogger.printLog("update user information");
            com.loplat.placeengine.a.b.a(this.a, a.o(this.a), adId);
        }
    }

    public static int a(Context context, String clientId, String clientSecret, String uniqueUserId) {
        b.a(context, clientId);
        b.b(context, clientSecret);
        String storedUserId = o(context);
        LoplatLogger.printLog("StoredUserId: " + storedUserId);
        boolean isUpdatingUniqueUserIdRequired = false;
        if (storedUserId == null || ((storedUserId != null && a(storedUserId)) || (storedUserId != null && storedUserId.equals("")))) {
            if (uniqueUserId == null || uniqueUserId.equals("")) {
                uniqueUserId = Long.toString(System.currentTimeMillis());
            }
            if (storedUserId == null || !storedUserId.equals(uniqueUserId)) {
                a(context, uniqueUserId);
                LoplatLogger.printLog("UniqueUserId: " + uniqueUserId);
                isUpdatingUniqueUserIdRequired = true;
            }
        } else if (uniqueUserId != null && !uniqueUserId.equals("") && !storedUserId.equals(uniqueUserId)) {
            a(context, uniqueUserId);
            LoplatLogger.printLog("UniqueUserId: " + uniqueUserId);
            isUpdatingUniqueUserIdRequired = true;
        }
        try {
            new b(context, isUpdatingUniqueUserIdRequired).execute(new Void[0]);
        } catch (VerifyError e) {
            LoplatLogger.writeLog("[Exception] Init User ADID: " + e);
            if (isUpdatingUniqueUserIdRequired) {
                b.a(context, o(context), p(context));
            }
        }
        return 1;
    }

    private static boolean a(String storedUserId) {
        boolean isEmail = false;
        if (storedUserId == null || (storedUserId != null && storedUserId.trim().equals(""))) {
            return false;
        }
        if (Patterns.EMAIL_ADDRESS.matcher(storedUserId).matches()) {
            isEmail = true;
        }
        return isEmail;
    }

    public static void a(Context context) {
        try {
            new C0093a(context).execute(new Void[0]);
        } catch (VerifyError e) {
            LoplatLogger.writeLog("[Exception] Check User ADID: " + e);
        }
    }

    public static int b(Context context) {
        d(context, 1);
        try {
            ((WifiManager) context.getSystemService("wifi")).startScan();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] start wifi scan: " + e);
        }
        return 1;
    }

    public static int c(Context context) {
        d(context, 0);
        return 1;
    }

    public static int a(Context context, int monitoringType) {
        com.loplat.placeengine.c.a.d(context, monitoringType);
        return 1;
    }

    public static int d(Context context) {
        return com.loplat.placeengine.c.a.p(context);
    }

    public static int e(Context context) {
        if (com.loplat.placeengine.c.a.p(context) == 0) {
            int status = b.h(context);
            if (status == 0 || status == 1) {
                return 0;
            }
            return 2;
        } else if (com.loplat.placeengine.c.a.p(context) == 1 && c.c(context) == 2) {
            return 2;
        } else {
            return 0;
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:26:0x015f A[SYNTHETIC, Splitter:B:26:0x015f] */
    /* JADX WARNING: Removed duplicated region for block: B:35:0x016f A[SYNTHETIC, Splitter:B:35:0x016f] */
    /* JADX WARNING: Removed duplicated region for block: B:63:0x029b A[SYNTHETIC, Splitter:B:63:0x029b] */
    public static Place f(Context context) {
        Place placeInfo = null;
        com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
        synchronized (modedbm) {
            if (com.loplat.placeengine.c.a.p(context) == 0) {
                SQLiteDatabase db = modedbm.a(context);
                Cursor cursor_place = null;
                try {
                    cursor_place = db.rawQuery("select * from places where _placeid = " + b.j(context), null);
                    LoplatLogger.writeLog("cursor_place count: " + cursor_place.getCount());
                    if (cursor_place.getCount() == 1) {
                        Place placeInfo2 = new Place();
                        try {
                            cursor_place.moveToFirst();
                            placeInfo2.name = cursor_place.getString(cursor_place.getColumnIndex("name"));
                            placeInfo2.tags = cursor_place.getString(cursor_place.getColumnIndex("tags"));
                            placeInfo2.category = cursor_place.getString(cursor_place.getColumnIndex("category"));
                            placeInfo2.lat = cursor_place.getDouble(cursor_place.getColumnIndex("lat"));
                            placeInfo2.lng = cursor_place.getDouble(cursor_place.getColumnIndex("lng"));
                            placeInfo2.floor = cursor_place.getInt(cursor_place.getColumnIndex("floor"));
                            placeInfo2.accuracy = cursor_place.getFloat(cursor_place.getColumnIndex("accuracy"));
                            placeInfo2.threshold = cursor_place.getFloat(cursor_place.getColumnIndex("threshold"));
                            placeInfo2.client_code = cursor_place.getString(cursor_place.getColumnIndex("client_code"));
                            placeInfo2.loplatid = cursor_place.getLong(cursor_place.getColumnIndex("loplatid"));
                            LoplatLogger.writeLog("placename: " + placeInfo2.name + ",accuracy: " + placeInfo2.accuracy + ", lat: " + placeInfo2.lat + ", lng: " + placeInfo2.lng + ", client_code: " + placeInfo2.client_code + ", loplatid: " + placeInfo2.loplatid);
                            placeInfo = placeInfo2;
                        } catch (Exception e) {
                            e = e;
                            placeInfo = placeInfo2;
                            try {
                                LoplatLogger.writeLog("[Exception] Read my visits: " + e);
                                if (cursor_place != null) {
                                    if (!cursor_place.isClosed()) {
                                        cursor_place.close();
                                    }
                                }
                                modedbm.a(db);
                                return placeInfo;
                            } catch (Throwable th) {
                                th = th;
                                if (cursor_place != null) {
                                }
                                throw th;
                            }
                        } catch (Throwable th2) {
                            th = th2;
                            Place place = placeInfo2;
                            if (cursor_place != null) {
                                if (!cursor_place.isClosed()) {
                                    cursor_place.close();
                                }
                            }
                            throw th;
                        }
                    }
                    if (cursor_place != null) {
                        if (!cursor_place.isClosed()) {
                            cursor_place.close();
                        }
                    }
                } catch (Exception e2) {
                    e = e2;
                    LoplatLogger.writeLog("[Exception] Read my visits: " + e);
                    if (cursor_place != null) {
                    }
                    modedbm.a(db);
                    return placeInfo;
                }
                modedbm.a(db);
            } else if (com.loplat.placeengine.c.a.p(context) == 1 && c.c(context) == 2) {
                SQLiteDatabase db2 = modedbm.a(context);
                Cursor cursor_place2 = null;
                try {
                    cursor_place2 = db2.rawQuery("select * from places", null);
                    if (cursor_place2.getCount() > 0) {
                        Place placeInfo3 = new Place();
                        try {
                            cursor_place2.moveToLast();
                            placeInfo3.name = cursor_place2.getString(cursor_place2.getColumnIndex("name"));
                            placeInfo3.tags = cursor_place2.getString(cursor_place2.getColumnIndex("tags"));
                            placeInfo3.category = cursor_place2.getString(cursor_place2.getColumnIndex("category"));
                            placeInfo3.lat = cursor_place2.getDouble(cursor_place2.getColumnIndex("lat"));
                            placeInfo3.lng = cursor_place2.getDouble(cursor_place2.getColumnIndex("lng"));
                            placeInfo3.floor = cursor_place2.getInt(cursor_place2.getColumnIndex("floor"));
                            placeInfo3.accuracy = cursor_place2.getFloat(cursor_place2.getColumnIndex("accuracy"));
                            placeInfo3.threshold = cursor_place2.getFloat(cursor_place2.getColumnIndex("threshold"));
                            placeInfo3.client_code = cursor_place2.getString(cursor_place2.getColumnIndex("client_code"));
                            placeInfo3.loplatid = cursor_place2.getLong(cursor_place2.getColumnIndex("loplatid"));
                            LoplatLogger.writeLog("placename: " + placeInfo3.name + ",accuracy: " + placeInfo3.accuracy + ", lat: " + placeInfo3.lat + ", lng: " + placeInfo3.lng + ", client_code: " + placeInfo3.client_code);
                            placeInfo = placeInfo3;
                        } catch (Exception e3) {
                            e = e3;
                            placeInfo = placeInfo3;
                            try {
                                LoplatLogger.writeLog("[Exception] Read places: " + e);
                                if (cursor_place2 != null) {
                                }
                                modedbm.a(db2);
                                return placeInfo;
                            } catch (Throwable th3) {
                                th = th3;
                                if (cursor_place2 != null && !cursor_place2.isClosed()) {
                                    cursor_place2.close();
                                }
                                throw th;
                            }
                        } catch (Throwable th4) {
                            th = th4;
                            Place place2 = placeInfo3;
                            cursor_place2.close();
                            throw th;
                        }
                    }
                    if (cursor_place2 != null) {
                        if (!cursor_place2.isClosed()) {
                            cursor_place2.close();
                        }
                    }
                } catch (Exception e4) {
                    e = e4;
                    LoplatLogger.writeLog("[Exception] Read places: " + e);
                    if (cursor_place2 != null) {
                        if (!cursor_place2.isClosed()) {
                            cursor_place2.close();
                        }
                    }
                    modedbm.a(db2);
                    return placeInfo;
                }
                modedbm.a(db2);
            }
        }
        return placeInfo;
    }

    public static int g(Context context) {
        if (!com.loplat.placeengine.c.a.g(context)) {
            return 3;
        }
        if (com.loplat.placeengine.c.a.k(context) || !com.loplat.placeengine.c.a.h(context)) {
            return 4;
        }
        try {
            WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
            if (wifiManager != null) {
                e(context, 1);
                wifiManager.startScan();
                LoplatLogger.printLog("start wifi scan");
                return 1;
            }
            LoplatLogger.writeLog("WifiManager is null");
            return 4;
        } catch (Exception e) {
            e(context, 0);
            LoplatLogger.writeLog("[Exception] start wifi scan: " + e);
            return 4;
        }
    }

    public static int h(Context context) {
        if (!com.loplat.placeengine.c.a.g(context)) {
            return 3;
        }
        if (com.loplat.placeengine.c.a.k(context) || !com.loplat.placeengine.c.a.h(context)) {
            return 4;
        }
        try {
            WifiManager wifiManager = (WifiManager) context.getSystemService("wifi");
            if (wifiManager != null) {
                e(context, 1);
                wifiManager.startScan();
                LoplatLogger.printLog("start wifi scan");
                return 1;
            }
            LoplatLogger.writeLog("WifiManager is null");
            return 4;
        } catch (Exception e) {
            e(context, 0);
            LoplatLogger.writeLog("[Exception] start wifi scan: " + e);
            return 4;
        }
    }

    public static void b(Context context, int processingStatus) {
        int engineInProgress = m(context);
        if (engineInProgress == 1 || engineInProgress == 2) {
            LoplatLogger.writeLog("postProcessingWifiScan");
            if (processingStatus == 2) {
                List<Long> scanList = c.b(context);
                if (scanList.size() > 0) {
                    long latestScanTime = scanList.get(scanList.size() - 1).longValue();
                    LoplatLogger.printLog("getPlaceName: " + scanList.size() + ", " + latestScanTime);
                    List<d> latestScan = c.b(context, latestScanTime);
                    if (engineInProgress == 1) {
                        b.a(context, latestScan);
                    } else if (engineInProgress == 2) {
                        b.c(context, latestScan);
                    }
                }
            } else if (processingStatus == 1) {
                Plengi plengi = Plengi.getInstance(null);
                if (plengi != null) {
                    PlengiResponse plengiResponse = new PlengiResponse();
                    plengiResponse.type = 1;
                    plengiResponse.result = 2;
                    plengiResponse.errorReason = "Location Acquisition Fail";
                    plengi.getListener().listen(plengiResponse);
                }
            }
            e(context, 0);
        }
    }

    public static int i(Context context) {
        int environment = l(context);
        if (environment == 1) {
            LoplatLogger.writeLog("startColocate in place auto detection ");
            List<Long> scanList = c.b(context);
            List<d> prevScan = null;
            if (scanList.size() > 0) {
                prevScan = c.b(context, scanList.get(scanList.size() - 1).longValue());
            }
            b.d(context, prevScan);
        }
        return environment;
    }

    public static int j(Context context) {
        int environment = l(context);
        if (environment == 1) {
            LoplatLogger.writeLog("stopColocate in place auto detection ");
            b.b(context);
        }
        return environment;
    }

    public static int k(Context context) {
        int environment = l(context);
        if (environment == 1) {
            b.a(context);
        }
        return environment;
    }

    public static void a(Context context, int defaultPeriod, int stayPeriod) {
        com.loplat.placeengine.c.a.a(context, defaultPeriod);
        com.loplat.placeengine.c.a.b(context, stayPeriod);
    }

    public static void c(Context context, int defaultPeriod) {
        com.loplat.placeengine.c.a.c(context, defaultPeriod);
    }

    public static int l(Context context) {
        int result = 1;
        if (!com.loplat.placeengine.c.a.g(context)) {
            result = 3;
        } else if (!com.loplat.placeengine.c.a.i(context)) {
            result = 4;
        }
        LoplatLogger.printLog("isEngineWorkable: " + result);
        return result;
    }

    private static void e(Context context, int status) {
        try {
            Editor editor = context.getSharedPreferences("PLACEENGINE", 0).edit();
            editor.putInt("engineinprogress", status);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set engine progress status error: " + e);
        }
    }

    public static int m(Context context) {
        int progress = 0;
        try {
            return context.getSharedPreferences("PLACEENGINE", 0).getInt("engineinprogress", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get engine progress status error: " + e);
            return progress;
        }
    }

    public static void d(Context context, int status) {
        try {
            Editor editor = context.getSharedPreferences("PLACEENGINE", 0).edit();
            editor.putInt("enginestatus", status);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set engine status error: " + e);
        }
    }

    public static int n(Context context) {
        int status = 0;
        try {
            return context.getSharedPreferences("PLACEENGINE", 0).getInt("enginestatus", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get engine status error: " + e);
            return status;
        }
    }

    public static void a(Context context, String userid) {
        try {
            Editor editor = context.getSharedPreferences("PLACEENGINE", 0).edit();
            editor.putString("uniqueuserid", userid);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set user's unique user ID error: " + e);
        }
    }

    public static String o(Context context) {
        String uniqueUserId = null;
        try {
            return context.getSharedPreferences("PLACEENGINE", 0).getString("uniqueuserid", null);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get user's unique user ID error: " + e);
            return uniqueUserId;
        }
    }

    public static void b(Context context, String adId) {
        try {
            Editor editor = context.getSharedPreferences("PLACEENGINE", 0).edit();
            editor.putString("advertisementid", adId);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set user's ad ID error: " + e);
        }
    }

    public static String p(Context context) {
        String userAdId = null;
        try {
            return context.getSharedPreferences("PLACEENGINE", 0).getString("advertisementid", null);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get user's ad ID error: " + e);
            return userAdId;
        }
    }
}