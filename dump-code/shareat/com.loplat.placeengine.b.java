package com.loplat.placeengine;

import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences.Editor;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.d.a;
import com.loplat.placeengine.d.c;
import com.loplat.placeengine.d.d;
import com.loplat.placeengine.location.LocationMonitorService;
import com.loplat.placeengine.utils.LoplatLogger;
import java.util.ArrayList;
import java.util.List;

/* compiled from: PlaceRecognizer */
public class b {
    /* JADX WARNING: type inference failed for: r37v0, types: [java.util.List, java.util.List<android.net.wifi.ScanResult>] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public static int a(Context context, List<ScanResult> r37) {
        List<d> mergedScan;
        List<d> mergedScan2;
        if (!l(context)) {
            return 0;
        }
        b(context);
        List<d> scan = c.b(context, (List<ScanResult>) r37);
        int prevState = h(context);
        if (scan == null) {
            return 1;
        }
        LoplatLogger.writeLog("----Place Status: " + prevState + ", scan no: " + scan.size());
        float energy = a.a(scan);
        if (energy == 0.0f) {
            return 1;
        }
        float currentThreshold = a.a(energy);
        long scanTime = System.currentTimeMillis();
        int curState = prevState;
        switch (prevState) {
            case 0:
                List<Long> scanIdList = c.b(context);
                LoplatLogger.writeLog("----Place Status: " + prevState + ", scanIdList size: " + scanIdList.size());
                if (scanIdList.size() > 0) {
                    long referenceScanTime = scanIdList.get(scanIdList.size() - 1).longValue();
                    float similarity = com.loplat.placeengine.d.b.a(scan, c.b(context, referenceScanTime));
                    LoplatLogger.writeLog("MOVE similarity: " + similarity + ", energy: " + energy + ", threshold: " + currentThreshold);
                    if (similarity >= currentThreshold) {
                        long timediff = scanTime - referenceScanTime;
                        if (timediff <= com.loplat.placeengine.c.a.f(context) || ((double) similarity) < 0.8d) {
                            curState = 1;
                        } else {
                            LoplatLogger.writeLog("MOVE ---> STAY: time diff: " + timediff);
                            curState = 2;
                        }
                        a(context, scanTime);
                        break;
                    }
                }
                break;
            case 1:
                float similarity2 = com.loplat.placeengine.d.b.a(scan, c.b(context, i(context)));
                LoplatLogger.writeLog("STATIONARY similarity: " + similarity2 + ", energy: " + energy + ", threshold: " + currentThreshold);
                if (similarity2 >= currentThreshold) {
                    if (-1 <= 0) {
                        long timediff2 = scanTime - i(context);
                        LoplatLogger.printLog("time diff: " + timediff2);
                        if (timediff2 <= com.loplat.placeengine.c.a.f(context)) {
                            curState = 1;
                            break;
                        } else {
                            curState = 2;
                            break;
                        }
                    } else {
                        curState = 2;
                        break;
                    }
                } else {
                    curState = 0;
                    break;
                }
            case 2:
                float staySimilarity = com.loplat.placeengine.d.b.a(scan, e(context));
                float threshold = (k(context) * 0.4f) + (0.6f * currentThreshold);
                LoplatLogger.writeLog("STAY similarity: " + staySimilarity + ", energy: " + energy + ", dynamic_threshold: " + threshold);
                if (staySimilarity < threshold) {
                    if (staySimilarity >= 0.05f) {
                        curState = 3;
                        try {
                            ((WifiManager) context.getSystemService("wifi")).startScan();
                            break;
                        } catch (Exception e) {
                            LoplatLogger.writeLog("[Exception] start wifi scan: " + e);
                            break;
                        }
                    } else {
                        LoplatLogger.writeLog("STAY ---> MOVE");
                        curState = 0;
                        break;
                    }
                }
                break;
            case 3:
                List<Long> scanIdList2 = c.b(context);
                LoplatLogger.writeLog("----Place Status: " + prevState + ", scanIdList size: " + scanIdList2.size());
                if (scanIdList2.size() > 0) {
                    mergedScan = c.a(scan, c.b(context, scanIdList2.get(scanIdList2.size() - 1).longValue()));
                } else {
                    mergedScan = scan;
                }
                float staySimilarity2 = com.loplat.placeengine.d.b.a(mergedScan, e(context));
                float threshold2 = ((k(context) * 0.4f) + (a.a(a.a(mergedScan)) * 0.6f)) * 0.9f;
                LoplatLogger.writeLog("STAY similarity: " + staySimilarity2 + ", energy: " + energy + ", dynamic_threshold: " + threshold2 + ", client_code: " + com.loplat.placeengine.c.a.l(context));
                if (staySimilarity2 < threshold2) {
                    if (com.loplat.placeengine.c.a.l(context) != null && staySimilarity2 > 0.05f) {
                        LoplatLogger.writeLog("------- STATE_LEAVING_CHECK -----");
                        curState = 4;
                        a(context, scanTime);
                        com.loplat.placeengine.a.b.b(context, scan);
                        break;
                    } else {
                        curState = 0;
                        break;
                    }
                } else {
                    curState = 2;
                    break;
                }
            case 4:
                LoplatLogger.writeLog("STATE_LEAVING_STATIONARY --> MOVE");
                curState = 0;
                break;
            case 5:
                float similarity3 = com.loplat.placeengine.d.b.a(scan, c.b(context, i(context)));
                LoplatLogger.writeLog("STATE_LEAVING_STATIONARY similarity: " + similarity3 + ", energy: " + energy + ", threshold: " + currentThreshold);
                if (similarity3 < currentThreshold) {
                    curState = 4;
                    a(context, scanTime);
                    com.loplat.placeengine.a.b.b(context, scan);
                    break;
                } else {
                    curState = 2;
                    break;
                }
        }
        if (prevState != curState) {
            LoplatLogger.writeLog("--- PlaceStatus Changed to --> " + curState);
            a(context, curState);
            if (curState == 2 && (prevState == 0 || prevState == 1 || prevState == 5)) {
                LoplatLogger.writeLog("-STAY---------------------------");
                List<Long> scanIdList3 = c.b(context);
                LoplatLogger.writeLog("----Place Status: " + prevState + ", scanIdList size: " + scanIdList3.size());
                if (scanIdList3.size() > 0) {
                    mergedScan2 = c.a(scan, c.b(context, scanIdList3.get(scanIdList3.size() - 1).longValue()));
                } else {
                    mergedScan2 = scan;
                }
                long placeid = d(context);
                b(context, mergedScan2);
                b(context, placeid);
                a(context, currentThreshold);
                f(context);
                LoplatLogger.writeLog("-STAY---------------------------: search_internal");
                com.loplat.placeengine.a.b.b(context, mergedScan2);
            } else if (curState == 0 && (prevState == 2 || prevState == 3 || prevState == 4)) {
                LoplatLogger.writeLog("-LEFT---------------------------");
                Place place = a.f(context);
                b(context, 0);
                m(context);
                g(context);
                if (place != null) {
                    if (place.name != null && !place.name.startsWith("unknown") && place.accuracy > place.threshold) {
                        long loplatid = place.loplatid;
                        com.loplat.placeengine.a.b.a(context, loplatid);
                        LoplatLogger.writeLog("Leave Event: " + loplatid + ", " + place.name);
                    }
                    try {
                        if (place.name.startsWith("unknown")) {
                            LoplatLogger.writeLog("-Do Not Send LEFT EVENT for unknown place-");
                        } else {
                            PlengiListener plengiListener = Plengi.getInstance(null).getListener();
                            PlengiResponse plengiResponse = new PlengiResponse();
                            plengiResponse.type = 2;
                            plengiResponse.placeEvent = 2;
                            plengiResponse.place = place;
                            LoplatLogger.writeLog("RECOGNIZER -> [LEAVE PLACE INFORMATION] -> " + place.loplatid + " " + place.name);
                            plengiListener.listen(plengiResponse);
                        }
                    } catch (NullPointerException e2) {
                        LoplatLogger.writeLog("[Exception] get place error: " + e2);
                    }
                }
                com.loplat.placeengine.c.a.m(context);
                com.loplat.placeengine.c.a.a(context, (String) null);
            }
        }
        c.a(context, scan, scanTime);
        return 2;
    }

    public static void a(Context context) {
        LoplatLogger.writeLog("FORCE-LEFT---------------------------");
        Place place = a.f(context);
        b(context, 0);
        m(context);
        g(context);
        if (place != null) {
            if (place.name != null && !place.name.startsWith("unknown") && place.accuracy > place.threshold) {
                long loplatid = place.loplatid;
                com.loplat.placeengine.a.b.a(context, loplatid);
                LoplatLogger.writeLog("Leave Event: " + loplatid + ", " + place.name);
            }
            try {
                if (place.name.startsWith("unknown")) {
                    LoplatLogger.writeLog("-Do Not Send LEFT EVENT for unknown place-");
                } else {
                    PlengiListener plengiListener = Plengi.getInstance(null).getListener();
                    PlengiResponse plengiResponse = new PlengiResponse();
                    plengiResponse.type = 2;
                    plengiResponse.placeEvent = 2;
                    plengiResponse.place = place;
                    LoplatLogger.writeLog("RECOGNIZER -> [FORCE LEAVE PLACE INFORMATION] -> " + place.loplatid + " " + place.name);
                    plengiListener.listen(plengiResponse);
                }
            } catch (NullPointerException e) {
                LoplatLogger.writeLog("[Exception] get place error: " + e);
            }
        }
        com.loplat.placeengine.c.a.m(context);
        com.loplat.placeengine.c.a.a(context, (String) null);
    }

    private static boolean l(Context context) {
        boolean available = false;
        if (h(context) == 3) {
            available = true;
        }
        if (System.currentTimeMillis() - c(context) > 60000) {
            available = true;
        } else {
            LoplatLogger.writeLog("--- skip wifi scan (too short period) ---");
        }
        int engineInProgress = a.m(context);
        if (engineInProgress == 1 || engineInProgress == 2) {
            return true;
        }
        return available;
    }

    public static void b(Context context) {
        try {
            Editor editor = context.getSharedPreferences("PlaceRecognizer", 0).edit();
            editor.putLong("lastscantime", System.currentTimeMillis());
            editor.commit();
        } catch (Exception e) {
        }
    }

    public static long c(Context context) {
        long scanTime = 0;
        try {
            return context.getSharedPreferences("PlaceRecognizer", 0).getLong("lastscantime", 0);
        } catch (Exception e) {
            return scanTime;
        }
    }

    public static long d(Context context) {
        com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
        long placeid = 0;
        synchronized (modedbm) {
            SQLiteDatabase db = modedbm.a(context);
            if (db != null) {
                ContentValues insertValues = new ContentValues();
                insertValues.put("name", "unknown place");
                placeid = db.insert("places", null, insertValues);
                LoplatLogger.writeLog("New Place id: " + placeid);
            }
            modedbm.a(db);
        }
        return placeid;
    }

    public static void b(Context context, List<d> scan) {
        com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
        synchronized (modedbm) {
            SQLiteDatabase db = modedbm.a(context);
            if (db != null) {
                ContentValues insertValues = new ContentValues();
                db.delete("footprint", null, null);
                for (d wifi : scan) {
                    insertValues.clear();
                    insertValues.put("bssid", wifi.a);
                    insertValues.put("ssid", wifi.b);
                    insertValues.put("rss", Integer.valueOf(wifi.c));
                    insertValues.put("frequency", Integer.valueOf(wifi.d));
                    db.insert("footprint", null, insertValues);
                }
            }
            modedbm.a(db);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:13:0x005f A[SYNTHETIC, Splitter:B:13:0x005f] */
    public static List<d> e(Context context) {
        List<d> footprints = new ArrayList<>();
        com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
        synchronized (modedbm) {
            SQLiteDatabase db = modedbm.a(context);
            Cursor cursor = null;
            try {
                Cursor cursor2 = db.rawQuery("select * from footprint", null);
                if (!cursor2.moveToFirst() || cursor2.getCount() <= 0) {
                    if (cursor2 != null) {
                        if (!cursor2.isClosed()) {
                            cursor2.close();
                        }
                    }
                    modedbm.a(db);
                } else {
                    do {
                        footprints.add(new d(cursor2.getString(cursor2.getColumnIndex("bssid")), cursor2.getString(cursor2.getColumnIndex("ssid")), cursor2.getInt(cursor2.getColumnIndex("rss")), cursor2.getInt(cursor2.getColumnIndex("frequency"))));
                    } while (cursor2.moveToNext());
                    if (cursor2 != null) {
                    }
                    modedbm.a(db);
                }
            } catch (Exception e) {
                LoplatLogger.printLog("[Exception] Read footprint DB: " + e);
                if (cursor != null) {
                    if (!cursor.isClosed()) {
                        cursor.close();
                    }
                }
            } catch (Throwable th) {
                if (cursor != null) {
                    if (!cursor.isClosed()) {
                        cursor.close();
                    }
                }
                throw th;
            }
        }
        return footprints;
    }

    public static void a(Context context, double lat, double lng, float accuracy, float threshold) {
        if (h(context) != 2) {
            return;
        }
        if (lat != 0.0d || lng != 0.0d) {
            com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
            synchronized (modedbm) {
                SQLiteDatabase db = modedbm.a(context);
                long placeid = j(context);
                float preAccuracy = 300.0f;
                Cursor cursor = null;
                try {
                    cursor = db.rawQuery("select * from places where _placeid = " + placeid, null);
                    if (cursor.getCount() == 1) {
                        cursor.moveToFirst();
                        preAccuracy = cursor.isNull(cursor.getColumnIndex("accuracy")) ? 300.0f : cursor.getFloat(cursor.getColumnIndex("accuracy"));
                    }
                    if (cursor != null) {
                        if (!cursor.isClosed()) {
                            cursor.close();
                        }
                    }
                } catch (Exception e) {
                    LoplatLogger.writeLog("[Exception] Read my visits: " + e);
                    if (cursor != null) {
                        if (!cursor.isClosed()) {
                            cursor.close();
                        }
                    }
                } catch (Throwable th) {
                    if (cursor != null && !cursor.isClosed()) {
                        cursor.close();
                    }
                    throw th;
                }
                LoplatLogger.writeLog("updateLocation: " + preAccuracy + " --> " + accuracy);
                if (db != null && ((accuracy < 1.0f && (accuracy > preAccuracy || preAccuracy == 300.0f)) || accuracy < preAccuracy)) {
                    ContentValues insertValues = new ContentValues();
                    insertValues.put("lat", Double.valueOf(lat));
                    insertValues.put("lng", Double.valueOf(lng));
                    insertValues.put("accuracy", Float.valueOf(accuracy));
                    insertValues.put("threshold", Float.valueOf(threshold));
                    db.update("places", insertValues, "_placeid=" + placeid, null);
                }
                modedbm.a(db);
            }
        }
    }

    public static void a(Context context, Place place) {
        if (h(context) == 2) {
            com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
            synchronized (modedbm) {
                SQLiteDatabase db = modedbm.a(context);
                if (db != null) {
                    long placeid = j(context);
                    ContentValues insertValues = new ContentValues();
                    insertValues.put("name", place.name);
                    insertValues.put("tags", place.tags);
                    insertValues.put("category", place.category);
                    insertValues.put("floor", Integer.valueOf(place.floor));
                    insertValues.put("client_code", place.client_code);
                    insertValues.put("loplatid", Long.valueOf(place.loplatid));
                    float preAccuracy = 300.0f;
                    Cursor cursor = null;
                    try {
                        cursor = db.rawQuery("select * from places where _placeid = " + placeid, null);
                        if (cursor.getCount() == 1) {
                            cursor.moveToFirst();
                            preAccuracy = cursor.isNull(cursor.getColumnIndex("accuracy")) ? 300.0f : cursor.getFloat(cursor.getColumnIndex("accuracy"));
                        }
                        if (cursor != null) {
                            if (!cursor.isClosed()) {
                                cursor.close();
                            }
                        }
                    } catch (Exception e) {
                        LoplatLogger.writeLog("[Exception] Read my visits: " + e);
                        if (cursor != null) {
                            if (!cursor.isClosed()) {
                                cursor.close();
                            }
                        }
                    } catch (Throwable th) {
                        if (cursor != null) {
                            if (!cursor.isClosed()) {
                                cursor.close();
                            }
                        }
                        throw th;
                    }
                    LoplatLogger.writeLog("updateLocation: " + preAccuracy + " --> " + place.accuracy);
                    if (!(place.lat == 0.0d && place.lng == 0.0d) && ((place.accuracy < 1.0f && (place.accuracy > preAccuracy || preAccuracy == 300.0f)) || place.accuracy < preAccuracy)) {
                        insertValues.put("lat", Double.valueOf(place.lat));
                        insertValues.put("lng", Double.valueOf(place.lng));
                        insertValues.put("accuracy", Float.valueOf(place.accuracy));
                        insertValues.put("threshold", Float.valueOf(place.threshold));
                    }
                    db.update("places", insertValues, "_placeid=" + placeid, null);
                    modedbm.a(db);
                }
            }
            com.loplat.placeengine.c.a.a(context, place.client_code);
        }
    }

    public static void a(Context context, String name, String tags, String category, int floor, String clientCode, long loplatid) {
        if (h(context) == 2) {
            com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
            synchronized (modedbm) {
                SQLiteDatabase db = modedbm.a(context);
                if (db != null) {
                    ContentValues insertValues = new ContentValues();
                    insertValues.put("name", name);
                    insertValues.put("tags", tags);
                    insertValues.put("category", category);
                    insertValues.put("floor", Integer.valueOf(floor));
                    insertValues.put("client_code", clientCode);
                    insertValues.put("loplatid", Long.valueOf(loplatid));
                    db.update("places", insertValues, "_placeid=" + j(context), null);
                    modedbm.a(db);
                }
            }
            com.loplat.placeengine.c.a.a(context, clientCode);
        }
    }

    private static void m(Context context) {
        com.loplat.placeengine.b.b modeDBManager = com.loplat.placeengine.b.b.a();
        synchronized (modeDBManager) {
            SQLiteDatabase db = modeDBManager.a(context);
            if (db != null) {
                try {
                    db.delete("places", null, null);
                    LoplatLogger.writeLog("delete old place info");
                } catch (Exception e) {
                }
                modeDBManager.a(db);
            }
        }
    }

    public static void f(Context context) {
        if (com.loplat.placeengine.c.a.n(context)) {
            Intent i = new Intent(context, LocationMonitorService.class);
            i.putExtra("command", "singleupdate");
            context.startService(i);
        }
    }

    public static void g(Context context) {
        if (com.loplat.placeengine.c.a.n(context) && com.loplat.placeengine.c.a.b(context, (String) "com.loplat.placeengine.location.LocationMonitorService")) {
            try {
                context.stopService(new Intent(context, LocationMonitorService.class));
            } catch (RuntimeException e) {
                LoplatLogger.writeLog("[Exception] stop service error: " + e);
            }
        }
    }

    public static void a(Context context, int placstatus) {
        try {
            Editor editor = context.getSharedPreferences("PlaceRecognizer", 0).edit();
            editor.putInt("placestatus", placstatus);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set place status error: " + e);
        }
    }

    public static int h(Context context) {
        int status = 0;
        try {
            return context.getSharedPreferences("PlaceRecognizer", 0).getInt("placestatus", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get place status error: " + e);
            return status;
        }
    }

    public static void a(Context context, long time) {
        try {
            Editor editor = context.getSharedPreferences("PlaceRecognizer", 0).edit();
            editor.putLong("staystarttime", time);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set stay start time error: " + e);
        }
    }

    public static long i(Context context) {
        long startTime = 0;
        try {
            return context.getSharedPreferences("PlaceRecognizer", 0).getLong("staystarttime", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get stay start time error: " + e);
            return startTime;
        }
    }

    public static void b(Context context, long placeid) {
        try {
            Editor editor = context.getSharedPreferences("PlaceRecognizer", 0).edit();
            editor.putLong("placeid", placeid);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set current place ID error: " + e);
        }
    }

    public static long j(Context context) {
        long placeId = 0;
        try {
            return context.getSharedPreferences("PlaceRecognizer", 0).getLong("placeid", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get current place ID error: " + e);
            return placeId;
        }
    }

    public static void a(Context context, float threshold) {
        try {
            Editor editor = context.getSharedPreferences("PlaceRecognizer", 0).edit();
            editor.putFloat("leavethreshold", threshold);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set place's threshold error: " + e);
        }
    }

    public static float k(Context context) {
        float threshold = 0.4f;
        try {
            return context.getSharedPreferences("PlaceRecognizer", 0).getFloat("leavethreshold", 0.4f);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get place's threshold error: " + e);
            return threshold;
        }
    }
}