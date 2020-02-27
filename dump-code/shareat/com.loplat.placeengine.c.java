package com.loplat.placeengine;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences.Editor;
import android.database.sqlite.SQLiteDatabase;
import android.net.wifi.ScanResult;
import com.loplat.placeengine.PlengiResponse.Place;
import com.loplat.placeengine.a.b;
import com.loplat.placeengine.d.a;
import com.loplat.placeengine.d.d;
import com.loplat.placeengine.utils.LoplatLogger;
import java.util.List;

/* compiled from: PlaceTracker */
public class c {
    static long a = 150000;
    static long b = 120000;

    /* JADX WARNING: type inference failed for: r13v0, types: [java.util.List, java.util.List<android.net.wifi.ScanResult>] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public static int a(Context context, List<ScanResult> r13) {
        if (com.loplat.placeengine.d.c.a(context, (List<ScanResult>) r13)) {
            a(context);
            List<d> scan = com.loplat.placeengine.d.c.a((List<ScanResult>) r13, context);
            if (scan == null || ((scan != null && scan.size() == 0) || a.a(scan) == 0.0f)) {
                return 1;
            }
            if (c(context) == 0) {
                a(context, 3);
                LoplatLogger.writeLog("----Tracker Status Change: Move ---> Premium");
            }
            LoplatLogger.writeLog("[TRACKER] SEARCH PREMIUM WIFI LIST ---------------------------: search_internal");
            b.b(context, scan);
            com.loplat.placeengine.d.c.a(context, scan, System.currentTimeMillis());
            return 2;
        } else if (!e(context)) {
            return 0;
        } else {
            a(context);
            List<d> scan2 = com.loplat.placeengine.d.c.b(context, (List<ScanResult>) r13);
            int prevState = c(context);
            if (scan2 == null) {
                return 1;
            }
            LoplatLogger.writeLog("----Tracker Status: " + prevState + ", scan no: " + scan2.size());
            if (a.a(scan2) == 0.0f) {
                return 1;
            }
            long scanTime = System.currentTimeMillis();
            switch (prevState) {
                case 0:
                    List<Long> scanIdList = com.loplat.placeengine.d.c.b(context);
                    if (scanIdList.size() > 0 && com.loplat.placeengine.d.b.a(scan2, com.loplat.placeengine.d.c.b(context, scanIdList.get(scanIdList.size() - 1).longValue())) >= 0.2f) {
                        LoplatLogger.writeLog("[TRACKER] ENTER STATIONARY ---------------------------: search_internal");
                        a(context, 1);
                        b.b(context, scan2);
                        break;
                    }
                case 1:
                case 3:
                    List<Long> scanIdList2 = com.loplat.placeengine.d.c.b(context);
                    if (scanIdList2.size() > 0 && com.loplat.placeengine.d.b.a(scan2, com.loplat.placeengine.d.c.b(context, scanIdList2.get(scanIdList2.size() - 1).longValue())) <= 0.7f) {
                        LoplatLogger.writeLog("[TRACKER] EXIT STATIONARY ---------------------------: ");
                        a(context, 0);
                        break;
                    }
                case 2:
                    List<Long> scanIdList3 = com.loplat.placeengine.d.c.b(context);
                    if (scanIdList3.size() > 0) {
                        float a2 = com.loplat.placeengine.d.b.a(scan2, com.loplat.placeengine.d.c.b(context, scanIdList3.get(scanIdList3.size() - 1).longValue()));
                        LoplatLogger.writeLog("[TRACKER] UPDATE STAY ---------------------------: search_internal");
                        b.b(context, scan2);
                        break;
                    }
                    break;
            }
            com.loplat.placeengine.d.c.a(context, scan2, scanTime);
            return 2;
        }
    }

    public static void a(Context context, Place place) {
        if (place != null) {
            if (c(context) == 1 || c(context) == 3) {
                if (place.accuracy < place.threshold) {
                    return;
                }
            } else if (c(context) == 2 && place.accuracy < place.threshold) {
                a(context, 0);
                a(context, 0);
                return;
            }
            a(context, 2);
            a(context, place.loplatid);
            com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
            synchronized (modedbm) {
                SQLiteDatabase db = modedbm.a(context);
                if (db != null) {
                    ContentValues insertValues = new ContentValues();
                    insertValues.put("name", place.name);
                    insertValues.put("tags", place.tags);
                    insertValues.put("category", place.category);
                    insertValues.put("floor", Integer.valueOf(place.floor));
                    insertValues.put("client_code", place.client_code);
                    insertValues.put("loplatid", Long.valueOf(place.loplatid));
                    insertValues.put("lat", Double.valueOf(place.lat));
                    insertValues.put("lng", Double.valueOf(place.lng));
                    insertValues.put("accuracy", Float.valueOf(place.accuracy));
                    insertValues.put("threshold", Float.valueOf(place.threshold));
                    db.insert("places", null, insertValues);
                } else {
                    LoplatLogger.writeLog("db is null!!");
                }
                modedbm.a(db);
            }
        } else if (c(context) == 2) {
            a(context, 0);
            d(context);
            a(context, 0);
        }
    }

    private static void d(Context context) {
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

    private static boolean e(Context context) {
        boolean available = false;
        long currTime = System.currentTimeMillis();
        long timeThreshold = (long) (((double) com.loplat.placeengine.c.a.d(context)) * 0.7d);
        if (c(context) == 1) {
            timeThreshold = (long) (((double) com.loplat.placeengine.c.a.c(context)) * 0.7d);
        }
        if (currTime - b(context) > timeThreshold) {
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

    public static void a(Context context) {
        try {
            Editor editor = context.getSharedPreferences("PlaceTracker", 0).edit();
            editor.putLong("lastscantime", System.currentTimeMillis());
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set last scan time error: " + e);
        }
    }

    public static long b(Context context) {
        long scanTime = 0;
        try {
            return context.getSharedPreferences("PlaceTracker", 0).getLong("lastscantime", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get last scan time error: " + e);
            return scanTime;
        }
    }

    public static void a(Context context, int trackerStatus) {
        try {
            Editor editor = context.getSharedPreferences("PlaceTracker", 0).edit();
            editor.putInt("trackerStatus", trackerStatus);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set tracker status error: " + e);
        }
    }

    public static int c(Context context) {
        int status = 0;
        try {
            return context.getSharedPreferences("PlaceTracker", 0).getInt("trackerStatus", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get tracker status error: " + e);
            return status;
        }
    }

    public static void a(Context context, long placeid) {
        try {
            Editor editor = context.getSharedPreferences("PlaceTracker", 0).edit();
            editor.putLong("placeid", placeid);
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set current place ID error: " + e);
        }
    }
}