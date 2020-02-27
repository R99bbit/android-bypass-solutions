package com.loplat.placeengine.d;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences.Editor;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.wifi.ScanResult;
import android.os.Build.VERSION;
import android.os.SystemClock;
import com.loplat.placeengine.b;
import com.loplat.placeengine.c.a;
import com.loplat.placeengine.utils.LoplatLogger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

/* compiled from: WifiScanManager */
public class c {
    static final String[] a = {"iphone", "android", "ollehegg", "macbook", "pocket-fi", "imac", "wibro"};
    static final String[] b = {"cvs4u", "skp_4e21", "ministop", "withme", "korea7", "ofc_wlan"};
    private static final Comparator<d> c = new Comparator<d>() {
        /* renamed from: a */
        public int compare(d object1, d object2) {
            int a = object1.c;
            int b = object2.c;
            int cmp = a > b ? 1 : a < b ? -1 : 0;
            return cmp * -1;
        }
    };

    static int a(Context context) {
        int currStatus = b.h(context);
        if (currStatus == 0 || currStatus == 3) {
            return 30000;
        }
        return 120000;
    }

    public static List<d> a(List<ScanResult> scanResults, Context context) {
        long elapsedRealtime = SystemClock.elapsedRealtime();
        int timeoutCount = 0;
        long timeLimit = (long) a(context);
        List<d> scan = new ArrayList<>();
        for (ScanResult wifi : scanResults) {
            boolean exclude = false;
            if (wifi.SSID != null && wifi.SSID != "") {
                String ssidlow = wifi.SSID.toLowerCase();
                String[] strArr = a;
                int length = strArr.length;
                int i = 0;
                while (true) {
                    if (i >= length) {
                        break;
                    } else if (ssidlow.contains(strArr[i])) {
                        exclude = true;
                        break;
                    } else {
                        i++;
                    }
                }
            }
            if (!exclude) {
                if (VERSION.SDK_INT <= 16) {
                    d dVar = new d(wifi.BSSID, wifi.SSID, wifi.level, wifi.frequency);
                    scan.add(dVar);
                } else if (elapsedRealtime - (wifi.timestamp / 1000) < timeLimit) {
                    d dVar2 = new d(wifi.BSSID, wifi.SSID, wifi.level, wifi.frequency);
                    scan.add(dVar2);
                } else {
                    timeoutCount++;
                }
            }
        }
        if (scan.size() == 0) {
            return scan;
        }
        ArrayList<d> uniqueScan = new ArrayList<>();
        for (d orig : scan) {
            boolean duplicated = false;
            Iterator<d> it = uniqueScan.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                d wifi2 = it.next();
                if (orig.a.equals(wifi2.a) && orig.d == wifi2.d) {
                    duplicated = true;
                    break;
                }
            }
            if (!duplicated) {
                uniqueScan.add(orig);
            }
        }
        LoplatLogger.writeLog("Scan Time Out: " + timeoutCount + " / " + scanResults.size());
        Collections.sort(uniqueScan, c);
        return uniqueScan;
    }

    public static void a(Context context, List<d> scan, long scanTime) {
        com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
        synchronized (modedbm) {
            SQLiteDatabase db = modedbm.a(context);
            if (db != null) {
                for (d wifi : scan) {
                    ContentValues insertValues = new ContentValues();
                    insertValues.put("scanid", Long.valueOf(scanTime));
                    insertValues.put("bssid", wifi.a);
                    insertValues.put("ssid", wifi.b);
                    insertValues.put("rss", Integer.valueOf(wifi.c));
                    insertValues.put("frequency", Integer.valueOf(wifi.d));
                    db.insert("wifiscans", null, insertValues);
                }
            } else {
                LoplatLogger.writeLog("db is null @ storeScan");
            }
            modedbm.a(db);
        }
        a(context, scanTime);
    }

    public static void a(Context context, long scanTime) {
        com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
        synchronized (modedbm) {
            SQLiteDatabase db = modedbm.a(context);
            try {
                db.execSQL("DELETE FROM wifiscans WHERE scanid < " + String.valueOf(scanTime - 172800000));
            } catch (Exception e) {
                LoplatLogger.writeLog("[Exception] DELETE wifiscans DB: " + e);
            }
            modedbm.a(db);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:13:0x0070 A[SYNTHETIC, Splitter:B:13:0x0070] */
    public static List<d> b(Context context, long scanid) {
        List<d> footprints = new ArrayList<>();
        com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
        synchronized (modedbm) {
            SQLiteDatabase db = modedbm.a(context);
            Cursor cursor = null;
            try {
                Cursor cursor2 = db.rawQuery("select * from wifiscans where scanid = " + scanid, null);
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
                LoplatLogger.writeLog("[Exception] Read place DB: " + e);
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

    public static List<d> a(List<d> first, List<d> second) {
        List<d> mergedScan = new ArrayList<>();
        for (d wifi1 : first) {
            boolean found = false;
            Iterator<d> it = second.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                d wifi2 = it.next();
                if (wifi1.a.equals(wifi2.a) && wifi1.d == wifi2.d) {
                    mergedScan.add(new d(wifi1.a, wifi1.b, (wifi1.c + wifi2.c) / 2, wifi1.d));
                    found = true;
                    break;
                }
            }
            if (!found) {
                mergedScan.add(wifi1);
            }
        }
        for (d wifi22 : second) {
            boolean found2 = false;
            Iterator<d> it2 = mergedScan.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                d wifi = it2.next();
                if (wifi22.a.equals(wifi.a) && wifi.d == wifi22.d) {
                    found2 = true;
                    break;
                }
            }
            if (!found2) {
                mergedScan.add(wifi22);
            }
        }
        return mergedScan;
    }

    public static List<Long> b(Context context) {
        List<Long> scanList = new ArrayList<>();
        com.loplat.placeengine.b.b modedbm = com.loplat.placeengine.b.b.a();
        synchronized (modedbm) {
            SQLiteDatabase db = modedbm.a(context);
            Cursor cursor = null;
            try {
                Cursor cursor2 = db.rawQuery("select scanid from wifiscans order by scanid desc limit 1", null);
                if (cursor2.getCount() == 1) {
                    cursor2.moveToFirst();
                    scanList.add(Long.valueOf(cursor2.getLong(cursor2.getColumnIndex("scanid"))));
                }
                if (cursor2 != null) {
                    if (!cursor2.isClosed()) {
                        cursor2.close();
                    }
                }
            } catch (Exception e) {
                LoplatLogger.writeLog("[Exception] Read scan id list: " + e);
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
            modedbm.a(db);
        }
        return scanList;
    }

    public static boolean a(Context context, List<ScanResult> wifiLists) {
        if (wifiLists == null || (wifiLists != null && wifiLists.size() == 0)) {
            return false;
        }
        if (System.currentTimeMillis() - d(context) < 45000) {
            LoplatLogger.writeLog("--- skip to check premium wifi list (too short period) ---");
            return false;
        }
        long elapsedRealtime = SystemClock.elapsedRealtime();
        if (wifiLists != null && wifiLists.size() > 0) {
            for (ScanResult scanResult : wifiLists) {
                if (VERSION.SDK_INT <= 16) {
                    String ssid = scanResult.SSID.toLowerCase();
                    String[] strArr = b;
                    int length = strArr.length;
                    int i = 0;
                    while (i < length) {
                        if (!ssid.contains(strArr[i]) || scanResult.level <= -54) {
                            i++;
                        } else {
                            LoplatLogger.writeLog("Premium WiFi AP -> [SSID]: " + ssid.toUpperCase() + " [RSS]: " + scanResult.level);
                            c(context);
                            return true;
                        }
                    }
                    continue;
                } else if (elapsedRealtime - (scanResult.timestamp / 1000) < 30000) {
                    String ssid2 = scanResult.SSID.toLowerCase();
                    String[] strArr2 = b;
                    int length2 = strArr2.length;
                    int i2 = 0;
                    while (i2 < length2) {
                        if (!ssid2.contains(strArr2[i2]) || scanResult.level <= -54) {
                            i2++;
                        } else {
                            LoplatLogger.writeLog("Premium WiFi AP -> [SSID]: " + ssid2.toUpperCase() + " [RSS]: " + scanResult.level);
                            c(context);
                            return true;
                        }
                    }
                    continue;
                } else {
                    continue;
                }
            }
        }
        return false;
    }

    /* JADX WARNING: type inference failed for: r4v0, types: [java.util.List, java.util.List<android.net.wifi.ScanResult>] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public static List<d> b(Context context, List<ScanResult> r4) {
        List<d> scan = new ArrayList<>();
        if (r4 == 0 || r4.size() <= 0) {
            d wifiType = a.t(context);
            if (wifiType != null) {
                LoplatLogger.printLog("get connected wifi ap info");
                scan.add(wifiType);
            } else {
                LoplatLogger.printLog("There is no connected wifi ap");
                return null;
            }
        } else {
            scan = a((List<ScanResult>) r4, context);
        }
        return scan;
    }

    public static void c(Context context) {
        try {
            Editor editor = context.getSharedPreferences("WifiScanManager", 0).edit();
            editor.putLong("lastpremiumscantime", System.currentTimeMillis());
            editor.commit();
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] set wifi scan time for premium error: " + e);
        }
    }

    public static long d(Context context) {
        long scanTime = 0;
        try {
            return context.getSharedPreferences("WifiScanManager", 0).getLong("lastpremiumscantime", 0);
        } catch (Exception e) {
            LoplatLogger.writeLog("[Exception] get wifi scan time for premium error: " + e);
            return scanTime;
        }
    }
}