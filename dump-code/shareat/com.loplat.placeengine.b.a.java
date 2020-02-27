package com.loplat.placeengine.b;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import com.loplat.placeengine.utils.LoplatLogger;

/* compiled from: DBHelper */
public class a extends SQLiteOpenHelper {
    protected Context a;

    public a(Context context) {
        super(context, "mode.db", null, 3);
        this.a = context;
    }

    public void onCreate(SQLiteDatabase db) {
        LoplatLogger.writeLog("DBHelper: onCreate");
        db.execSQL("CREATE TABLE wifiscaninfo (scanid INTEGER, lat DOUBLE, lng DOUBLE, accuracy INTEGER);");
        db.execSQL("CREATE TABLE wifiscans (scanid INTEGER, bssid TEXT, ssid TEXT, rss INTEGER, frequency INTEGER);");
        db.execSQL("CREATE TABLE footprint (placeid INTEGER, bssid TEXT, ssid TEXT, rss INTEGER, frequency INTEGER);");
        db.execSQL("CREATE TABLE places (_placeid INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, tags TEXT, category TEXT, address TEXT, lat DOUBLE, lng DOUBLE, floor INTEGER, accuracy REAL, threshold REAL, client_code TEXT, String clientid, loplatid INTEGER);");
        db.execSQL("CREATE TABLE place_wifi (placeid INTEGER, bssid TEXT, ssid TEXT, rss INTEGER, frequency INTEGER);");
        db.execSQL("CREATE TABLE my_visits (_visitid INTEGER PRIMARY KEY AUTOINCREMENT, placeid INTEGER, enter INTEGER, leave INTEGER, lat DOUBLE, lng DOUBLE, accuracy REAL);");
    }

    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if (oldVersion == 2 && newVersion == 3) {
            db.execSQL("DROP TABLE IF EXISTS wifiscaninfo");
            db.execSQL("DROP TABLE IF EXISTS wifiscans");
            db.execSQL("DROP TABLE IF EXISTS wifiscfootprintans");
            db.execSQL("DROP TABLE IF EXISTS places");
            db.execSQL("DROP TABLE IF EXISTS place_wifi");
            db.execSQL("DROP TABLE IF EXISTS my_visits");
            onCreate(db);
        }
    }
}