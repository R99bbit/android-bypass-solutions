package com.loplat.placeengine.b;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import com.loplat.placeengine.utils.LoplatLogger;

/* compiled from: ModeDBManager */
public class b {
    private static String a = "ModeDBManager";
    private static b b = null;

    private b() {
    }

    public static synchronized b a() {
        b bVar;
        synchronized (b.class) {
            try {
                if (b == null) {
                    b = new b();
                }
                bVar = b;
            }
        }
        return bVar;
    }

    public void a(SQLiteDatabase database) {
        if (database != null) {
            try {
                database.close();
                LoplatLogger.writeLog("Close DB");
            } catch (Exception e) {
                LoplatLogger.writeLog("[Exception] close Db error: " + e);
            }
        }
    }

    public SQLiteDatabase a(Context context) {
        SQLiteDatabase db = null;
        try {
            db = new a(context).getWritableDatabase();
        } catch (SQLiteException e) {
            LoplatLogger.writeLog("[Exception] Get DB error: " + e);
        }
        LoplatLogger.writeLog("Get DB");
        return db;
    }
}