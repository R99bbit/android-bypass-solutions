package com.igaworks.dao.tracking;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import com.igaworks.util.bolts_task.CustomSQLiteOpenHelper;

public class TrackingActivitySQLiteOpenHelper extends CustomSQLiteOpenHelper {
    private static final String DATABASE_NAME = "IgawTrackingActivitySQLiteDB.db";
    private static final int DATABASE_VERSION = 1;
    public static final String IP_CAMPAIGN_KEY = "campaign_key";
    public static final String IP_CONVERSION_KEY = "conversion_key";
    public static final String IP_CREATED_AT = "created_at";
    public static final String IP_IS_FIRST_TIME = "isFirstTime";
    public static final String IP_RESOURCE_KEY = "resource_key";
    public static final String IP_SPACE_KEY = "space_key";
    public static final String KEY_ID = "Id";
    static final String KEY_ISDIRTY = "isDirty";
    static final String KEY_NAME = "Name";
    static final String KEY_VALUE = "Value";
    public static final String TABLE_APP_TRACKING = "tbl_AppTracking";
    public static final String TABLE_IMPRESSION_TRACKING = "tbl_ImpressionTracking";

    public TrackingActivitySQLiteOpenHelper(Context context) {
        super(context, DATABASE_NAME, null, 1);
    }

    private void createSchema(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE tbl_AppTracking (Id INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT NOT NULL, Value TEXT NOT NULL, isDirty INTEGER DEFAULT 0, UNIQUE(Value));");
        db.execSQL("CREATE TABLE tbl_ImpressionTracking (Id INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT NOT NULL, Value TEXT NOT NULL, isDirty INTEGER DEFAULT 0, UNIQUE(Value));");
    }

    public void onCreate(SQLiteDatabase db) {
        createSchema(db);
    }

    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS tbl_AppTracking");
        db.execSQL("DROP TABLE IF EXISTS tbl_ImpressionTracking");
        createSchema(db);
    }

    public void clearDatabase(Context context) {
        context.deleteDatabase(DATABASE_NAME);
    }
}