package com.igaworks.dao;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;
import com.igaworks.interfaces.CommonInterface;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import java.text.SimpleDateFormat;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

@Deprecated
public abstract class AdbrixDB {
    public static final String ACTIVITY = "activity";
    public static final String ACTIVITY_COUNTER_NO = "_id";
    public static final String CONVERSION_KEY = "conversion_key";
    public static final String COUNTER = "counter";
    public static final String DATABASE_NAME = "adbrix_backward.db";
    public static final String DATABASE_TABLE_ALL_ACTIVITY = "AllActivityCounter";
    public static final String DATABASE_TABLE_CPE = "ActivityCounter";
    public static final String DATABASE_TABLE_RESTORE_ACTIVITY = "CounterForRestore";
    public static final String DATABASE_TABLE_RETRY_COMPLETE_CONVERSION = "RetryCompleteConversion";
    public static final int DATABASE_VERSION = 1;
    public static final String DAY = "day";
    public static final String DAY_UPDATED = "day_updated";
    public static final SimpleDateFormat DB_DATE_FORMAT = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2);
    public static final String GROUP = "activity_group";
    public static final String HOUR = "hour";
    public static final String HOUR_UPDATED = "hour_updated";
    public static final String MONTH = "month";
    public static final String MONTH_UPDATED = "month_updated";
    public static final String NO_COUNTING_UPDATE_DATETIME = "no_counting_update_datetime";
    public static final String REGIST_DATETIME = "regist_datetime";
    public static final String RETRY_COUNT = "retry_count";
    public static final String UPDATE_DATETIME = "update_datetime";
    public static final String YEAR = "year";
    public static final String YEAR_UPDATED = "year_updated";
    protected static AdbrixDBOpenHelper dbHelper;
    protected Context context;
    protected SQLiteDatabase db;

    protected static class AdbrixDBOpenHelper extends SQLiteOpenHelper {
        private static String DATABASE_CREATE_ALL_ACTIVITY = "create table AllActivityCounter (%s integer primary key autoincrement, %s text not null, %s text not null, %s integer not null,UNIQUE(%s, %s) ON CONFLICT REPLACE)";
        private static String DATABASE_CREATE_CPE = "create table ActivityCounter (%s integer primary key autoincrement, %s integer not null, %s integer not null, %s integer not null, %s integer not null, %s text not null, %s text not null, %s integer, %s integer not null, %s integer not null, %s integer not null, %s integer not null, %s text, %s text, %s text,UNIQUE(%s, %s, %s, %s, %s, %s) ON CONFLICT REPLACE)";
        private static String DATABASE_CREATE_RESTORE_ACTIVITY = "create table CounterForRestore (%s integer primary key autoincrement, %s text not null, %s text not null, %s text not null)";
        private static String DATABASE_CREATE_RETRY_COMPLETE_CONVERSION = "create table RetryCompleteConversion (%s integer primary key, %s integer not null)";

        public AdbrixDBOpenHelper(Context context, String name, CursorFactory factory, int version) {
            super(context, name, factory, version);
        }

        public void onCreate(SQLiteDatabase _db) {
            _db.execSQL(String.format(DATABASE_CREATE_CPE, new Object[]{"_id", "year", "month", "day", "hour", "activity_group", "activity", "counter", "year_updated", "month_updated", "day_updated", "hour_updated", "regist_datetime", "update_datetime", "no_counting_update_datetime", "year", "month", "day", "hour", "activity_group", "activity"}));
            _db.execSQL(String.format(DATABASE_CREATE_ALL_ACTIVITY, new Object[]{"_id", "activity_group", "activity", "counter", "activity_group", "activity"}));
            _db.execSQL(String.format(DATABASE_CREATE_RESTORE_ACTIVITY, new Object[]{"_id", "activity_group", "activity", "regist_datetime"}));
            _db.execSQL(String.format(DATABASE_CREATE_RETRY_COMPLETE_CONVERSION, new Object[]{"conversion_key", "retry_count"}));
        }

        public void onUpgrade(SQLiteDatabase _db, int _oldVersion, int _newVersion) {
            _db.execSQL("DROP TABLE IF EXISTS ActivityCounter");
            _db.execSQL("DROP TABLE IF EXISTS AllActivityCounter");
            _db.execSQL("DROP TABLE IF EXISTS CounterForRestore");
            _db.execSQL("DROP TABLE IF EXISTS RetryCompleteConversion");
            onCreate(_db);
        }
    }

    public void open() throws SQLiteException {
        try {
            TaskUtils.wait(Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
                public Void then(Task<Void> task) throws Exception {
                    try {
                        AdbrixDB.this.db = AdbrixDB.dbHelper.getWritableDatabase();
                    } catch (SQLiteException e) {
                        AdbrixDB.this.db = AdbrixDB.dbHelper.getReadableDatabase();
                    }
                    return null;
                }
            }, (Executor) Task.BACKGROUND_EXECUTOR), 1000, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void close() {
        try {
            TaskUtils.wait(Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
                public Void then(Task<Void> task) throws Exception {
                    AdbrixDB.this.db.close();
                    return null;
                }
            }, (Executor) Task.BACKGROUND_EXECUTOR), 1000, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}