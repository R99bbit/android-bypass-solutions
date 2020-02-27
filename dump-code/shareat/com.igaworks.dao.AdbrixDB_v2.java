package com.igaworks.dao;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import com.igaworks.interfaces.CommonInterface;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.CustomSQLiteOpenHelper;
import com.igaworks.util.bolts_task.Task;
import java.text.SimpleDateFormat;
import java.util.Locale;

public abstract class AdbrixDB_v2 {
    public static final String ACTIVITY = "activity";
    public static final String ACTIVITY_COUNTER_NO = "_id";
    public static final String CONVERSION_KEY = "conversion_key";
    public static final String COUNTER = "counter";
    public static final String DATABASE_NAME = "adbrix.db";
    public static final String DATABASE_TABLE_ALL_ACTIVITY = "AllActivityCounter";
    public static final String DATABASE_TABLE_CPE = "ActivityCounter";
    public static final String DATABASE_TABLE_RESTORE_ACTIVITY = "CounterForRestore";
    public static final String DATABASE_TABLE_RETRY_COMPLETE_CONVERSION = "RetryCompleteConversion";
    public static final int DATABASE_VERSION = 1;
    public static final String DAY = "day";
    public static final String DAY_UPDATED = "day_updated";
    public static final SimpleDateFormat DB_DATE_FORMAT = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.KOREA);
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
    protected AdbrixDBOpenHelper dbHelper;

    protected static class AdbrixDBOpenHelper extends CustomSQLiteOpenHelper {
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

    protected interface SQLiteDatabaseCallable<T> {
        T call(CustomSQLiteDatabase customSQLiteDatabase);
    }

    /* access modifiers changed from: protected */
    public <T> Task<T> runWithManagedConnection(final SQLiteDatabaseCallable<Task<T>> callable) {
        return this.dbHelper.getWritableDatabaseAsync().onSuccessTask(new Continuation<CustomSQLiteDatabase, Task<T>>() {
            public Task<T> then(Task<CustomSQLiteDatabase> task) throws Exception {
                final CustomSQLiteDatabase db = (CustomSQLiteDatabase) task.getResult();
                return ((Task) callable.call(db)).continueWithTask(new Continuation<T, Task<T>>() {
                    public Task<T> then(Task<T> task) throws Exception {
                        db.closeAsync();
                        return task;
                    }
                });
            }
        });
    }

    /* access modifiers changed from: protected */
    public Task<Void> runWithManagedTransaction(final SQLiteDatabaseCallable<Task<Void>> callable) {
        return this.dbHelper.getWritableDatabaseAsync().onSuccessTask(new Continuation<CustomSQLiteDatabase, Task<Void>>() {
            public Task<Void> then(Task<CustomSQLiteDatabase> task) throws Exception {
                final CustomSQLiteDatabase db = (CustomSQLiteDatabase) task.getResult();
                Task<Void> beginTransactionAsync = db.beginTransactionAsync();
                final SQLiteDatabaseCallable sQLiteDatabaseCallable = callable;
                return beginTransactionAsync.onSuccessTask(new Continuation<Void, Task<Void>>() {
                    public Task<Void> then(Task<Void> task) throws Exception {
                        final CustomSQLiteDatabase customSQLiteDatabase = db;
                        Task onSuccessTask = ((Task) sQLiteDatabaseCallable.call(db)).onSuccessTask(new Continuation<Void, Task<Void>>() {
                            public Task<Void> then(Task<Void> task) throws Exception {
                                return customSQLiteDatabase.setTransactionSuccessfulAsync();
                            }
                        });
                        final CustomSQLiteDatabase customSQLiteDatabase2 = db;
                        return onSuccessTask.continueWithTask(new Continuation<Void, Task<Void>>() {
                            public Task<Void> then(Task<Void> task) throws Exception {
                                customSQLiteDatabase2.endTransactionAsync();
                                customSQLiteDatabase2.closeAsync();
                                return task;
                            }
                        });
                    }
                });
            }
        });
    }

    /* access modifiers changed from: protected */
    public <T> Task<T> runWithManagedComplexTransaction(final SQLiteDatabaseCallable<Task<T>> callable) {
        return this.dbHelper.getWritableDatabaseAsync().onSuccessTask(new Continuation<CustomSQLiteDatabase, Task<T>>() {
            public Task<T> then(Task<CustomSQLiteDatabase> task) throws Exception {
                final CustomSQLiteDatabase db = (CustomSQLiteDatabase) task.getResult();
                Task<Void> beginTransactionAsync = db.beginTransactionAsync();
                final SQLiteDatabaseCallable sQLiteDatabaseCallable = callable;
                return beginTransactionAsync.onSuccessTask(new Continuation<Void, Task<T>>() {
                    public Task<T> then(Task<Void> task) throws Exception {
                        final CustomSQLiteDatabase customSQLiteDatabase = db;
                        Task onSuccessTask = ((Task) sQLiteDatabaseCallable.call(db)).onSuccessTask(new Continuation<T, Task<T>>() {
                            public Task<T> then(Task<T> task) throws Exception {
                                customSQLiteDatabase.setTransactionSuccessfulAsync();
                                return task;
                            }
                        });
                        final CustomSQLiteDatabase customSQLiteDatabase2 = db;
                        return onSuccessTask.continueWithTask(new Continuation<T, Task<T>>() {
                            public Task<T> then(Task<T> task) throws Exception {
                                customSQLiteDatabase2.endTransactionAsync();
                                customSQLiteDatabase2.closeAsync();
                                return task;
                            }
                        });
                    }
                });
            }
        });
    }
}