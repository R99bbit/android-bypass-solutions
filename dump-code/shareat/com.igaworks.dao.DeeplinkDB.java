package com.igaworks.dao;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.CustomSQLiteOpenHelper;
import com.igaworks.util.bolts_task.Task;

public class DeeplinkDB {
    public static final String COMMERCE_CLICK_ID = "commerce_click_id";
    public static final String CONVERSION_KEY = "conversion_key";
    public static final String DATABASE_NAME = "deeplink.db";
    public static final String DATABASE_TABLE_CONVERSION_RESTORE = "ConversionRestore";
    public static final int DATABASE_VERSION = 4;
    static final String DEEPLINK_INFO = "deeplink_info";
    public static final String IS_DIRTY = "isDirty";
    public static final String KEY = "_id";
    public static final String LINK_PARAM = "link_param";
    public static final String RETRY_COUNT = "retry_count";
    public static final String TABLE_REENGAGEMENT_CONVERSION = "ReEngagementConversionTbl";
    public static final String TABLE_THIRD_PARTY_CONVERSION = "ThirdPartyConversionTbl";
    protected CommerceDBOpenHelper dbHelper;

    protected static class CommerceDBOpenHelper extends CustomSQLiteOpenHelper {
        private static String DATABASE_CREATE_CONVERSION_RESTORE = "create table ConversionRestore (%s integer primary key autoincrement, %s text not null, %s text not null, %s text, %s integer, %s integer, UNIQUE(%s, %s) ON CONFLICT REPLACE)";

        public CommerceDBOpenHelper(Context context, String name, CursorFactory factory, int version) {
            super(context, name, factory, version);
        }

        public void onCreate(SQLiteDatabase _db) {
            _db.execSQL(String.format(DATABASE_CREATE_CONVERSION_RESTORE, new Object[]{"_id", "conversion_key", DeeplinkDB.COMMERCE_CLICK_ID, DeeplinkDB.LINK_PARAM, "retry_count", DeeplinkDB.IS_DIRTY, "conversion_key", DeeplinkDB.COMMERCE_CLICK_ID}));
            _db.execSQL("CREATE TABLE ReEngagementConversionTbl (_id INTEGER PRIMARY KEY AUTOINCREMENT, conversion_key INTEGER, deeplink_info TEXT NOT NULL, retry_count INTEGER, isDirty INTEGER DEFAULT 0, UNIQUE(conversion_key));");
            _db.execSQL("CREATE TABLE ThirdPartyConversionTbl (_id INTEGER PRIMARY KEY AUTOINCREMENT, conversion_key INTEGER, deeplink_info TEXT NOT NULL, retry_count INTEGER, isDirty INTEGER DEFAULT 0, UNIQUE(conversion_key));");
        }

        public void onUpgrade(SQLiteDatabase _db, int _oldVersion, int _newVersion) {
            _db.execSQL("DROP TABLE IF EXISTS ConversionRestore");
            _db.execSQL("DROP TABLE IF EXISTS ReEngagementConversionTbl");
            _db.execSQL("DROP TABLE IF EXISTS ThirdPartyConversionTbl");
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