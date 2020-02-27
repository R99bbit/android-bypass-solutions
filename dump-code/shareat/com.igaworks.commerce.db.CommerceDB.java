package com.igaworks.commerce.db;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.CustomSQLiteOpenHelper;
import com.igaworks.util.bolts_task.Task;

public class CommerceDB {
    public static final String CATEGORY = "category";
    public static final String CREATE_AT = "create_at";
    public static final String CURRENCY = "currency";
    public static final String DATABASE_NAME = "commerce.db";
    public static final String DATABASE_TABLE_COMMERCE_EVENT_V2 = "CommerceEventV2";
    public static final String DATABASE_TABLE_PURCHASE_RESTORE = "PurchaseRestore";
    public static final int DATABASE_VERSION = 3;
    public static final String EVENT_JSON_VALUE = "event_json";
    public static final String IS_DIRTY = "is_Dirty";
    public static final String KEY = "_id";
    public static final String ORDER_ID = "order_id";
    public static final String PRICE = "price";
    public static final String PRODUCT_ID = "product_id";
    public static final String PRODUCT_NAME = "product_name";
    public static final String QUANTITY = "quantity";
    public static final String RETRY_COUNT = "retry_count";
    protected CommerceDBOpenHelper dbHelper;

    protected static class CommerceDBOpenHelper extends CustomSQLiteOpenHelper {
        private static String DATABASE_CREATE_COMMERCE_EVENT_V2 = "create table CommerceEventV2 (%s integer primary key autoincrement, %s text not null, %s integer, %s integer DEFAULT 0, UNIQUE(%s) ON CONFLICT REPLACE)";
        private static String DATABASE_CREATE_PURCHASE_RESTORE = "create table PurchaseRestore (%s integer primary key autoincrement, %s text, %s text not null, %s text not null, %s real not null, %s integer, %s text not null, %s text not null, %s text not null, %s integer, %s integer DEFAULT 0, UNIQUE(%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT REPLACE)";

        public CommerceDBOpenHelper(Context context, String name, CursorFactory factory, int version) {
            super(context, name, factory, version);
        }

        public void onCreate(SQLiteDatabase _db) {
            String createCommandPurchaseRestore = String.format(DATABASE_CREATE_PURCHASE_RESTORE, new Object[]{"_id", CommerceDB.ORDER_ID, CommerceDB.PRODUCT_ID, CommerceDB.PRODUCT_NAME, "price", "quantity", "currency", "category", CommerceDB.CREATE_AT, "retry_count", CommerceDB.IS_DIRTY, CommerceDB.ORDER_ID, CommerceDB.PRODUCT_ID, CommerceDB.PRODUCT_NAME, "price", "quantity", "currency", "category", CommerceDB.CREATE_AT});
            String createEventTableSQL = String.format(DATABASE_CREATE_COMMERCE_EVENT_V2, new Object[]{"_id", CommerceDB.EVENT_JSON_VALUE, "retry_count", CommerceDB.IS_DIRTY, CommerceDB.EVENT_JSON_VALUE});
            _db.execSQL(createCommandPurchaseRestore);
            _db.execSQL(createEventTableSQL);
        }

        public void onUpgrade(SQLiteDatabase _db, int _oldVersion, int _newVersion) {
            _db.execSQL("DROP TABLE IF EXISTS PurchaseRestore");
            _db.execSQL("DROP TABLE IF EXISTS CommerceEventV2");
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