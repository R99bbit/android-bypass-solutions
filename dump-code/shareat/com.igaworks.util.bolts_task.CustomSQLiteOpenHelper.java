package com.igaworks.util.bolts_task;

import android.app.Activity;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import android.database.sqlite.SQLiteOpenHelper;

public abstract class CustomSQLiteOpenHelper {
    private final SQLiteOpenHelper helper;

    public abstract void onCreate(SQLiteDatabase sQLiteDatabase);

    public abstract void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2);

    public CustomSQLiteOpenHelper(Context context, String name, CursorFactory factory, int version) {
        this.helper = new SQLiteOpenHelper(context instanceof Activity ? context.getApplicationContext() : context, name, factory, version) {
            public void onOpen(SQLiteDatabase db) {
                super.onOpen(db);
                CustomSQLiteOpenHelper.this.onOpen(db);
            }

            public void onCreate(SQLiteDatabase db) {
                CustomSQLiteOpenHelper.this.onCreate(db);
            }

            public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
                CustomSQLiteOpenHelper.this.onUpgrade(db, oldVersion, newVersion);
            }
        };
    }

    public Task<CustomSQLiteDatabase> getReadableDatabaseAsync() {
        return getDatabaseAsync(false);
    }

    public Task<CustomSQLiteDatabase> getWritableDatabaseAsync() {
        return getDatabaseAsync(true);
    }

    private Task<CustomSQLiteDatabase> getDatabaseAsync(boolean writable) {
        return CustomSQLiteDatabase.openDatabaseAsync(this.helper, !writable ? 1 : 0);
    }

    public void onOpen(SQLiteDatabase db) {
    }
}