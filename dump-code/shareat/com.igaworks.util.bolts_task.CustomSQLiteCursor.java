package com.igaworks.util.bolts_task;

import android.annotation.TargetApi;
import android.content.ContentResolver;
import android.database.CharArrayBuffer;
import android.database.ContentObserver;
import android.database.Cursor;
import android.database.DataSetObserver;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;

class CustomSQLiteCursor implements Cursor {
    /* access modifiers changed from: private */
    public Cursor cursor;
    private Executor executor;

    public static Cursor create(Cursor cursor2, Executor executor2) {
        return VERSION.SDK_INT >= 14 ? cursor2 : new CustomSQLiteCursor(cursor2, executor2);
    }

    private CustomSQLiteCursor(Cursor cursor2, Executor executor2) {
        this.cursor = cursor2;
        this.executor = executor2;
    }

    public int getCount() {
        return this.cursor.getCount();
    }

    public int getPosition() {
        return this.cursor.getPosition();
    }

    public boolean move(int offset) {
        return this.cursor.move(offset);
    }

    public boolean moveToPosition(int position) {
        return this.cursor.moveToPosition(position);
    }

    public boolean moveToFirst() {
        return this.cursor.moveToFirst();
    }

    public boolean moveToLast() {
        return this.cursor.moveToLast();
    }

    public boolean moveToNext() {
        return this.cursor.moveToNext();
    }

    public boolean moveToPrevious() {
        return this.cursor.moveToPrevious();
    }

    public boolean isFirst() {
        return this.cursor.isFirst();
    }

    public boolean isLast() {
        return this.cursor.isLast();
    }

    public boolean isBeforeFirst() {
        return this.cursor.isBeforeFirst();
    }

    public boolean isAfterLast() {
        return this.cursor.isAfterLast();
    }

    public int getColumnIndex(String columnName) {
        return this.cursor.getColumnIndex(columnName);
    }

    public int getColumnIndexOrThrow(String columnName) throws IllegalArgumentException {
        return this.cursor.getColumnIndexOrThrow(columnName);
    }

    public String getColumnName(int columnIndex) {
        return this.cursor.getColumnName(columnIndex);
    }

    public String[] getColumnNames() {
        return this.cursor.getColumnNames();
    }

    public int getColumnCount() {
        return this.cursor.getColumnCount();
    }

    public byte[] getBlob(int columnIndex) {
        return this.cursor.getBlob(columnIndex);
    }

    public String getString(int columnIndex) {
        return this.cursor.getString(columnIndex);
    }

    public void copyStringToBuffer(int columnIndex, CharArrayBuffer buffer) {
        this.cursor.copyStringToBuffer(columnIndex, buffer);
    }

    public short getShort(int columnIndex) {
        return this.cursor.getShort(columnIndex);
    }

    public int getInt(int columnIndex) {
        return this.cursor.getInt(columnIndex);
    }

    public long getLong(int columnIndex) {
        return this.cursor.getLong(columnIndex);
    }

    public float getFloat(int columnIndex) {
        return this.cursor.getFloat(columnIndex);
    }

    public double getDouble(int columnIndex) {
        return this.cursor.getDouble(columnIndex);
    }

    @TargetApi(11)
    public int getType(int columnIndex) {
        return this.cursor.getType(columnIndex);
    }

    public boolean isNull(int columnIndex) {
        return this.cursor.isNull(columnIndex);
    }

    @Deprecated
    public void deactivate() {
        this.cursor.deactivate();
    }

    @Deprecated
    public boolean requery() {
        return this.cursor.requery();
    }

    public void close() {
        Task.call((Callable<TResult>) new Callable<Void>() {
            public Void call() throws Exception {
                CustomSQLiteCursor.this.cursor.close();
                return null;
            }
        }, this.executor);
    }

    public boolean isClosed() {
        return this.cursor.isClosed();
    }

    public void registerContentObserver(ContentObserver observer) {
        this.cursor.registerContentObserver(observer);
    }

    public void unregisterContentObserver(ContentObserver observer) {
        this.cursor.unregisterContentObserver(observer);
    }

    public void registerDataSetObserver(DataSetObserver observer) {
        this.cursor.registerDataSetObserver(observer);
    }

    public void unregisterDataSetObserver(DataSetObserver observer) {
        this.cursor.unregisterDataSetObserver(observer);
    }

    public void setNotificationUri(ContentResolver cr, Uri uri) {
        this.cursor.setNotificationUri(cr, uri);
    }

    @TargetApi(19)
    public Uri getNotificationUri() {
        return this.cursor.getNotificationUri();
    }

    public boolean getWantsAllOnMoveCalls() {
        return this.cursor.getWantsAllOnMoveCalls();
    }

    public Bundle getExtras() {
        return this.cursor.getExtras();
    }

    public Bundle respond(Bundle extras) {
        return this.cursor.respond(extras);
    }

    @TargetApi(23)
    public void setExtras(Bundle extras) {
        if (VERSION.SDK_INT >= 23) {
            this.cursor.setExtras(extras);
        }
    }
}