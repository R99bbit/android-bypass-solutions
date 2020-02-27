package com.igaworks.util.bolts_task;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import com.igaworks.util.bolts_task.Task.TaskCompletionSource;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CustomSQLiteDatabase {
    /* access modifiers changed from: private */
    public static final ExecutorService dbExecutor = Executors.newSingleThreadExecutor();
    private static final TaskQueue taskQueue = new TaskQueue();
    /* access modifiers changed from: private */
    public Task<Void> current = null;
    /* access modifiers changed from: private */
    public final Object currentLock = new Object();
    /* access modifiers changed from: private */
    public SQLiteDatabase db;
    /* access modifiers changed from: private */
    public int openFlags;
    /* access modifiers changed from: private */
    public final TaskCompletionSource tcs = Task.create();

    static Task<CustomSQLiteDatabase> openDatabaseAsync(SQLiteOpenHelper helper, int flags) {
        CustomSQLiteDatabase db2 = new CustomSQLiteDatabase(flags);
        return db2.open(helper).continueWithTask(new Continuation<Void, Task<CustomSQLiteDatabase>>() {
            public Task<CustomSQLiteDatabase> then(Task<Void> task) throws Exception {
                return Task.forResult(CustomSQLiteDatabase.this);
            }
        });
    }

    private CustomSQLiteDatabase(int flags) {
        this.openFlags = flags;
        taskQueue.enqueue(new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> toAwait) throws Exception {
                synchronized (CustomSQLiteDatabase.this.currentLock) {
                    CustomSQLiteDatabase.this.current = toAwait;
                }
                return CustomSQLiteDatabase.this.tcs.getTask();
            }
        });
    }

    public Task<Boolean> isReadOnlyAsync() {
        Task<Boolean> task;
        synchronized (this.currentLock) {
            task = this.current.continueWith(new Continuation<Void, Boolean>() {
                public Boolean then(Task<Void> task) throws Exception {
                    return Boolean.valueOf(CustomSQLiteDatabase.this.db.isReadOnly());
                }
            });
            this.current = task.makeVoid();
        }
        return task;
    }

    public Task<Boolean> isOpenAsync() {
        Task<Boolean> task;
        synchronized (this.currentLock) {
            task = this.current.continueWith(new Continuation<Void, Boolean>() {
                public Boolean then(Task<Void> task) throws Exception {
                    return Boolean.valueOf(CustomSQLiteDatabase.this.db.isOpen());
                }
            });
            this.current = task.makeVoid();
        }
        return task;
    }

    public boolean inTransaction() {
        return this.db.inTransaction();
    }

    /* access modifiers changed from: 0000 */
    public Task<Void> open(final SQLiteOpenHelper helper) {
        Task<Void> task;
        synchronized (this.currentLock) {
            this.current = this.current.continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, SQLiteDatabase>() {
                public SQLiteDatabase then(Task<Void> task) throws Exception {
                    if ((CustomSQLiteDatabase.this.openFlags & 1) == 1) {
                        return helper.getReadableDatabase();
                    }
                    return helper.getWritableDatabase();
                }
            }, (Executor) dbExecutor).continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<SQLiteDatabase, Task<Void>>() {
                public Task<Void> then(Task<SQLiteDatabase> task) throws Exception {
                    CustomSQLiteDatabase.this.db = (SQLiteDatabase) task.getResult();
                    return task.makeVoid();
                }
            }, (Executor) Task.BACKGROUND_EXECUTOR);
            task = this.current;
        }
        return task;
    }

    public Task<Void> beginTransactionAsync() {
        Task<Void> continueWithTask;
        synchronized (this.currentLock) {
            try {
                this.current = this.current.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Void, Task<Void>>() {
                    public Task<Void> then(Task<Void> task) throws Exception {
                        CustomSQLiteDatabase.this.db.beginTransaction();
                        return task;
                    }
                }, (Executor) dbExecutor);
                continueWithTask = this.current.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Void, Task<Void>>() {
                    public Task<Void> then(Task<Void> task) throws Exception {
                        return task;
                    }
                }, (Executor) Task.BACKGROUND_EXECUTOR);
            }
        }
        return continueWithTask;
    }

    public Task<Void> setTransactionSuccessfulAsync() {
        Task<Void> continueWithTask;
        synchronized (this.currentLock) {
            try {
                this.current = this.current.onSuccessTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Void, Task<Void>>() {
                    public Task<Void> then(Task<Void> task) throws Exception {
                        CustomSQLiteDatabase.this.db.setTransactionSuccessful();
                        return task;
                    }
                }, (Executor) dbExecutor);
                continueWithTask = this.current.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Void, Task<Void>>() {
                    public Task<Void> then(Task<Void> task) throws Exception {
                        return task;
                    }
                }, (Executor) Task.BACKGROUND_EXECUTOR);
            }
        }
        return continueWithTask;
    }

    public Task<Void> endTransactionAsync() {
        Task<Void> continueWithTask;
        synchronized (this.currentLock) {
            this.current = this.current.continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Void, Void>() {
                public Void then(Task<Void> task) throws Exception {
                    CustomSQLiteDatabase.this.db.endTransaction();
                    return null;
                }
            }, (Executor) dbExecutor);
            continueWithTask = this.current.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Void, Task<Void>>() {
                public Task<Void> then(Task<Void> task) throws Exception {
                    return task;
                }
            }, (Executor) Task.BACKGROUND_EXECUTOR);
        }
        return continueWithTask;
    }

    public Task<Void> closeAsync() {
        Task<Void> continueWithTask;
        synchronized (this.currentLock) {
            this.current = this.current.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Void, Task<Void>>() {
                /* JADX INFO: finally extract failed */
                public Task<Void> then(Task<Void> task) throws Exception {
                    try {
                        CustomSQLiteDatabase.this.db.close();
                        CustomSQLiteDatabase.this.tcs.setResult(null);
                        return CustomSQLiteDatabase.this.tcs.getTask();
                    } catch (Throwable th) {
                        CustomSQLiteDatabase.this.tcs.setResult(null);
                        throw th;
                    }
                }
            }, (Executor) dbExecutor);
            continueWithTask = this.current.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Void, Task<Void>>() {
                public Task<Void> then(Task<Void> task) throws Exception {
                    return task;
                }
            }, (Executor) Task.BACKGROUND_EXECUTOR);
        }
        return continueWithTask;
    }

    public Task<Cursor> queryAsync(String table, String[] select, String where, String[] args) {
        Task<Cursor> continueWithTask;
        synchronized (this.currentLock) {
            try {
                final String str = table;
                final String[] strArr = select;
                final String str2 = where;
                final String[] strArr2 = args;
                Task<Cursor> task = this.current.onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<Void, Cursor>() {
                    public Cursor then(Task<Void> task) throws Exception {
                        return CustomSQLiteDatabase.this.db.query(str, strArr, str2, strArr2, null, null, null);
                    }
                }, (Executor) dbExecutor).onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<Cursor, Cursor>() {
                    public Cursor then(Task<Cursor> task) throws Exception {
                        Cursor cursor = CustomSQLiteCursor.create((Cursor) task.getResult(), CustomSQLiteDatabase.dbExecutor);
                        cursor.getCount();
                        return cursor;
                    }
                }, (Executor) dbExecutor);
                this.current = task.makeVoid();
                continueWithTask = task.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Cursor, Task<Cursor>>() {
                    public Task<Cursor> then(Task<Cursor> task) throws Exception {
                        return task;
                    }
                }, (Executor) Task.BACKGROUND_EXECUTOR);
            }
        }
        return continueWithTask;
    }

    public Task<Void> insertWithOnConflict(final String table, final ContentValues values, final int conflictAlgorithm) {
        Task<Void> makeVoid;
        synchronized (this.currentLock) {
            Task<Long> task = this.current.onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<Void, Long>() {
                public Long then(Task<Void> task) throws Exception {
                    return Long.valueOf(CustomSQLiteDatabase.this.db.insertWithOnConflict(table, null, values, conflictAlgorithm));
                }
            }, (Executor) dbExecutor);
            this.current = task.makeVoid();
            makeVoid = task.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Long, Task<Long>>() {
                public Task<Long> then(Task<Long> task) throws Exception {
                    return task;
                }
            }, (Executor) Task.BACKGROUND_EXECUTOR).makeVoid();
        }
        return makeVoid;
    }

    public Task<Void> insertOrThrowAsync(final String table, final ContentValues values) {
        Task<Void> makeVoid;
        synchronized (this.currentLock) {
            try {
                Task<Long> task = this.current.onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<Void, Long>() {
                    public Long then(Task<Void> task) throws Exception {
                        return Long.valueOf(CustomSQLiteDatabase.this.db.insertOrThrow(table, null, values));
                    }
                }, (Executor) dbExecutor);
                this.current = task.makeVoid();
                makeVoid = task.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Long, Task<Long>>() {
                    public Task<Long> then(Task<Long> task) throws Exception {
                        return task;
                    }
                }, (Executor) Task.BACKGROUND_EXECUTOR).makeVoid();
            }
        }
        return makeVoid;
    }

    public Task<Integer> updateAsync(String table, ContentValues values, String where, String[] args) {
        Task<Integer> continueWithTask;
        synchronized (this.currentLock) {
            try {
                final String str = table;
                final ContentValues contentValues = values;
                final String str2 = where;
                final String[] strArr = args;
                Task<Integer> task = this.current.onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<Void, Integer>() {
                    public Integer then(Task<Void> task) throws Exception {
                        return Integer.valueOf(CustomSQLiteDatabase.this.db.update(str, contentValues, str2, strArr));
                    }
                }, (Executor) dbExecutor);
                this.current = task.makeVoid();
                continueWithTask = task.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Integer, Task<Integer>>() {
                    public Task<Integer> then(Task<Integer> task) throws Exception {
                        return task;
                    }
                }, (Executor) Task.BACKGROUND_EXECUTOR);
            }
        }
        return continueWithTask;
    }

    public Task<Void> deleteAsync(final String table, final String where, final String[] args) {
        Task<Void> makeVoid;
        synchronized (this.currentLock) {
            try {
                Task<Integer> task = this.current.onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<Void, Integer>() {
                    public Integer then(Task<Void> task) throws Exception {
                        return Integer.valueOf(CustomSQLiteDatabase.this.db.delete(table, where, args));
                    }
                }, (Executor) dbExecutor);
                this.current = task.makeVoid();
                makeVoid = task.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Integer, Task<Integer>>() {
                    public Task<Integer> then(Task<Integer> task) throws Exception {
                        return task;
                    }
                }, (Executor) Task.BACKGROUND_EXECUTOR).makeVoid();
            }
        }
        return makeVoid;
    }

    public Task<Cursor> rawQueryAsync(final String sql, final String[] args) {
        Task<Cursor> continueWithTask;
        synchronized (this.currentLock) {
            try {
                Task<Cursor> task = this.current.onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<Void, Cursor>() {
                    public Cursor then(Task<Void> task) throws Exception {
                        return CustomSQLiteDatabase.this.db.rawQuery(sql, args);
                    }
                }, (Executor) dbExecutor).onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<Cursor, Cursor>() {
                    public Cursor then(Task<Cursor> task) throws Exception {
                        Cursor cursor = CustomSQLiteCursor.create((Cursor) task.getResult(), CustomSQLiteDatabase.dbExecutor);
                        cursor.getCount();
                        return cursor;
                    }
                }, (Executor) dbExecutor);
                this.current = task.makeVoid();
                continueWithTask = task.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Cursor, Task<Cursor>>() {
                    public Task<Cursor> then(Task<Cursor> task) throws Exception {
                        return task;
                    }
                }, (Executor) Task.BACKGROUND_EXECUTOR);
            }
        }
        return continueWithTask;
    }

    public Task<Long> queryNumEntries(final String table) {
        Task<Long> continueWithTask;
        synchronized (this.currentLock) {
            Task<Long> task = this.current.onSuccess((Continuation<TResult, TContinuationResult>) new Continuation<Void, Long>() {
                public Long then(Task<Void> task) throws Exception {
                    return Long.valueOf(DatabaseUtils.queryNumEntries(CustomSQLiteDatabase.this.db, table));
                }
            }, (Executor) dbExecutor);
            this.current = task.makeVoid();
            continueWithTask = task.continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<Long, Task<Long>>() {
                public Task<Long> then(Task<Long> task) throws Exception {
                    return task;
                }
            }, (Executor) Task.BACKGROUND_EXECUTOR);
        }
        return continueWithTask;
    }
}