package com.igaworks.adbrix.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.util.Log;
import com.igaworks.adbrix.model.RetryCompleteConversion;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.dao.AdbrixDB_v2;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import java.util.ArrayList;
import java.util.List;

public class ConversionDAOForRetryCompletion extends AdbrixDB_v2 {
    private static final String TAG = "ActivityDAOForRestore";
    private static ConversionDAOForRetryCompletion counterForAllActivityDao;

    public static ConversionDAOForRetryCompletion getDAO(Context ctx) {
        if (counterForAllActivityDao == null) {
            synchronized (ConversionDAOForRetryCompletion.class) {
                try {
                    if (counterForAllActivityDao == null) {
                        counterForAllActivityDao = new ConversionDAOForRetryCompletion(ctx);
                    }
                }
            }
        }
        if (CommonFrameworkImpl.getContext() == null) {
            CommonFrameworkImpl.setContext(ctx);
        }
        return counterForAllActivityDao;
    }

    private ConversionDAOForRetryCompletion(Context ctx) {
        try {
            if (this.dbHelper == null) {
                this.dbHelper = new AdbrixDBOpenHelper(ctx, AdbrixDB_v2.DATABASE_NAME, null, 1);
            }
        } catch (Exception e) {
        }
    }

    public List<RetryCompleteConversion> getRetryConversions() {
        Task<List<RetryCompleteConversion>> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<List<RetryCompleteConversion>>>() {
            public Task<List<RetryCompleteConversion>> call(CustomSQLiteDatabase db) {
                return db.queryAsync("RetryCompleteConversion", new String[]{"conversion_key", "retry_count"}, null, null).onSuccess(new Continuation<Cursor, List<RetryCompleteConversion>>() {
                    public List<RetryCompleteConversion> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        List<RetryCompleteConversion> result = new ArrayList<>();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            result.add(new RetryCompleteConversion(cursor.getInt(0), cursor.getInt(1)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return result;
                    }
                });
            }
        });
        try {
            TaskUtils.wait(task);
            return (List) task.getResult();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(IgawConstant.QA_TAG, "ConversionDAOForRetryCompletion >>getRetryConversions Error: " + e.getMessage());
            return null;
        }
    }

    public int getRetryCount(final int conversionKey) {
        Task<Integer> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Integer>>() {
            public Task<Integer> call(CustomSQLiteDatabase db) {
                return db.queryAsync("RetryCompleteConversion", new String[]{"conversion_key", "retry_count"}, "conversion_key=" + conversionKey, null).onSuccess(new Continuation<Cursor, Integer>() {
                    public Integer then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (!cursor.moveToFirst() || cursor.getCount() == 0) {
                            cursor.close();
                            return Integer.valueOf(0);
                        }
                        int result = cursor.getInt(1);
                        cursor.close();
                        return Integer.valueOf(result);
                    }
                });
            }
        });
        try {
            TaskUtils.wait(task);
            return ((Integer) task.getResult()).intValue();
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    public void updateOrInsertConversionForRetry(final int conversionKey) {
        runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task<Cursor> queryAsync = _db.queryAsync("RetryCompleteConversion", new String[]{"conversion_key", "retry_count"}, "conversion_key=" + conversionKey, null);
                final int i = conversionKey;
                return queryAsync.onSuccessTask(new Continuation<Cursor, Task<Void>>() {
                    public Task<Void> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (!cursor.moveToFirst() || cursor.getCount() == 0) {
                            cursor.close();
                            ContentValues newTaskValues = new ContentValues();
                            newTaskValues.put("conversion_key", Integer.valueOf(i));
                            newTaskValues.put("retry_count", Integer.valueOf(0));
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), ConversionDAOForRetryCompletion.TAG, String.format("add retry complete conversion : conversionKey = %d", new Object[]{Integer.valueOf(i)}), 2);
                            return _db.insertOrThrowAsync("RetryCompleteConversion", newTaskValues);
                        }
                        ContentValues newValue = new ContentValues();
                        newValue.put("retry_count", Integer.valueOf(cursor.getInt(1) + 1));
                        cursor.close();
                        return _db.updateAsync("RetryCompleteConversion", newValue, "conversion_key=" + i, null).makeVoid();
                    }
                });
            }
        });
    }

    public boolean removeRetryCount(final int conversionKey) {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), ConversionDAOForRetryCompletion.TAG, "removeRetryCount conversionKey =  " + conversionKey, 2);
                return db.deleteAsync("RetryCompleteConversion", "conversion_key=" + conversionKey, null).makeVoid();
            }
        });
        return true;
    }

    public boolean clearRetryCount() {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), ConversionDAOForRetryCompletion.TAG, "Remove restore queue", 2);
                return db.deleteAsync("RetryCompleteConversion", null, null).makeVoid();
            }
        });
        return true;
    }
}