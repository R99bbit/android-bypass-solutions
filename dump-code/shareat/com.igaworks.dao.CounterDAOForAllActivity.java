package com.igaworks.dao;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;

public class CounterDAOForAllActivity extends AdbrixDB_v2 {
    private static final String TAG = "CounterDAOForAllActivity";
    private static CounterDAOForAllActivity counterForAllActivityDao;

    public static CounterDAOForAllActivity getDAO(Context ctx) {
        if (counterForAllActivityDao == null) {
            synchronized (CounterDAOForAllActivity.class) {
                try {
                    if (counterForAllActivityDao == null) {
                        counterForAllActivityDao = new CounterDAOForAllActivity(ctx);
                    }
                }
            }
        }
        if (CommonFrameworkImpl.getContext() == null) {
            CommonFrameworkImpl.setContext(ctx);
        }
        return counterForAllActivityDao;
    }

    private CounterDAOForAllActivity(Context ctx) {
        try {
            if (this.dbHelper == null) {
                this.dbHelper = new AdbrixDBOpenHelper(ctx, AdbrixDB_v2.DATABASE_NAME, null, 1);
            }
        } catch (Exception e) {
        }
    }

    public void updateItemToAllActivity(final String group, final String activity) {
        runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task<Cursor> queryAsync = _db.queryAsync("AllActivityCounter", new String[]{"_id", "activity_group", "activity", "counter"}, "activity_group='" + group + "' and " + "activity" + "='" + activity + "'", null);
                final String str = group;
                final String str2 = activity;
                return queryAsync.onSuccessTask(new Continuation<Cursor, Task<Void>>() {
                    public Task<Void> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (!cursor.moveToFirst() || cursor.getCount() == 0) {
                            cursor.close();
                            ContentValues newTaskValues = new ContentValues();
                            newTaskValues.put("activity_group", str);
                            newTaskValues.put("activity", str2);
                            newTaskValues.put("counter", Integer.valueOf(1));
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), CounterDAOForAllActivity.TAG, String.format("Update Item of All Activity : group = %s, activity = %s", new Object[]{str, str2}), 2);
                            return _db.insertOrThrowAsync("AllActivityCounter", newTaskValues);
                        }
                        ContentValues newValue = new ContentValues();
                        newValue.put("counter", Integer.valueOf(cursor.getInt(3) + 1));
                        int id = cursor.getInt(0);
                        cursor.close();
                        return _db.updateAsync("AllActivityCounter", newValue, "_id=" + id, null).makeVoid();
                    }
                });
            }
        });
    }

    public int getCountInAllActivityByGroupAndActivity(final String group, final String activity) {
        Task<Integer> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Integer>>() {
            public Task<Integer> call(CustomSQLiteDatabase db) {
                return db.queryAsync("AllActivityCounter", new String[]{"_id", "activity_group", "activity", "counter"}, "activity_group='" + group + "' and " + "activity" + "='" + activity + "'", null).onSuccess(new Continuation<Cursor, Integer>() {
                    public Integer then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        int result = 0;
                        if (cursor.moveToFirst() && cursor.getCount() > 0) {
                            result = cursor.getInt(3);
                        }
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

    public int getCountInAllActivityByGroup(final String group) {
        if (group == null || group.equals("")) {
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "getCountInAllActivityByGroup: group value is invalid", 0);
            return 0;
        }
        Task<Integer> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Integer>>() {
            public Task<Integer> call(CustomSQLiteDatabase db) {
                return db.queryAsync("AllActivityCounter", new String[]{"_id", "activity_group", "activity", "counter"}, "activity_group='" + group + "'", null).onSuccess(new Continuation<Cursor, Integer>() {
                    public Integer then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        int count = cursor.getCount();
                        if (cursor.moveToFirst() && count > 0) {
                            cursor.getInt(3);
                        }
                        cursor.close();
                        return Integer.valueOf(0);
                    }
                });
            }
        });
        try {
            TaskUtils.wait(task);
            return ((Integer) task.getResult()).intValue();
        } catch (Exception e) {
            e.printStackTrace();
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "getCountInAllActivityByGroup Error: " + e.getMessage(), 0);
            return 0;
        }
    }
}