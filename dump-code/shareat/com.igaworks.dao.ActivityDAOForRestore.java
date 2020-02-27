package com.igaworks.dao;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.model.RestoreActivity;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class ActivityDAOForRestore extends AdbrixDB_v2 {
    private static final String TAG = "ActivityDAOForRestore";
    private static ActivityDAOForRestore counterForAllActivityDao;

    public static ActivityDAOForRestore getDAO(Context ctx) {
        if (counterForAllActivityDao == null) {
            synchronized (ActivityDAOForRestore.class) {
                try {
                    if (counterForAllActivityDao == null) {
                        counterForAllActivityDao = new ActivityDAOForRestore(ctx);
                    }
                }
            }
        }
        if (CommonFrameworkImpl.getContext() == null) {
            CommonFrameworkImpl.setContext(ctx);
        }
        return counterForAllActivityDao;
    }

    private ActivityDAOForRestore(Context ctx) {
        try {
            if (this.dbHelper == null) {
                this.dbHelper = new AdbrixDBOpenHelper(ctx, AdbrixDB_v2.DATABASE_NAME, null, 1);
            }
        } catch (Exception e) {
        }
    }

    public int addItem(final String group, final String activity) {
        try {
            runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
                public Task<Void> call(CustomSQLiteDatabase db) {
                    ContentValues newTaskValues = new ContentValues();
                    newTaskValues.put("activity_group", group);
                    newTaskValues.put("activity", activity);
                    newTaskValues.put("regist_datetime", ActivityDAOForRestore.DB_DATE_FORMAT.format(new Date()));
                    IgawLogger.Logging(CommonFrameworkImpl.getContext(), ActivityDAOForRestore.TAG, String.format("Update Item of Activity Restore : group = %s, activity = %s", new Object[]{group, activity}), 2);
                    return db.insertOrThrowAsync("CounterForRestore", newTaskValues);
                }
            });
            return 1;
        } catch (Exception e) {
            return 0;
        }
    }

    public List<RestoreActivity> getRestoreActivities() {
        Task<List<RestoreActivity>> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<List<RestoreActivity>>>() {
            public Task<List<RestoreActivity>> call(CustomSQLiteDatabase db) {
                return db.queryAsync("CounterForRestore", new String[]{"_id", "activity_group", "activity", "regist_datetime"}, null, null).onSuccess(new Continuation<Cursor, List<RestoreActivity>>() {
                    public List<RestoreActivity> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        List<RestoreActivity> result = new ArrayList<>();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            Calendar calendar = Calendar.getInstance();
                            try {
                                calendar.setTime(AdbrixDB_v2.DB_DATE_FORMAT.parse(cursor.getString(3)));
                            } catch (ParseException e) {
                                e.printStackTrace();
                            }
                            result.add(new RestoreActivity(cursor.getInt(0), cursor.getString(1), cursor.getString(2), calendar));
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
            new ArrayList();
            return (List) task.getResult();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(IgawConstant.QA_TAG, "getRestoreActivities Error0" + e.getMessage());
            return null;
        }
    }

    public boolean clearRestoreActivity() {
        try {
            IgawLogger.Logging(CommonFrameworkImpl.getContext(), TAG, "Remove restore queue", 2);
            runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
                public Task<Void> call(CustomSQLiteDatabase db) {
                    return db.deleteAsync("CounterForRestore", null, null);
                }
            });
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}