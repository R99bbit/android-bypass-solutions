package com.igaworks.dao;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.model.ActivityCounter;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class CounterDAOForCPEActivity extends AdbrixDB_v2 {
    private static final String TAG = "CounterDAOForCPEActivity";
    private static CounterDAOForCPEActivity activityCounterDAO;

    public static CounterDAOForCPEActivity getDAO(Context ctx) {
        if (activityCounterDAO == null) {
            synchronized (CounterDAOForCPEActivity.class) {
                try {
                    if (activityCounterDAO == null) {
                        activityCounterDAO = new CounterDAOForCPEActivity(ctx);
                    }
                }
            }
        }
        if (CommonFrameworkImpl.getContext() == null) {
            CommonFrameworkImpl.setContext(ctx);
        }
        return activityCounterDAO;
    }

    private CounterDAOForCPEActivity(Context ctx) {
        try {
            if (this.dbHelper == null) {
                this.dbHelper = new AdbrixDBOpenHelper(ctx, AdbrixDB_v2.DATABASE_NAME, null, 1);
            }
        } catch (Exception e) {
        }
    }

    public void insertCounter(int year, int month, int day, int hour, String group, String activity) {
        insertCounter(year, month, day, hour, group, activity, null);
    }

    public void insertCounter(int year, int month, int day, int hour, String group, String activity, Calendar calendar) {
        final int i = year;
        final int i2 = month;
        final int i3 = day;
        final int i4 = hour;
        final String str = group;
        final String str2 = activity;
        final Calendar calendar2 = calendar;
        runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                Date date;
                ContentValues newTaskValues = new ContentValues();
                newTaskValues.put("year", Integer.valueOf(i));
                newTaskValues.put("month", Integer.valueOf(i2));
                newTaskValues.put("day", Integer.valueOf(i3));
                newTaskValues.put("hour", Integer.valueOf(i4));
                newTaskValues.put("activity_group", str);
                newTaskValues.put("activity", str2);
                newTaskValues.put("counter", Integer.valueOf(1));
                newTaskValues.put("year_updated", Integer.valueOf(i));
                newTaskValues.put("month_updated", Integer.valueOf(i2));
                newTaskValues.put("day_updated", Integer.valueOf(i3));
                newTaskValues.put("hour_updated", Integer.valueOf(i4));
                if (calendar2 == null) {
                    date = Calendar.getInstance().getTime();
                } else {
                    date = calendar2.getTime();
                }
                newTaskValues.put("no_counting_update_datetime", CounterDAOForCPEActivity.DB_DATE_FORMAT.format(date));
                newTaskValues.put("regist_datetime", CounterDAOForCPEActivity.DB_DATE_FORMAT.format(date));
                newTaskValues.put("update_datetime", CounterDAOForCPEActivity.DB_DATE_FORMAT.format(date));
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), CounterDAOForCPEActivity.TAG, String.format("Insert counter : [%d-%d-%d %dh] group = %s, activity = %s", new Object[]{Integer.valueOf(i), Integer.valueOf(i2), Integer.valueOf(i3), Integer.valueOf(i4), str, str2}), 2);
                return db.insertOrThrowAsync("ActivityCounter", newTaskValues);
            }
        });
    }

    public void removeCounter(final int activityCounterNo) {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), CounterDAOForCPEActivity.TAG, "Remove counter : activityCounterNo = " + activityCounterNo, 2);
                return db.deleteAsync("ActivityCounter", activityCounterNo + "=" + activityCounterNo, null);
            }
        });
    }

    public void removeCounter(final String group, final String activity) {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), CounterDAOForCPEActivity.TAG, String.format("Remove counter : group = %s, activity = %s", new Object[]{group, activity}), 2);
                return db.deleteAsync("ActivityCounter", CounterDAOForCPEActivity.this.getQueryString(group, activity), null);
            }
        });
    }

    public void removeCounter(int year, int month, int day, int hour, String group, String activity) {
        final int i = year;
        final int i2 = month;
        final int i3 = day;
        final int i4 = hour;
        final String str = group;
        final String str2 = activity;
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), CounterDAOForCPEActivity.TAG, String.format("Remove counter : [%d-%d-%d %dh] group = %s, activity = %s", new Object[]{Integer.valueOf(i), Integer.valueOf(i2), Integer.valueOf(i3), Integer.valueOf(i4), str, str2}), 2);
                return db.deleteAsync("ActivityCounter", CounterDAOForCPEActivity.this.getQueryString(i, i2, i3, i4, str, str2), null);
            }
        });
    }

    public void removeCounterLessThanDate(int year, int month, int day, int hour, String group, String activity) {
        final int i = year;
        final int i2 = month;
        final int i3 = day;
        final int i4 = hour;
        final String str = group;
        final String str2 = activity;
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), CounterDAOForCPEActivity.TAG, String.format("Remove counter by date that less than: [%d-%d-%d %dh] group = %s, activity = %s", new Object[]{Integer.valueOf(i), Integer.valueOf(i2), Integer.valueOf(i3), Integer.valueOf(i4), str, str2}), 2);
                return db.deleteAsync("ActivityCounter", CounterDAOForCPEActivity.this.getQueryStringByDateLessThan(i, i2, i3, i4, str, str2), null);
            }
        });
    }

    public void increment(ActivityCounter counter) {
        increment(counter, null);
    }

    public void increment(final ActivityCounter counter, final Calendar calendar) {
        runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                Date date;
                ContentValues newValue = new ContentValues();
                newValue.put("counter", Integer.valueOf(counter.getCounter() + 1));
                if (calendar == null) {
                    date = Calendar.getInstance().getTime();
                } else {
                    date = calendar.getTime();
                }
                newValue.put("update_datetime", CounterDAOForCPEActivity.DB_DATE_FORMAT.format(date));
                newValue.put("no_counting_update_datetime", CounterDAOForCPEActivity.DB_DATE_FORMAT.format(date));
                return db.updateAsync("ActivityCounter", newValue, "_id=" + counter.getActivityCounterNo(), null).makeVoid();
            }
        });
    }

    public void updateDateUpdated(ActivityCounter counter, int yearUpdated, int monthUpdated, int dayUpdated, int hourUpdated) {
        updateDateUpdated(counter, yearUpdated, monthUpdated, dayUpdated, hourUpdated, null);
    }

    public void updateDateUpdated(ActivityCounter counter, int yearUpdated, int monthUpdated, int dayUpdated, int hourUpdated, Calendar calendar) {
        final int i = yearUpdated;
        final int i2 = monthUpdated;
        final int i3 = dayUpdated;
        final int i4 = hourUpdated;
        final Calendar calendar2 = calendar;
        final ActivityCounter activityCounter = counter;
        runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                Date date;
                ContentValues newValue = new ContentValues();
                newValue.put("year_updated", Integer.valueOf(i));
                newValue.put("month_updated", Integer.valueOf(i2));
                newValue.put("day_updated", Integer.valueOf(i3));
                newValue.put("hour_updated", Integer.valueOf(i4));
                if (calendar2 == null) {
                    date = Calendar.getInstance().getTime();
                } else {
                    date = calendar2.getTime();
                }
                newValue.put("update_datetime", CounterDAOForCPEActivity.DB_DATE_FORMAT.format(date));
                newValue.put("no_counting_update_datetime", CounterDAOForCPEActivity.DB_DATE_FORMAT.format(date));
                return db.updateAsync("ActivityCounter", newValue, "_id=" + activityCounter.getActivityCounterNo(), null).makeVoid();
            }
        });
    }

    public void updateNoCountingDateUpdated(ActivityCounter counter, int yearUpdated, int monthUpdated, int dayUpdated, int hourUpdated, Calendar calendar) {
        final int i = yearUpdated;
        final int i2 = monthUpdated;
        final int i3 = dayUpdated;
        final int i4 = hourUpdated;
        final Calendar calendar2 = calendar;
        final ActivityCounter activityCounter = counter;
        runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                Date date;
                ContentValues newValue = new ContentValues();
                newValue.put("year_updated", Integer.valueOf(i));
                newValue.put("month_updated", Integer.valueOf(i2));
                newValue.put("day_updated", Integer.valueOf(i3));
                newValue.put("hour_updated", Integer.valueOf(i4));
                if (calendar2 == null) {
                    date = Calendar.getInstance().getTime();
                } else {
                    date = calendar2.getTime();
                }
                newValue.put("no_counting_update_datetime", CounterDAOForCPEActivity.DB_DATE_FORMAT.format(date));
                return db.updateAsync("ActivityCounter", newValue, "_id=" + activityCounter.getActivityCounterNo(), null).makeVoid();
            }
        });
    }

    public String getQueryString(int year, int month, int day, int hour, String group, String activity) {
        String query = "year=" + year + " and " + "month" + "=" + month + " and " + "day" + "=" + day + " and " + "hour" + "=" + hour + " and " + "activity_group" + "='" + group + "' and " + "activity" + "='" + activity + "'";
        IgawLogger.Logging(CommonFrameworkImpl.getContext(), TAG, query, 3);
        return query;
    }

    public String getQueryStringByDateLessThan(int year, int month, int day, int hour, String group, String activity) {
        Calendar date = Calendar.getInstance();
        date.set(1, year);
        date.set(2, month);
        date.set(5, day);
        date.set(11, hour);
        date.set(12, 0);
        date.set(13, 0);
        String query = "no_counting_update_datetime < '" + DB_DATE_FORMAT.format(date.getTime()) + "' and " + "activity_group" + "='" + group + "' and " + "activity" + "='" + activity + "'";
        IgawLogger.Logging(CommonFrameworkImpl.getContext(), TAG, query, 3);
        return query;
    }

    public String getQueryString(int year, int month, int day, String group, String activity) {
        String query = "year=" + year + " and " + "month" + "=" + month + " and " + "day" + "=" + day + " and " + "activity_group" + "='" + group + "' and " + "activity" + "='" + activity + "'";
        IgawLogger.Logging(CommonFrameworkImpl.getContext(), TAG, query, 3);
        return query;
    }

    public String getQueryString(String group, String activity) {
        String query = "activity_group='" + group + "'";
        if (activity != null && activity.length() > 0) {
            query = new StringBuilder(String.valueOf(query)).append(" and activity='").append(activity).append("'").toString();
        }
        IgawLogger.Logging(CommonFrameworkImpl.getContext(), TAG, query, 3);
        return query;
    }

    public List<ActivityCounter> getActivityCounters(int year, int month, int day, int hour, String group, String activity) {
        final int i = year;
        final int i2 = month;
        final int i3 = day;
        final int i4 = hour;
        final String str = group;
        final String str2 = activity;
        Task<List<ActivityCounter>> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<List<ActivityCounter>>>() {
            public Task<List<ActivityCounter>> call(CustomSQLiteDatabase db) {
                return db.queryAsync("ActivityCounter", new String[]{"_id", "year", "month", "day", "hour", "activity_group", "activity", "counter", "year_updated", "month_updated", "day_updated", "hour_updated", "regist_datetime", "update_datetime", "no_counting_update_datetime"}, CounterDAOForCPEActivity.this.getQueryString(i, i2, i3, i4, str, str2), null).onSuccess(new Continuation<Cursor, List<ActivityCounter>>() {
                    public List<ActivityCounter> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        ArrayList arrayList = new ArrayList();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            arrayList.add(new ActivityCounter(cursor.getInt(0), cursor.getInt(1), cursor.getInt(2), cursor.getInt(3), cursor.getInt(4), cursor.getString(5), cursor.getString(6), cursor.getInt(7), cursor.getInt(8), cursor.getInt(9), cursor.getInt(10), cursor.getInt(11), cursor.getString(12), cursor.getString(13), cursor.getString(14)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return arrayList;
                    }
                });
            }
        });
        try {
            TaskUtils.wait(task);
            return (List) task.getResult();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(IgawConstant.QA_TAG, "getActivityCounters Error: " + e.getMessage());
            return null;
        }
    }

    public List<ActivityCounter> getActivityCounters(int year, int month, int day, String group, String activity) {
        final int i = year;
        final int i2 = month;
        final int i3 = day;
        final String str = group;
        final String str2 = activity;
        Task<List<ActivityCounter>> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<List<ActivityCounter>>>() {
            public Task<List<ActivityCounter>> call(CustomSQLiteDatabase db) {
                return db.queryAsync("ActivityCounter", new String[]{"_id", "year", "month", "day", "hour", "activity_group", "activity", "counter", "year_updated", "month_updated", "day_updated", "hour_updated", "regist_datetime", "update_datetime", "no_counting_update_datetime"}, CounterDAOForCPEActivity.this.getQueryString(i, i2, i3, str, str2), null).onSuccess(new Continuation<Cursor, List<ActivityCounter>>() {
                    public List<ActivityCounter> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        ArrayList arrayList = new ArrayList();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            arrayList.add(new ActivityCounter(cursor.getInt(0), cursor.getInt(1), cursor.getInt(2), cursor.getInt(3), cursor.getInt(4), cursor.getString(5), cursor.getString(6), cursor.getInt(7), cursor.getInt(8), cursor.getInt(9), cursor.getInt(10), cursor.getInt(11), cursor.getString(12), cursor.getString(13), cursor.getString(14)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return arrayList;
                    }
                });
            }
        });
        try {
            TaskUtils.wait(task);
            return (List) task.getResult();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(IgawConstant.QA_TAG, "getActivityCounters Error: " + e.getMessage());
            return null;
        }
    }

    public List<ActivityCounter> getActivityCounters(final String group, final String activity) {
        Task<List<ActivityCounter>> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<List<ActivityCounter>>>() {
            public Task<List<ActivityCounter>> call(CustomSQLiteDatabase db) {
                return db.queryAsync("ActivityCounter", new String[]{"_id", "year", "month", "day", "hour", "activity_group", "activity", "counter", "year_updated", "month_updated", "day_updated", "hour_updated", "regist_datetime", "update_datetime", "no_counting_update_datetime"}, CounterDAOForCPEActivity.this.getQueryString(group, activity), null).onSuccess(new Continuation<Cursor, List<ActivityCounter>>() {
                    public List<ActivityCounter> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        ArrayList arrayList = new ArrayList();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            arrayList.add(new ActivityCounter(cursor.getInt(0), cursor.getInt(1), cursor.getInt(2), cursor.getInt(3), cursor.getInt(4), cursor.getString(5), cursor.getString(6), cursor.getInt(7), cursor.getInt(8), cursor.getInt(9), cursor.getInt(10), cursor.getInt(11), cursor.getString(12), cursor.getString(13), cursor.getString(14)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return null;
                    }
                });
            }
        });
        try {
            TaskUtils.wait(task);
            return (List) task.getResult();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(IgawConstant.QA_TAG, "getActivityCounters Error: " + e.getMessage());
            return null;
        }
    }

    public ActivityCounter getActivityCounter(int year, int month, int day, int hour, String group, String activity) {
        final int i = year;
        final int i2 = month;
        final int i3 = day;
        final int i4 = hour;
        final String str = group;
        final String str2 = activity;
        Task<ActivityCounter> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<ActivityCounter>>() {
            public Task<ActivityCounter> call(CustomSQLiteDatabase db) {
                return db.queryAsync("ActivityCounter", new String[]{"_id", "year", "month", "day", "hour", "activity_group", "activity", "counter", "year_updated", "month_updated", "day_updated", "hour_updated", "update_datetime", "regist_datetime", "no_counting_update_datetime"}, CounterDAOForCPEActivity.this.getQueryString(i, i2, i3, i4, str, str2), null).onSuccess(new Continuation<Cursor, ActivityCounter>() {
                    public ActivityCounter then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (cursor.getCount() == 0 || !cursor.moveToFirst()) {
                            cursor.close();
                            return null;
                        }
                        ActivityCounter activityCounter = new ActivityCounter(cursor.getInt(0), cursor.getInt(1), cursor.getInt(2), cursor.getInt(3), cursor.getInt(4), cursor.getString(5), cursor.getString(6), cursor.getInt(7), cursor.getInt(8), cursor.getInt(9), cursor.getInt(10), cursor.getInt(11), cursor.getString(12), cursor.getString(13), cursor.getString(14));
                        cursor.close();
                        return activityCounter;
                    }
                });
            }
        });
        try {
            TaskUtils.wait(task);
            return (ActivityCounter) task.getResult();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(IgawConstant.QA_TAG, "getActivityCounters Error: " + e.getMessage());
            return null;
        }
    }
}