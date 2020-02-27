package com.igaworks.dao.tracking;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.dao.DeeplinkDB;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.bolts_task.Capture;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.Task;
import io.fabric.sdk.android.services.settings.SettingsJsonConstants;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONException;
import org.json.JSONObject;

public class TrackingActivitySQLiteDB {
    private static TrackingActivitySQLiteDB INSTANCE = null;
    private static final int MAXIMUM_NUMBER_OF_TRACKING_ACTIVITY = 750;
    private final TrackingActivitySQLiteOpenHelper helper;

    private interface SQLiteDatabaseCallable<T> {
        T call(CustomSQLiteDatabase customSQLiteDatabase);
    }

    private TrackingActivitySQLiteDB(TrackingActivitySQLiteOpenHelper helper2) {
        this.helper = helper2;
    }

    public static TrackingActivitySQLiteDB getInstance(Context context) {
        if (INSTANCE == null) {
            synchronized (TrackingActivitySQLiteDB.class) {
                try {
                    if (INSTANCE == null) {
                        INSTANCE = new TrackingActivitySQLiteDB(new TrackingActivitySQLiteOpenHelper(context));
                    }
                }
            }
        }
        return INSTANCE;
    }

    public Task<Void> addTrackingActivityAsyn(final String activity_name, final String activity_info) {
        return runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                ContentValues values = new ContentValues();
                values.put("Name", activity_name);
                values.put("Value", activity_info);
                values.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(0));
                return db.insertOrThrowAsync(TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING, values);
            }
        });
    }

    public Task<ArrayList<TrackingActivityModel>> getActivityListParam(boolean isOldVersion, Context context, String group, String act, long endSessionParam) {
        final boolean z = isOldVersion;
        final Context context2 = context;
        final String str = group;
        final String str2 = act;
        final long j = endSessionParam;
        return runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> call(CustomSQLiteDatabase db) {
                return TrackingActivitySQLiteDB.this.getCleanAppTrackingActivitiesInDBAsync(z, db, context2, str, str2, j);
            }
        });
    }

    public Task<Void> reclaimDirtyDataForRetry(final ArrayList<TrackingActivityModel> list, final Context context, final String table) {
        return runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                return TrackingActivitySQLiteDB.this.updateIsDirtyProperpy(context, list, 0, db, table);
            }
        });
    }

    public Task<Void> removeTrackingActivities(final ArrayList<TrackingActivityModel> list, final Context context, final String table) {
        return runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                return TrackingActivitySQLiteDB.this.removeTrackingData(context, list, db, table);
            }
        });
    }

    public Task<ArrayList<TrackingActivityModel>> getOrphanTracking(final Context context, final String table) {
        return runWithManagedConnection(new SQLiteDatabaseCallable<Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> call(CustomSQLiteDatabase db) {
                return TrackingActivitySQLiteDB.this.getOrphanDirtyTrackingActivitiesInDBAsync(db, table, context);
            }
        });
    }

    public Task<Void> setImpressionData(Context context, int campaignKey, int resourceKey, String spaceKey, String createdAt, String conversion_key, Boolean isFirstTime) {
        final int i = campaignKey;
        final int i2 = resourceKey;
        final String str = spaceKey;
        final String str2 = createdAt;
        final String str3 = conversion_key;
        final Boolean bool = isFirstTime;
        return runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                JSONObject result = new JSONObject();
                try {
                    result.put("campaign_key", i);
                    result.put("resource_key", i2);
                    result.put("space_key", str);
                    result.put("created_at", str2);
                    if (str3 != null && !str3.equals("")) {
                        result.put("conversion_key", str3);
                    }
                    if (bool != null && !bool.equals("")) {
                        result.put(TrackingActivitySQLiteOpenHelper.IP_IS_FIRST_TIME, bool);
                    }
                } catch (JSONException e) {
                    e.printStackTrace();
                }
                ContentValues values = new ContentValues();
                values.put("Name", str2);
                values.put("Value", result.toString());
                values.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(0));
                return db.insertOrThrowAsync(TrackingActivitySQLiteOpenHelper.TABLE_IMPRESSION_TRACKING, values);
            }
        });
    }

    public Task<ArrayList<TrackingActivityModel>> getImpressionData(final boolean isOldVersion, final Context context) {
        final Capture<ArrayList<TrackingActivityModel>> impList = new Capture<>(new ArrayList());
        return runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task onSuccess = _db.rawQueryAsync("SELECT * FROM tbl_ImpressionTracking WHERE isDirty=? ORDER BY Id ASC LIMIT 50", new String[]{String.valueOf(0)}).onSuccess(new Continuation<Cursor, ArrayList<TrackingActivityModel>>() {
                    public ArrayList<TrackingActivityModel> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        ArrayList<TrackingActivityModel> impression_tracking = new ArrayList<>();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            impression_tracking.add(new TrackingActivityModel(cursor.getInt(0), cursor.getString(1), cursor.getString(2)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return impression_tracking;
                    }
                });
                final Capture capture = impList;
                final boolean z = isOldVersion;
                final Context context = context;
                Task onSuccessTask = onSuccess.onSuccessTask(new Continuation<ArrayList<TrackingActivityModel>, Task<Void>>() {
                    public Task<Void> then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                        capture.set((ArrayList) task.getResult());
                        try {
                            if (!z) {
                                return TrackingActivitySQLiteDB.this.updateIsDirtyProperpy(context, (ArrayList) capture.get(), 1, _db, TrackingActivitySQLiteOpenHelper.TABLE_IMPRESSION_TRACKING);
                            }
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "Compat >> removeImpressionTrackingData", 2, true);
                            return TrackingActivitySQLiteDB.this.removeTrackingData(context, (ArrayList) capture.get(), _db, TrackingActivitySQLiteOpenHelper.TABLE_IMPRESSION_TRACKING);
                        } catch (Exception e) {
                            Log.e(IgawConstant.QA_TAG, "Impression tracking >> @updateIsDirtyProperpy Error" + e.getMessage());
                            e.printStackTrace();
                            return null;
                        }
                    }
                });
                final Capture capture2 = impList;
                return onSuccessTask.onSuccess(new Continuation<Void, ArrayList<TrackingActivityModel>>() {
                    public ArrayList<TrackingActivityModel> then(Task<Void> task) throws Exception {
                        return (ArrayList) capture2.get();
                    }
                });
            }
        });
    }

    public Task<Integer> getCount(Context context, final String table, final int isDirty) {
        return runWithManagedConnection(new SQLiteDatabaseCallable<Task<Integer>>() {
            public Task<Integer> call(CustomSQLiteDatabase db) {
                String query;
                String[] args;
                if (isDirty < 0) {
                    query = "SELECT * FROM " + table;
                    args = null;
                } else {
                    query = "SELECT * FROM " + table + " WHERE " + DeeplinkDB.IS_DIRTY + "=? ";
                    args = new String[]{String.valueOf(isDirty)};
                }
                return db.rawQueryAsync(query, args).onSuccess(new Continuation<Cursor, Integer>() {
                    public Integer then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        int result = cursor.getCount();
                        cursor.close();
                        return Integer.valueOf(result);
                    }
                });
            }
        });
    }

    public Task<ArrayList<TrackingActivityModel>> getTrackingActivitiesInDB(final String table, final int isDirty) {
        return runWithManagedConnection(new SQLiteDatabaseCallable<Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> call(CustomSQLiteDatabase db) {
                String query;
                String[] args;
                if (isDirty < 0) {
                    query = "SELECT * FROM " + table;
                    args = null;
                } else {
                    query = "SELECT * FROM " + table + " WHERE " + DeeplinkDB.IS_DIRTY + "=? ";
                    args = new String[]{String.valueOf(isDirty)};
                }
                return db.rawQueryAsync(query, args).onSuccess(new Continuation<Cursor, ArrayList<TrackingActivityModel>>() {
                    public ArrayList<TrackingActivityModel> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        ArrayList<TrackingActivityModel> tracking_Info = new ArrayList<>();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            tracking_Info.add(new TrackingActivityModel(cursor.getInt(0), cursor.getString(1), cursor.getString(2), cursor.getInt(3)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return tracking_Info;
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public Task<ArrayList<TrackingActivityModel>> getCleanAppTrackingActivitiesInDBAsync(boolean isOldVersion, CustomSQLiteDatabase db, Context context, String group, String act, long endSessionParam) {
        final Capture<ArrayList<TrackingActivityModel>> raw_list = new Capture<>(new ArrayList());
        final Capture<ArrayList<TrackingActivityModel>> filter_list = new Capture<>(new ArrayList());
        final Context context2 = context;
        final Context context3 = context;
        final CustomSQLiteDatabase customSQLiteDatabase = db;
        final String str = group;
        final String str2 = act;
        final Context context4 = context;
        final CustomSQLiteDatabase customSQLiteDatabase2 = db;
        final long j = endSessionParam;
        final boolean z = isOldVersion;
        final Context context5 = context;
        final CustomSQLiteDatabase customSQLiteDatabase3 = db;
        return db.rawQueryAsync("SELECT * FROM tbl_AppTracking WHERE isDirty=? ORDER BY Id ASC LIMIT 50", new String[]{String.valueOf(0)}).onSuccess(new Continuation<Cursor, ArrayList<TrackingActivityModel>>() {
            public ArrayList<TrackingActivityModel> then(Task<Cursor> task) throws Exception {
                TrackingActivityModel activity;
                Cursor cursor = (Cursor) task.getResult();
                ArrayList<TrackingActivityModel> tracking_Info = new ArrayList<>();
                cursor.moveToFirst();
                while (!cursor.isAfterLast()) {
                    try {
                        JSONObject activityJson = new JSONObject(cursor.getString(2));
                        String created_at = activityJson.getString("created_at");
                        if (created_at == null || created_at.equals("")) {
                            created_at = CommonHelper.GetKSTServerTimeAsString(context2);
                        }
                        activityJson.put("created_at", created_at);
                        activity = new TrackingActivityModel(cursor.getInt(0), cursor.getString(1), activityJson.toString());
                    } catch (Exception e) {
                        Log.e(IgawConstant.QA_TAG, "Exception at getCleanAppTrackingActivitiesInDBAsync: " + e.getMessage());
                        activity = new TrackingActivityModel(cursor.getInt(0), cursor.getString(1), cursor.getString(2));
                    }
                    tracking_Info.add(activity);
                    cursor.moveToNext();
                }
                cursor.close();
                return tracking_Info;
            }
        }).onSuccessTask(new Continuation<ArrayList<TrackingActivityModel>, Task<Void>>() {
            public Task<Void> then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                raw_list.set((ArrayList) task.getResult());
                if (((ArrayList) raw_list.get()).size() <= TrackingActivitySQLiteDB.MAXIMUM_NUMBER_OF_TRACKING_ACTIVITY) {
                    return Task.forResult(null);
                }
                IgawLogger.Logging(context3, IgawConstant.QA_TAG, "ADBrixManager > too old tracking activities will be removed", 2, false);
                raw_list.set(new ArrayList());
                return TrackingActivitySQLiteDB.this.clearTrackingActivities(customSQLiteDatabase);
            }
        }).onSuccessTask(new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> task) throws Exception {
                ArrayList<TrackingActivityModel> list = (ArrayList) raw_list.get();
                ArrayList<TrackingActivityModel> filtered_activity_info_list = new ArrayList<>();
                ArrayList arrayList = new ArrayList();
                int i = 0;
                while (i < list.size()) {
                    TrackingActivityModel mTrackingActivityModel = list.get(i);
                    String activity = mTrackingActivityModel.getValue();
                    try {
                        JSONObject valObj = new JSONObject(activity);
                        if (str.equals(SettingsJsonConstants.SESSION_KEY) && str2.equals("end") && valObj != null && list.size() == 1 && valObj.has("group") && !valObj.isNull("group") && valObj.getString("group").equals(SettingsJsonConstants.SESSION_KEY) && valObj.has("activity") && !valObj.isNull("activity") && valObj.getString("activity").equals("end")) {
                            IgawLogger.Logging(context4, IgawConstant.QA_TAG, "ADBrixManager > endSession called consecutively. remove prev endSession", 3);
                            arrayList.add(TrackingActivitySQLiteDB.this.removeTrackingData(context4, list, customSQLiteDatabase2, TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING));
                        }
                        if (!str.equals(SettingsJsonConstants.SESSION_KEY) || !str2.equals("start") || !mTrackingActivityModel.getKey().endsWith("_session_end") || !valObj.has("param") || valObj.isNull("param") || !valObj.getString("param").equals(j)) {
                            filtered_activity_info_list.add(mTrackingActivityModel);
                            i++;
                        } else {
                            IgawLogger.Logging(context4, IgawConstant.QA_TAG, "ADBrixManager > startSession - skip adding end session to tracking param : keep session!!!", 3);
                            arrayList.add(TrackingActivitySQLiteDB.this.removeSingleActivity(context4, mTrackingActivityModel, customSQLiteDatabase2, TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING));
                            i++;
                        }
                    } catch (Exception e) {
                        arrayList.add(TrackingActivitySQLiteDB.this.removeSingleActivity(context4, mTrackingActivityModel, customSQLiteDatabase2, TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING));
                        IgawLogger.Logging(context4, IgawConstant.QA_TAG, "Error when sending tracking data: " + activity, 0, true);
                    }
                }
                filter_list.set(filtered_activity_info_list);
                return Task.whenAll(arrayList);
            }
        }).onSuccessTask(new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> task) throws Exception {
                ArrayList<TrackingActivityModel> flist = (ArrayList) filter_list.get();
                if (!z) {
                    return TrackingActivitySQLiteDB.this.updateIsDirtyProperpy(context5, flist, 1, customSQLiteDatabase3, TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING);
                }
                IgawLogger.Logging(context5, IgawConstant.QA_TAG, "Compat >> removeTrackingData", 2, true);
                return TrackingActivitySQLiteDB.this.removeTrackingData(context5, flist, customSQLiteDatabase3, TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING);
            }
        }).onSuccess(new Continuation<Void, ArrayList<TrackingActivityModel>>() {
            public ArrayList<TrackingActivityModel> then(Task<Void> task) throws Exception {
                return (ArrayList) filter_list.get();
            }
        });
    }

    /* access modifiers changed from: private */
    public Task<ArrayList<TrackingActivityModel>> getOrphanDirtyTrackingActivitiesInDBAsync(final CustomSQLiteDatabase db, String table, final Context context) {
        String query = "SELECT * FROM " + table + " WHERE " + DeeplinkDB.IS_DIRTY + "=? ";
        String[] args = {String.valueOf(1)};
        final Capture<ArrayList<TrackingActivityModel>> o_list = new Capture<>(new ArrayList());
        return db.rawQueryAsync(query, args).onSuccess(new Continuation<Cursor, ArrayList<TrackingActivityModel>>() {
            public ArrayList<TrackingActivityModel> then(Task<Cursor> task) throws Exception {
                Cursor cursor = (Cursor) task.getResult();
                ArrayList<TrackingActivityModel> tracking_Info = new ArrayList<>();
                cursor.moveToFirst();
                while (!cursor.isAfterLast()) {
                    tracking_Info.add(new TrackingActivityModel(cursor.getInt(0), cursor.getString(1), cursor.getString(2)));
                    cursor.moveToNext();
                }
                cursor.close();
                return tracking_Info;
            }
        }).onSuccessTask(new Continuation<ArrayList<TrackingActivityModel>, Task<Void>>() {
            public Task<Void> then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                o_list.set((ArrayList) task.getResult());
                if (((ArrayList) o_list.get()).size() <= TrackingActivitySQLiteDB.MAXIMUM_NUMBER_OF_TRACKING_ACTIVITY) {
                    return Task.forResult(null);
                }
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "getOrphanDirtyrackingActivitiesInDB > too old tracking activities will be removed", 2, false);
                o_list.set(new ArrayList());
                return TrackingActivitySQLiteDB.this.clearTrackingActivities(db);
            }
        }).onSuccess(new Continuation<Void, ArrayList<TrackingActivityModel>>() {
            public ArrayList<TrackingActivityModel> then(Task<Void> task) throws Exception {
                return (ArrayList) o_list.get();
            }
        });
    }

    /* access modifiers changed from: private */
    public Task<Void> clearTrackingActivities(final CustomSQLiteDatabase db) {
        return db.deleteAsync(TrackingActivitySQLiteOpenHelper.TABLE_APP_TRACKING, null, null).continueWithTask(new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> task) throws Exception {
                return db.deleteAsync(TrackingActivitySQLiteOpenHelper.TABLE_IMPRESSION_TRACKING, null, null);
            }
        });
    }

    /* access modifiers changed from: private */
    public Task<Void> removeSingleActivity(Context context, TrackingActivityModel mTrackingActivityModel, CustomSQLiteDatabase db, String table) {
        String[] args = {String.valueOf(mTrackingActivityModel.getId())};
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "Filter activity" + mTrackingActivityModel.getValue(), 2, true);
        return db.deleteAsync(table, "Id = ?", args);
    }

    /* access modifiers changed from: private */
    public Task<Void> updateIsDirtyProperpy(Context context, ArrayList<TrackingActivityModel> mTrackingActivityModel, int isDirty, CustomSQLiteDatabase db, String table) {
        if (mTrackingActivityModel == null) {
            return Task.forResult(null);
        }
        final int size = mTrackingActivityModel.size();
        final AtomicInteger count = new AtomicInteger(0);
        final ArrayList<TrackingActivityModel> arrayList = mTrackingActivityModel;
        final int i = isDirty;
        final Context context2 = context;
        final String str = table;
        final CustomSQLiteDatabase customSQLiteDatabase = db;
        return Task.forResult(null).continueWhile(new Callable<Boolean>() {
            public Boolean call() throws Exception {
                return count.get() < size ? Boolean.valueOf(true) : Boolean.valueOf(false);
            }
        }, new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> task) throws Exception {
                int index = count.getAndIncrement();
                TrackingActivityModel appTrack = (TrackingActivityModel) arrayList.get(index);
                int id = appTrack.getId();
                String activity = appTrack.getValue();
                ContentValues values = new ContentValues();
                values.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(i));
                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "Update table " + str + ". Index " + index + " : " + activity + " >> isDirty = " + i, 3, true);
                return customSQLiteDatabase.updateAsync(str, values, "Id = ?", new String[]{String.valueOf(id)}).makeVoid();
            }
        });
    }

    /* access modifiers changed from: private */
    public Task<Void> removeTrackingData(Context context, ArrayList<TrackingActivityModel> mTrackingActivityModel, CustomSQLiteDatabase db, String table) {
        if (mTrackingActivityModel == null) {
            return Task.forResult(null);
        }
        final int size = mTrackingActivityModel.size();
        final AtomicInteger count = new AtomicInteger(0);
        final ArrayList<TrackingActivityModel> arrayList = mTrackingActivityModel;
        final CustomSQLiteDatabase customSQLiteDatabase = db;
        final String str = table;
        return Task.forResult(null).continueWhile(new Callable<Boolean>() {
            public Boolean call() throws Exception {
                return count.get() < size ? Boolean.valueOf(true) : Boolean.valueOf(false);
            }
        }, new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> task) throws Exception {
                return customSQLiteDatabase.deleteAsync(str, "Id=?", new String[]{String.valueOf(((TrackingActivityModel) arrayList.get(count.getAndIncrement())).getId())});
            }
        });
    }

    private <T> Task<T> runWithManagedConnection(final SQLiteDatabaseCallable<Task<T>> callable) {
        return this.helper.getWritableDatabaseAsync().onSuccessTask(new Continuation<CustomSQLiteDatabase, Task<T>>() {
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

    private Task<Void> runWithManagedTransaction(final SQLiteDatabaseCallable<Task<Void>> callable) {
        return this.helper.getWritableDatabaseAsync().onSuccessTask(new Continuation<CustomSQLiteDatabase, Task<Void>>() {
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

    private <T> Task<T> runWithManagedComplexTransaction(final SQLiteDatabaseCallable<Task<T>> callable) {
        return this.helper.getWritableDatabaseAsync().onSuccessTask(new Continuation<CustomSQLiteDatabase, Task<T>>() {
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