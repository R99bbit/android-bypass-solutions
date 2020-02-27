package com.igaworks.dao;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.model.DeeplinkConversionItem;
import com.igaworks.model.DeeplinkReEngagementConversion;
import com.igaworks.util.bolts_task.Capture;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;

public class DeeplinkConversionRetryDAO extends DeeplinkDB {
    private static DeeplinkConversionRetryDAO counterForConversionDao;

    public static DeeplinkConversionRetryDAO getDAO(Context context) {
        if (counterForConversionDao == null) {
            synchronized (DeeplinkConversionRetryDAO.class) {
                try {
                    if (counterForConversionDao == null) {
                        counterForConversionDao = new DeeplinkConversionRetryDAO(context);
                    }
                }
            }
        }
        if (CommonFrameworkImpl.getContext() == null) {
            CommonFrameworkImpl.setContext(context);
        }
        return counterForConversionDao;
    }

    private DeeplinkConversionRetryDAO(Context context) {
        try {
            if (this.dbHelper == null) {
                this.dbHelper = new CommerceDBOpenHelper(context, DeeplinkDB.DATABASE_NAME, null, 4);
            }
        } catch (Exception e) {
        }
    }

    public ArrayList<DeeplinkConversionItem> getRetryConversions(final Context context) {
        final Capture<ArrayList<DeeplinkConversionItem>> retryList = new Capture<>(new ArrayList());
        try {
            return (ArrayList) TaskUtils.wait(runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<ArrayList<DeeplinkConversionItem>>>() {
                public Task<ArrayList<DeeplinkConversionItem>> call(CustomSQLiteDatabase db) {
                    final CustomSQLiteDatabase _db = db;
                    Task onSuccess = _db.queryAsync(DeeplinkDB.DATABASE_TABLE_CONVERSION_RESTORE, new String[]{"_id", "conversion_key", DeeplinkDB.COMMERCE_CLICK_ID, DeeplinkDB.LINK_PARAM, "retry_count", DeeplinkDB.IS_DIRTY}, "isDirty = 0", null).onSuccess(new Continuation<Cursor, ArrayList<DeeplinkConversionItem>>() {
                        public ArrayList<DeeplinkConversionItem> then(Task<Cursor> task) throws Exception {
                            Cursor cursor = (Cursor) task.getResult();
                            ArrayList<DeeplinkConversionItem> result = new ArrayList<>();
                            cursor.moveToFirst();
                            while (!cursor.isAfterLast()) {
                                result.add(new DeeplinkConversionItem(cursor.getInt(0), cursor.getInt(1), cursor.getString(2), cursor.getString(3), cursor.getInt(4), cursor.getInt(5)));
                                cursor.moveToNext();
                            }
                            cursor.close();
                            return result;
                        }
                    });
                    final Capture capture = retryList;
                    final Context context = context;
                    Task onSuccessTask = onSuccess.onSuccessTask(new Continuation<ArrayList<DeeplinkConversionItem>, Task<Void>>() {
                        public Task<Void> then(Task<ArrayList<DeeplinkConversionItem>> task) throws Exception {
                            capture.set((ArrayList) task.getResult());
                            return DeeplinkConversionRetryDAO.this.updateIsDirtyProperpy(context, (ArrayList) capture.get(), 1, _db, DeeplinkDB.DATABASE_TABLE_CONVERSION_RESTORE);
                        }
                    });
                    final Capture capture2 = retryList;
                    return onSuccessTask.onSuccess(new Continuation<Void, ArrayList<DeeplinkConversionItem>>() {
                        public ArrayList<DeeplinkConversionItem> then(Task<Void> task) throws Exception {
                            return (ArrayList) capture2.get();
                        }
                    });
                }
            }));
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(IgawConstant.QA_TAG, "DeeplinkConversionRetryDAO >> getRetryConversions Error: " + e.getMessage());
            return null;
        }
    }

    /* access modifiers changed from: private */
    public Task<Void> updateIsDirtyProperpy(Context context, ArrayList<DeeplinkConversionItem> mDeeplinkConversionItem, int isDirty, CustomSQLiteDatabase db, String table) {
        if (mDeeplinkConversionItem == null) {
            return Task.forResult(null);
        }
        final int size = mDeeplinkConversionItem.size();
        final AtomicInteger count = new AtomicInteger(0);
        final ArrayList<DeeplinkConversionItem> arrayList = mDeeplinkConversionItem;
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
                DeeplinkConversionItem conversion = (DeeplinkConversionItem) arrayList.get(index);
                int id = conversion.getKey();
                int ck = conversion.getConversionKey();
                ContentValues values = new ContentValues();
                values.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(i));
                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "Update table " + str + ". Index: " + index + " and ck = " + ck + " >> isDirty = " + i, 3, true);
                return customSQLiteDatabase.updateAsync(str, values, "_id = ?", new String[]{String.valueOf(id)}).makeVoid();
            }
        });
    }

    public int getRetryCount(final int key) {
        Task<Integer> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Integer>>() {
            public Task<Integer> call(CustomSQLiteDatabase db) {
                return db.queryAsync(DeeplinkDB.DATABASE_TABLE_CONVERSION_RESTORE, new String[]{"_id", "retry_count"}, "_id=" + key, null).onSuccess(new Continuation<Cursor, Integer>() {
                    public Integer then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (!cursor.moveToFirst() || cursor.getCount() == 0) {
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
            Log.e(IgawConstant.QA_TAG, "DeeplinkConversionRetryDAO >> getRetryCount >> Key: " + key + ">> Error: " + e.getMessage());
            return 0;
        }
    }

    public void updateOrInsertConversionForRetry(final int key, final int conversionKey, final String clickID) {
        runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task<Cursor> queryAsync = _db.queryAsync(DeeplinkDB.DATABASE_TABLE_CONVERSION_RESTORE, new String[]{"_id", "retry_count"}, "_id=" + key, null);
                final int i = conversionKey;
                final String str = clickID;
                final int i2 = key;
                return queryAsync.onSuccessTask(new Continuation<Cursor, Task<Void>>() {
                    public Task<Void> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (!cursor.moveToFirst() || cursor.getCount() == 0) {
                            cursor.close();
                            ContentValues newTaskValues = new ContentValues();
                            newTaskValues.put("conversion_key", Integer.valueOf(i));
                            newTaskValues.put(DeeplinkDB.COMMERCE_CLICK_ID, str);
                            newTaskValues.put("retry_count", Integer.valueOf(0));
                            newTaskValues.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(0));
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("add retry conversion : key = %d, conversionKey = %d ", new Object[]{Integer.valueOf(i2), Integer.valueOf(i)}), 2);
                            return _db.insertOrThrowAsync(DeeplinkDB.DATABASE_TABLE_CONVERSION_RESTORE, newTaskValues);
                        }
                        int retry = cursor.getInt(1) + 1;
                        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("add retry conversion : key = %d, conversionKey = %d , retry time = %d", new Object[]{Integer.valueOf(i2), Integer.valueOf(i), Integer.valueOf(retry)}), 2);
                        ContentValues newValue = new ContentValues();
                        newValue.put("retry_count", Integer.valueOf(retry));
                        newValue.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(0));
                        cursor.close();
                        return _db.updateAsync(DeeplinkDB.DATABASE_TABLE_CONVERSION_RESTORE, newValue, "_id=" + i2, null).makeVoid();
                    }
                });
            }
        });
    }

    public boolean removeRetryCount(final int key) {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "removeRetryCount key =  " + key, 2);
                return db.deleteAsync(DeeplinkDB.DATABASE_TABLE_CONVERSION_RESTORE, "_id=" + key, null).makeVoid();
            }
        });
        return true;
    }

    @Deprecated
    public boolean clearRetryItems() {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "Remove restore queue", 2);
                return db.deleteAsync(DeeplinkDB.DATABASE_TABLE_CONVERSION_RESTORE, null, null).makeVoid();
            }
        });
        return true;
    }

    public Task<Void> removeDeeplinkConversionItems(final ArrayList<DeeplinkConversionItem> list, final Context context) {
        return runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                return DeeplinkConversionRetryDAO.this.removeDeeplinkConversionItemList(context, list, db, DeeplinkDB.DATABASE_TABLE_CONVERSION_RESTORE);
            }
        });
    }

    /* access modifiers changed from: private */
    public Task<Void> removeDeeplinkConversionItemList(Context context, ArrayList<DeeplinkConversionItem> list, CustomSQLiteDatabase db, String table) {
        if (list == null) {
            return Task.forResult(null);
        }
        final int size = list.size();
        final AtomicInteger count = new AtomicInteger(0);
        final ArrayList<DeeplinkConversionItem> arrayList = list;
        final Context context2 = context;
        final CustomSQLiteDatabase customSQLiteDatabase = db;
        final String str = table;
        return Task.forResult(null).continueWhile(new Callable<Boolean>() {
            public Boolean call() throws Exception {
                return count.get() < size ? Boolean.valueOf(true) : Boolean.valueOf(false);
            }
        }, new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> task) throws Exception {
                int id = ((DeeplinkConversionItem) arrayList.get(count.getAndIncrement())).getKey();
                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "DeeplinkConversionRetryDAO >> Remove restore queue >> key = " + id, 2);
                if (id == -1) {
                    return null;
                }
                return customSQLiteDatabase.deleteAsync(str, "_id=?", new String[]{String.valueOf(id)});
            }
        });
    }

    public ArrayList<DeeplinkReEngagementConversion> getRetryReEngagementConversions(final Context context) {
        final Capture<ArrayList<DeeplinkReEngagementConversion>> retryList = new Capture<>(new ArrayList());
        Task<ArrayList<DeeplinkReEngagementConversion>> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<ArrayList<DeeplinkReEngagementConversion>>>() {
            public Task<ArrayList<DeeplinkReEngagementConversion>> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task onSuccess = _db.queryAsync(DeeplinkDB.TABLE_REENGAGEMENT_CONVERSION, new String[]{"_id", "conversion_key", "deeplink_info", "retry_count", DeeplinkDB.IS_DIRTY}, "isDirty = 0", null).onSuccess(new Continuation<Cursor, ArrayList<DeeplinkReEngagementConversion>>() {
                    public ArrayList<DeeplinkReEngagementConversion> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        ArrayList<DeeplinkReEngagementConversion> result = new ArrayList<>();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            result.add(new DeeplinkReEngagementConversion(cursor.getInt(0), cursor.getInt(1), cursor.getString(2), cursor.getInt(3), cursor.getInt(4)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return result;
                    }
                });
                final Capture capture = retryList;
                final Context context = context;
                Task onSuccessTask = onSuccess.onSuccessTask(new Continuation<ArrayList<DeeplinkReEngagementConversion>, Task<Void>>() {
                    public Task<Void> then(Task<ArrayList<DeeplinkReEngagementConversion>> task) throws Exception {
                        capture.set((ArrayList) task.getResult());
                        return DeeplinkConversionRetryDAO.this.updateIsDirtyProperpyForDLReEngMent(context, (ArrayList) capture.get(), 1, _db, DeeplinkDB.TABLE_REENGAGEMENT_CONVERSION);
                    }
                });
                final Capture capture2 = retryList;
                return onSuccessTask.onSuccess(new Continuation<Void, ArrayList<DeeplinkReEngagementConversion>>() {
                    public ArrayList<DeeplinkReEngagementConversion> then(Task<Void> task) throws Exception {
                        return (ArrayList) capture2.get();
                    }
                });
            }
        });
        try {
            TaskUtils.wait(task);
            return (ArrayList) task.getResult();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(IgawConstant.QA_TAG, "DeeplinkConversionRetryDAO >> getRetryReEngConversions Error: " + e.getMessage());
            return null;
        }
    }

    /* access modifiers changed from: private */
    public Task<Void> updateIsDirtyProperpyForDLReEngMent(Context context, ArrayList<DeeplinkReEngagementConversion> DeeplinkReEngagementConversionList, int isDirty, CustomSQLiteDatabase db, String table) {
        if (DeeplinkReEngagementConversionList == null) {
            return Task.forResult(null);
        }
        final int size = DeeplinkReEngagementConversionList.size();
        final AtomicInteger count = new AtomicInteger(0);
        final ArrayList<DeeplinkReEngagementConversion> arrayList = DeeplinkReEngagementConversionList;
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
                DeeplinkReEngagementConversion conversion = (DeeplinkReEngagementConversion) arrayList.get(index);
                int id = conversion.getKey();
                int ck = conversion.getConversionKey();
                ContentValues values = new ContentValues();
                values.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(i));
                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "Update table " + str + ". Index: " + index + " and ck = " + ck + " >> isDirty = " + i, 3, true);
                return customSQLiteDatabase.updateAsync(str, values, "_id = ?", new String[]{String.valueOf(id)}).makeVoid();
            }
        });
    }

    public void updateOrInsertDLReEngMntConversionForRetry(final int key, final int conversionKey, final String deeplink_info) {
        runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task<Cursor> queryAsync = _db.queryAsync(DeeplinkDB.TABLE_REENGAGEMENT_CONVERSION, new String[]{"_id", "retry_count"}, "_id=" + key, null);
                final int i = conversionKey;
                final String str = deeplink_info;
                final int i2 = key;
                return queryAsync.onSuccessTask(new Continuation<Cursor, Task<Void>>() {
                    public Task<Void> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (!cursor.moveToFirst() || cursor.getCount() == 0) {
                            cursor.close();
                            ContentValues newTaskValues = new ContentValues();
                            newTaskValues.put("conversion_key", Integer.valueOf(i));
                            newTaskValues.put("deeplink_info", str);
                            newTaskValues.put("retry_count", Integer.valueOf(0));
                            newTaskValues.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(0));
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("DeeplinkReEngaMnt: add retry conversion : key = %d, conversionKey = %d ", new Object[]{Integer.valueOf(i2), Integer.valueOf(i)}), 2);
                            return _db.insertOrThrowAsync(DeeplinkDB.TABLE_REENGAGEMENT_CONVERSION, newTaskValues);
                        }
                        int retry = cursor.getInt(1) + 1;
                        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("DeeplinkReEngaMnt: add retry conversion : key = %d, conversionKey = %d , retry time = %d", new Object[]{Integer.valueOf(i2), Integer.valueOf(i), Integer.valueOf(retry)}), 2);
                        ContentValues newValue = new ContentValues();
                        newValue.put("retry_count", Integer.valueOf(retry));
                        newValue.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(0));
                        cursor.close();
                        return _db.updateAsync(DeeplinkDB.TABLE_REENGAGEMENT_CONVERSION, newValue, "_id=" + i2, null).makeVoid();
                    }
                });
            }
        });
    }

    public boolean removeDLReEngMntRetryConversion(final int key) {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "DeeplinkReEngaMnt: removeRetryCount key =  " + key, 2);
                return db.deleteAsync(DeeplinkDB.TABLE_REENGAGEMENT_CONVERSION, "_id=" + key, null).makeVoid();
            }
        });
        return true;
    }

    public ArrayList<DeeplinkReEngagementConversion> getRetryThirdPartyConversions(final Context context) {
        final Capture<ArrayList<DeeplinkReEngagementConversion>> retryList = new Capture<>(new ArrayList());
        Task<ArrayList<DeeplinkReEngagementConversion>> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<ArrayList<DeeplinkReEngagementConversion>>>() {
            public Task<ArrayList<DeeplinkReEngagementConversion>> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task onSuccess = _db.queryAsync(DeeplinkDB.TABLE_THIRD_PARTY_CONVERSION, new String[]{"_id", "conversion_key", "deeplink_info", "retry_count", DeeplinkDB.IS_DIRTY}, "isDirty = 0", null).onSuccess(new Continuation<Cursor, ArrayList<DeeplinkReEngagementConversion>>() {
                    public ArrayList<DeeplinkReEngagementConversion> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        ArrayList<DeeplinkReEngagementConversion> result = new ArrayList<>();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            result.add(new DeeplinkReEngagementConversion(cursor.getInt(0), cursor.getInt(1), cursor.getString(2), cursor.getInt(3), cursor.getInt(4)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return result;
                    }
                });
                final Capture capture = retryList;
                final Context context = context;
                Task onSuccessTask = onSuccess.onSuccessTask(new Continuation<ArrayList<DeeplinkReEngagementConversion>, Task<Void>>() {
                    public Task<Void> then(Task<ArrayList<DeeplinkReEngagementConversion>> task) throws Exception {
                        capture.set((ArrayList) task.getResult());
                        return DeeplinkConversionRetryDAO.this.updateIsDirtyProperpyForDLReEngMent(context, (ArrayList) capture.get(), 1, _db, DeeplinkDB.TABLE_THIRD_PARTY_CONVERSION);
                    }
                });
                final Capture capture2 = retryList;
                return onSuccessTask.onSuccess(new Continuation<Void, ArrayList<DeeplinkReEngagementConversion>>() {
                    public ArrayList<DeeplinkReEngagementConversion> then(Task<Void> task) throws Exception {
                        return (ArrayList) capture2.get();
                    }
                });
            }
        });
        try {
            TaskUtils.wait(task);
            return (ArrayList) task.getResult();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(IgawConstant.QA_TAG, "DeeplinkConversionRetryDAO >> getRetryThirdPartyConversions Error: " + e.getMessage());
            return null;
        }
    }

    public void updateOrInsertDLThirdPartyConversionForRetry(final int key, final int conversionKey, final String deeplink_info) {
        runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task<Cursor> queryAsync = _db.queryAsync(DeeplinkDB.TABLE_THIRD_PARTY_CONVERSION, new String[]{"_id", "retry_count"}, "_id=" + key, null);
                final int i = conversionKey;
                final String str = deeplink_info;
                final int i2 = key;
                return queryAsync.onSuccessTask(new Continuation<Cursor, Task<Void>>() {
                    public Task<Void> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (!cursor.moveToFirst() || cursor.getCount() == 0) {
                            cursor.close();
                            ContentValues newTaskValues = new ContentValues();
                            newTaskValues.put("conversion_key", Integer.valueOf(i));
                            newTaskValues.put("deeplink_info", str);
                            newTaskValues.put("retry_count", Integer.valueOf(0));
                            newTaskValues.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(0));
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("ThirdPartyConversion: add retry conversion : key = %d, conversionKey = %d ", new Object[]{Integer.valueOf(i2), Integer.valueOf(i)}), 2);
                            return _db.insertOrThrowAsync(DeeplinkDB.TABLE_THIRD_PARTY_CONVERSION, newTaskValues);
                        }
                        int retry = cursor.getInt(1) + 1;
                        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("ThirdPartyConversion: add retry conversion : key = %d, conversionKey = %d , retry time = %d", new Object[]{Integer.valueOf(i2), Integer.valueOf(i), Integer.valueOf(retry)}), 2);
                        ContentValues newValue = new ContentValues();
                        newValue.put("retry_count", Integer.valueOf(retry));
                        newValue.put(DeeplinkDB.IS_DIRTY, Integer.valueOf(0));
                        cursor.close();
                        return _db.updateAsync(DeeplinkDB.TABLE_THIRD_PARTY_CONVERSION, newValue, "_id=" + i2, null).makeVoid();
                    }
                });
            }
        });
    }

    public boolean removeThirdPartyRetryConversion(final int key) {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "ThirdPartyConversion: removeRetryCount key =  " + key, 2);
                return db.deleteAsync(DeeplinkDB.TABLE_THIRD_PARTY_CONVERSION, "_id=" + key, null).makeVoid();
            }
        });
        return true;
    }
}