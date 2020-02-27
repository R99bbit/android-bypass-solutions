package com.igaworks.commerce.db;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.database.Cursor;
import android.util.Log;
import com.igaworks.commerce.model.CommerceV2EventItem;
import com.igaworks.commerce.net.CommerceHttpManager;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.util.bolts_task.Capture;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;

public class CommerceEventV2DAO extends CommerceDB {
    public static final String COMMERCE_EVENT_SP_V2_COUNT_OF_SAVED = "CommerceEventsV2_count_of_saved";
    public static final String COMMERCE_EVENT_SP_V2_NAME = "CommerceEventsV2";
    private static CommerceEventV2DAO counterForAllActivityDao;
    private static CommerceHttpManager httpManager = new CommerceHttpManager();

    public static CommerceEventV2DAO getDAO(Context _context) {
        if (counterForAllActivityDao == null) {
            synchronized (CommerceEventV2DAO.class) {
                if (counterForAllActivityDao == null) {
                    counterForAllActivityDao = new CommerceEventV2DAO(_context);
                }
            }
        }
        if (CommonFrameworkImpl.getContext() == null) {
            CommonFrameworkImpl.setContext(_context);
        }
        return counterForAllActivityDao;
    }

    private CommerceEventV2DAO(Context _context) {
        try {
            if (this.dbHelper == null) {
                this.dbHelper = new CommerceDBOpenHelper(_context, CommerceDB.DATABASE_NAME, null, 3);
            }
        } catch (Exception e) {
        }
    }

    public ArrayList<CommerceV2EventItem> getEventForCommerceV2() {
        final Capture<ArrayList<CommerceV2EventItem>> retryList = new Capture<>(new ArrayList());
        Task<ArrayList<CommerceV2EventItem>> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<ArrayList<CommerceV2EventItem>>>() {
            public Task<ArrayList<CommerceV2EventItem>> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task onSuccess = _db.queryAsync(CommerceDB.DATABASE_TABLE_COMMERCE_EVENT_V2, new String[]{"_id", CommerceDB.EVENT_JSON_VALUE, "retry_count"}, null, null).onSuccess(new Continuation<Cursor, ArrayList<CommerceV2EventItem>>() {
                    public ArrayList<CommerceV2EventItem> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        ArrayList<CommerceV2EventItem> result = new ArrayList<>();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            result.add(new CommerceV2EventItem(cursor.getInt(0), cursor.getString(1), cursor.getInt(2)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return result;
                    }
                });
                final Capture capture = retryList;
                Task onSuccessTask = onSuccess.onSuccessTask(new Continuation<ArrayList<CommerceV2EventItem>, Task<Void>>() {
                    public Task<Void> then(Task<ArrayList<CommerceV2EventItem>> task) throws Exception {
                        capture.set((ArrayList) task.getResult());
                        return CommerceEventV2DAO.this.updateIsDirtyProperpy(CommonFrameworkImpl.getContext(), (ArrayList) capture.get(), 1, _db, CommerceDB.DATABASE_TABLE_COMMERCE_EVENT_V2);
                    }
                });
                final Capture capture2 = retryList;
                return onSuccessTask.onSuccess(new Continuation<Void, ArrayList<CommerceV2EventItem>>() {
                    public ArrayList<CommerceV2EventItem> then(Task<Void> task) throws Exception {
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
            Log.e(IgawConstant.QA_TAG, "CommerceEnvetV2DAO >> getEventForCommerceV2 Error: " + e.getMessage());
            return null;
        }
    }

    /* access modifiers changed from: private */
    public Task<Void> updateIsDirtyProperpy(Context context, ArrayList<CommerceV2EventItem> mPurchaseItem, int isDirty, CustomSQLiteDatabase db, String table) {
        if (mPurchaseItem == null) {
            return Task.forResult(null);
        }
        final int size = mPurchaseItem.size();
        final AtomicInteger count = new AtomicInteger(0);
        final ArrayList<CommerceV2EventItem> arrayList = mPurchaseItem;
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
                int id = ((CommerceV2EventItem) arrayList.get(index)).getKey();
                ContentValues values = new ContentValues();
                values.put(CommerceDB.IS_DIRTY, Integer.valueOf(i));
                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "Update table " + str + ". Index: " + index + " and key = " + id + " >> isDirty = " + i, 3, true);
                return customSQLiteDatabase.updateAsync(str, values, "_id = ?", new String[]{String.valueOf(id)}).makeVoid();
            }
        });
    }

    public int getRetryCount(final int key) {
        Task<Integer> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Integer>>() {
            public Task<Integer> call(CustomSQLiteDatabase db) {
                return db.queryAsync(CommerceDB.DATABASE_TABLE_COMMERCE_EVENT_V2, new String[]{"_id", "retry_count"}, "_id=" + key, null).onSuccess(new Continuation<Cursor, Integer>() {
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
            Log.e(IgawConstant.QA_TAG, "CommerceEventV2DAO >> getRetryCount >> Key: " + key + ">> Error: " + e.getMessage());
            return 0;
        }
    }

    public void updateOrInsertConversion(final int key, final String pJson) {
        runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task<Cursor> queryAsync = _db.queryAsync(CommerceDB.DATABASE_TABLE_COMMERCE_EVENT_V2, new String[]{"_id", "retry_count"}, "_id=" + key, null);
                final int i = key;
                final String str = pJson;
                return queryAsync.onSuccessTask(new Continuation<Cursor, Task<Void>>() {
                    public Task<Void> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (!cursor.moveToFirst() || cursor.getCount() == 0) {
                            cursor.close();
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("CommerceEventV2DAO >> add eventForCommerceV2 : key = %d, json = %s", new Object[]{Integer.valueOf(i), str}), 2);
                            ContentValues newTaskValues = new ContentValues();
                            newTaskValues.put(CommerceDB.EVENT_JSON_VALUE, str);
                            newTaskValues.put("retry_count", Integer.valueOf(0));
                            newTaskValues.put(CommerceDB.IS_DIRTY, Integer.valueOf(0));
                            return _db.insertOrThrowAsync(CommerceDB.DATABASE_TABLE_COMMERCE_EVENT_V2, newTaskValues);
                        }
                        int count = cursor.getInt(1);
                        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("CommerceEventV2DAO >> add eventForCommerceV2 : key = %d, json = %s , retry time: " + count, new Object[]{Integer.valueOf(i), str}), 2);
                        ContentValues newValue = new ContentValues();
                        newValue.put("retry_count", Integer.valueOf(cursor.getInt(1) + 1));
                        newValue.put(CommerceDB.IS_DIRTY, Integer.valueOf(0));
                        cursor.close();
                        return _db.updateAsync(CommerceDB.DATABASE_TABLE_COMMERCE_EVENT_V2, newValue, "_id=" + i, null).makeVoid();
                    }
                }).onSuccess(new Continuation<Void, Void>() {
                    public Void then(Task<Void> task) throws Exception {
                        return null;
                    }
                });
            }
        });
    }

    public boolean removeRetryCount(final int key) {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "CommerceEventV2DAO >> removeRetryCount key =  " + key, 2);
                return db.deleteAsync(CommerceDB.DATABASE_TABLE_COMMERCE_EVENT_V2, "_id=" + key, null).makeVoid();
            }
        });
        return true;
    }

    @Deprecated
    public boolean clearRetryItems() {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "CommerceEventV2DAO >> Remove restore queue", 2);
                return db.deleteAsync(CommerceDB.DATABASE_TABLE_COMMERCE_EVENT_V2, null, null).makeVoid();
            }
        });
        return true;
    }

    public Task<Void> removePurchaseItem(final ArrayList<CommerceV2EventItem> list, final Context context) {
        return runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                return CommerceEventV2DAO.this.removePurchaseItemList(context, list, db, CommerceDB.DATABASE_TABLE_COMMERCE_EVENT_V2);
            }
        });
    }

    /* access modifiers changed from: private */
    public Task<Void> removePurchaseItemList(Context context, ArrayList<CommerceV2EventItem> list, CustomSQLiteDatabase db, String table) {
        if (list == null) {
            return Task.forResult(null);
        }
        final int size = list.size();
        final AtomicInteger count = new AtomicInteger(0);
        final ArrayList<CommerceV2EventItem> arrayList = list;
        final Context context2 = context;
        final CustomSQLiteDatabase customSQLiteDatabase = db;
        final String str = table;
        return Task.forResult(null).continueWhile(new Callable<Boolean>() {
            public Boolean call() throws Exception {
                return count.get() < size ? Boolean.valueOf(true) : Boolean.valueOf(false);
            }
        }, new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> task) throws Exception {
                CommerceV2EventItem mPurchaseItem = (CommerceV2EventItem) arrayList.get(count.getAndIncrement());
                int id = mPurchaseItem.getKey();
                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "CommerceEventV2DAO >> Remove restore queue >> key = " + id + " json = " + mPurchaseItem.getJson(), 2);
                if (id == -1) {
                    return null;
                }
                return customSQLiteDatabase.deleteAsync(str, "_id=?", new String[]{String.valueOf(id)});
            }
        });
    }

    public static SharedPreferences getCommerceEventsSP(Context context) {
        return context.getSharedPreferences(COMMERCE_EVENT_SP_V2_NAME, 0);
    }

    public static SharedPreferences getCommerceEventsSPCountOfSaved(Context context) {
        return context.getSharedPreferences(COMMERCE_EVENT_SP_V2_COUNT_OF_SAVED, 0);
    }

    public static void addEvents(Context context, List<String> items) {
        Editor edt = getCommerceEventsSP(context).edit();
        for (String cem : items) {
            edt.putString(cem.toString(), cem.toString());
        }
        edt.commit();
    }

    public static void addEvent(Context context, String item) {
        Editor edt = getCommerceEventsSP(context).edit();
        edt.putString(item, item);
        edt.commit();
    }

    public static List<String> getEvents(Context context) {
        try {
            ArrayList arrayList = new ArrayList(getCommerceEventsSP(context).getAll().values());
            try {
                return arrayList;
            } catch (Exception e) {
                e.printStackTrace();
                return arrayList;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
            try {
            } catch (Exception e3) {
                e3.printStackTrace();
            }
            return null;
        } finally {
            try {
                Editor edt = getCommerceEventsSP(context).edit();
                edt.clear();
                edt.commit();
                Editor edt2 = getCommerceEventsSPCountOfSaved(context).edit();
                r5 = "Count";
                r7 = "Count";
                edt2.putInt(r5, getCommerceEventsSPCountOfSaved(context).getInt(r7, 0) - 1);
                edt2.commit();
            } catch (Exception e4) {
                e4.printStackTrace();
            }
        }
    }
}