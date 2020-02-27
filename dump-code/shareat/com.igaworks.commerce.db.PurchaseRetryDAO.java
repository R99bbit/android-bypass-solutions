package com.igaworks.commerce.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.util.Log;
import com.igaworks.commerce.model.PurchaseItem;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.util.bolts_task.Capture;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.CustomSQLiteDatabase;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.bolts_task.TaskUtils;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;

public class PurchaseRetryDAO extends CommerceDB {
    private static PurchaseRetryDAO counterForAllActivityDao;

    public static PurchaseRetryDAO getDAO(Context _context) {
        if (counterForAllActivityDao == null) {
            synchronized (PurchaseRetryDAO.class) {
                try {
                    if (counterForAllActivityDao == null) {
                        counterForAllActivityDao = new PurchaseRetryDAO(_context);
                    }
                }
            }
        }
        if (CommonFrameworkImpl.getContext() == null) {
            CommonFrameworkImpl.setContext(_context);
        }
        return counterForAllActivityDao;
    }

    private PurchaseRetryDAO(Context _context) {
        try {
            if (this.dbHelper == null) {
                this.dbHelper = new CommerceDBOpenHelper(_context, CommerceDB.DATABASE_NAME, null, 3);
            }
        } catch (Exception e) {
        }
    }

    public ArrayList<PurchaseItem> getRetryPurchase() {
        final Capture<ArrayList<PurchaseItem>> retryList = new Capture<>(new ArrayList());
        Task<ArrayList<PurchaseItem>> task = runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<ArrayList<PurchaseItem>>>() {
            public Task<ArrayList<PurchaseItem>> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task onSuccess = _db.queryAsync(CommerceDB.DATABASE_TABLE_PURCHASE_RESTORE, new String[]{"_id", CommerceDB.ORDER_ID, CommerceDB.PRODUCT_ID, CommerceDB.PRODUCT_NAME, "price", "quantity", "currency", "category", CommerceDB.CREATE_AT, "retry_count"}, null, null).onSuccess(new Continuation<Cursor, ArrayList<PurchaseItem>>() {
                    public ArrayList<PurchaseItem> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        ArrayList<PurchaseItem> result = new ArrayList<>();
                        cursor.moveToFirst();
                        while (!cursor.isAfterLast()) {
                            result.add(new PurchaseItem(cursor.getInt(0), cursor.getString(1), cursor.getString(2), cursor.getString(3), cursor.getDouble(4), cursor.getInt(5), cursor.getString(6), cursor.getString(7), cursor.getString(8), cursor.getInt(9)));
                            cursor.moveToNext();
                        }
                        cursor.close();
                        return result;
                    }
                });
                final Capture capture = retryList;
                Task onSuccessTask = onSuccess.onSuccessTask(new Continuation<ArrayList<PurchaseItem>, Task<Void>>() {
                    public Task<Void> then(Task<ArrayList<PurchaseItem>> task) throws Exception {
                        capture.set((ArrayList) task.getResult());
                        return PurchaseRetryDAO.this.updateIsDirtyProperpy(CommonFrameworkImpl.getContext(), (ArrayList) capture.get(), 1, _db, CommerceDB.DATABASE_TABLE_PURCHASE_RESTORE);
                    }
                });
                final Capture capture2 = retryList;
                return onSuccessTask.onSuccess(new Continuation<Void, ArrayList<PurchaseItem>>() {
                    public ArrayList<PurchaseItem> then(Task<Void> task) throws Exception {
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
            Log.e(IgawConstant.QA_TAG, "PurchaseRetryDAO >> getRetryPurchase Error: " + e.getMessage());
            return null;
        }
    }

    /* access modifiers changed from: private */
    public Task<Void> updateIsDirtyProperpy(Context context, ArrayList<PurchaseItem> mPurchaseItem, int isDirty, CustomSQLiteDatabase db, String table) {
        if (mPurchaseItem == null) {
            return Task.forResult(null);
        }
        final int size = mPurchaseItem.size();
        final AtomicInteger count = new AtomicInteger(0);
        final ArrayList<PurchaseItem> arrayList = mPurchaseItem;
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
                int id = ((PurchaseItem) arrayList.get(index)).getKey();
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
                return db.queryAsync(CommerceDB.DATABASE_TABLE_PURCHASE_RESTORE, new String[]{"_id", "retry_count"}, "_id=" + key, null).onSuccess(new Continuation<Cursor, Integer>() {
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
            Log.e(IgawConstant.QA_TAG, "PurchaseRetryDAO >> getRetryCount >> Key: " + key + ">> Error: " + e.getMessage());
            return 0;
        }
    }

    public void updateOrInsertConversionForRetry(int key, String orderID, String productID, String productName, double price, int quantity, String currency, String category, String createAt) {
        final int i = key;
        final String str = productID;
        final String str2 = orderID;
        final String str3 = productName;
        final double d = price;
        final int i2 = quantity;
        final String str4 = currency;
        final String str5 = category;
        final String str6 = createAt;
        runWithManagedComplexTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                final CustomSQLiteDatabase _db = db;
                Task<Cursor> queryAsync = _db.queryAsync(CommerceDB.DATABASE_TABLE_PURCHASE_RESTORE, new String[]{"_id", "retry_count"}, "_id=" + i, null);
                final int i = i;
                final String str = str;
                final String str2 = str2;
                final String str3 = str3;
                final double d = d;
                final int i2 = i2;
                final String str4 = str4;
                final String str5 = str5;
                final String str6 = str6;
                return queryAsync.onSuccessTask(new Continuation<Cursor, Task<Void>>() {
                    public Task<Void> then(Task<Cursor> task) throws Exception {
                        Cursor cursor = (Cursor) task.getResult();
                        if (!cursor.moveToFirst() || cursor.getCount() == 0) {
                            cursor.close();
                            IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("PurchaseRetryDAO >> add retry purchase : key = %d, productID = %s", new Object[]{Integer.valueOf(i), str}), 2);
                            ContentValues newTaskValues = new ContentValues();
                            newTaskValues.put(CommerceDB.ORDER_ID, str2);
                            newTaskValues.put(CommerceDB.PRODUCT_ID, str);
                            newTaskValues.put(CommerceDB.PRODUCT_NAME, str3);
                            newTaskValues.put("price", Double.valueOf(d));
                            newTaskValues.put("quantity", Integer.valueOf(i2));
                            newTaskValues.put("currency", str4);
                            newTaskValues.put("category", str5);
                            newTaskValues.put(CommerceDB.CREATE_AT, str6);
                            newTaskValues.put("retry_count", Integer.valueOf(0));
                            newTaskValues.put(CommerceDB.IS_DIRTY, Integer.valueOf(0));
                            return _db.insertOrThrowAsync(CommerceDB.DATABASE_TABLE_PURCHASE_RESTORE, newTaskValues);
                        }
                        int count = cursor.getInt(1);
                        IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, String.format("PurchaseRetryDAO >> add retry purchase : key = %d, productID = %s , retry time: " + count, new Object[]{Integer.valueOf(i), str}), 2);
                        ContentValues newValue = new ContentValues();
                        newValue.put("retry_count", Integer.valueOf(cursor.getInt(1) + 1));
                        newValue.put(CommerceDB.IS_DIRTY, Integer.valueOf(0));
                        cursor.close();
                        return _db.updateAsync(CommerceDB.DATABASE_TABLE_PURCHASE_RESTORE, newValue, "_id=" + i, null).makeVoid();
                    }
                });
            }
        });
    }

    public boolean removeRetryCount(final int key) {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "PurchaseRetryDAO >> removeRetryCount key =  " + key, 2);
                return db.deleteAsync(CommerceDB.DATABASE_TABLE_PURCHASE_RESTORE, "_id=" + key, null).makeVoid();
            }
        });
        return true;
    }

    @Deprecated
    public boolean clearRetryItems() {
        runWithManagedConnection(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                IgawLogger.Logging(CommonFrameworkImpl.getContext(), IgawConstant.QA_TAG, "PurchaseRetryDAO >> Remove restore queue", 2);
                return db.deleteAsync(CommerceDB.DATABASE_TABLE_PURCHASE_RESTORE, null, null).makeVoid();
            }
        });
        return true;
    }

    public Task<Void> removePurchaseItem(final ArrayList<PurchaseItem> list, final Context context) {
        return runWithManagedTransaction(new SQLiteDatabaseCallable<Task<Void>>() {
            public Task<Void> call(CustomSQLiteDatabase db) {
                return PurchaseRetryDAO.this.removePurchaseItemList(context, list, db, CommerceDB.DATABASE_TABLE_PURCHASE_RESTORE);
            }
        });
    }

    /* access modifiers changed from: private */
    public Task<Void> removePurchaseItemList(Context context, ArrayList<PurchaseItem> list, CustomSQLiteDatabase db, String table) {
        if (list == null) {
            return Task.forResult(null);
        }
        final int size = list.size();
        final AtomicInteger count = new AtomicInteger(0);
        final ArrayList<PurchaseItem> arrayList = list;
        final Context context2 = context;
        final CustomSQLiteDatabase customSQLiteDatabase = db;
        final String str = table;
        return Task.forResult(null).continueWhile(new Callable<Boolean>() {
            public Boolean call() throws Exception {
                return count.get() < size ? Boolean.valueOf(true) : Boolean.valueOf(false);
            }
        }, new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> task) throws Exception {
                PurchaseItem mPurchaseItem = (PurchaseItem) arrayList.get(count.getAndIncrement());
                int id = mPurchaseItem.getKey();
                IgawLogger.Logging(context2, IgawConstant.QA_TAG, "PurchaseRetryDAO >> Remove restore queue >> key = " + id + " productID = " + mPurchaseItem.getProductID(), 2);
                if (id == -1) {
                    return null;
                }
                return customSQLiteDatabase.deleteAsync(str, "_id=?", new String[]{String.valueOf(id)});
            }
        });
    }
}