package co.habitfactory.signalfinance_embrain.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.dataset.FinanceInfoDataSet;
import java.util.concurrent.atomic.AtomicInteger;

public class DatabaseHelperFinanceInfo extends SQLiteOpenHelper implements SignalLibConsts {
    private static final int DATABASE_VERSION = 1;
    private static final String KEY_FINANCE_INDEX = "FINANCE_INDEX";
    private static final String KEY_FINANCE_PACKAGE_NAME = "FINANCE_PACKAGE_NAME";
    public static final String TABLE_NAME = "table_finance_info";
    private static DatabaseHelperFinanceInfo sInstance;
    private final String TAG = DatabaseHelperFinanceInfo.class.getSimpleName();
    private SQLiteDatabase mDatabase;
    private AtomicInteger mOpenCounter = new AtomicInteger();

    public void onCreate(SQLiteDatabase sQLiteDatabase) {
    }

    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    public static synchronized DatabaseHelperFinanceInfo getInstance(Context context) {
        DatabaseHelperFinanceInfo databaseHelperFinanceInfo;
        synchronized (DatabaseHelperFinanceInfo.class) {
            try {
                if (sInstance == null) {
                    sInstance = new DatabaseHelperFinanceInfo(context.getApplicationContext());
                }
                databaseHelperFinanceInfo = sInstance;
            }
        }
        return databaseHelperFinanceInfo;
    }

    public DatabaseHelperFinanceInfo(Context context) {
        super(context, SignalLibConsts.DATABASE_NAME, null, 1);
    }

    public void onCreateWithTable(SQLiteDatabase sQLiteDatabase, String str) throws SQLException {
        if (sQLiteDatabase != null && str != null && str.length() > 0) {
            StringBuilder sb = new StringBuilder();
            sb.append("CREATE TABLE IF NOT EXISTS ");
            sb.append(str);
            sb.append(" (");
            sb.append(KEY_FINANCE_INDEX);
            sb.append(" INTEGER PRIMARY KEY AUTOINCREMENT,");
            sb.append(KEY_FINANCE_PACKAGE_NAME);
            sb.append(" TEXT)");
            sQLiteDatabase.execSQL(sb.toString());
        }
    }

    public void addRow(FinanceInfoDataSet financeInfoDataSet) throws Exception {
        if (!getRowExist(financeInfoDataSet.getFinancePackageName().toUpperCase()).booleanValue()) {
            SQLiteDatabase writableDatabase = getWritableDatabase();
            ContentValues contentValues = new ContentValues();
            contentValues.put(KEY_FINANCE_PACKAGE_NAME, financeInfoDataSet.getFinancePackageName().toUpperCase());
            writableDatabase.beginTransaction();
            try {
                writableDatabase.insert(TABLE_NAME, null, contentValues);
                writableDatabase.setTransactionSuccessful();
            } catch (Exception e) {
                e.printStackTrace();
            } catch (Throwable th) {
                writableDatabase.endTransaction();
                throw th;
            }
            writableDatabase.endTransaction();
        }
    }

    public void updateRow(String str, String str2) {
        SQLiteDatabase writableDatabase = getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put(KEY_FINANCE_PACKAGE_NAME, str2);
        writableDatabase.beginTransaction();
        try {
            writableDatabase.update(TABLE_NAME, contentValues, "FINANCE_PACKAGE_NAME = ? ", new String[]{str});
            writableDatabase.setTransactionSuccessful();
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Throwable th) {
            writableDatabase.endTransaction();
            throw th;
        }
        writableDatabase.endTransaction();
    }

    public void deleteRow(FinanceInfoDataSet financeInfoDataSet) {
        SQLiteDatabase writableDatabase = getWritableDatabase();
        writableDatabase.beginTransaction();
        try {
            writableDatabase.delete(TABLE_NAME, "FINANCE_PACKAGE_NAME = ? ", new String[]{financeInfoDataSet.getFinancePackageName()});
            writableDatabase.setTransactionSuccessful();
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Throwable th) {
            writableDatabase.endTransaction();
            throw th;
        }
        writableDatabase.endTransaction();
    }

    public Boolean getRowExist(String str) {
        Cursor cursor = null;
        try {
            SQLiteDatabase readableDatabase = getReadableDatabase();
            if (readableDatabase.isOpen()) {
                boolean z = true;
                SQLiteDatabase sQLiteDatabase = readableDatabase;
                cursor = sQLiteDatabase.query(TABLE_NAME, new String[]{KEY_FINANCE_INDEX}, "FINANCE_PACKAGE_NAME=?", new String[]{String.valueOf(str)}, null, null, null, null);
                if (cursor != null) {
                    try {
                        if (readableDatabase.isOpen()) {
                            if (cursor.getCount() <= 0) {
                                z = false;
                            }
                            Boolean valueOf = Boolean.valueOf(z);
                            if (cursor != null && !cursor.isClosed()) {
                                try {
                                    closeDatabase();
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                            return valueOf;
                        }
                    } catch (Exception e2) {
                        e2.printStackTrace();
                    }
                }
            }
            if (cursor != null && !cursor.isClosed()) {
                try {
                    closeDatabase();
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
            }
        } catch (SQLiteException e4) {
            e4.printStackTrace();
            if (cursor != null && !cursor.isClosed()) {
                closeDatabase();
            }
        } catch (Throwable th) {
            if (cursor != null && !cursor.isClosed()) {
                try {
                    closeDatabase();
                } catch (Exception e5) {
                    e5.printStackTrace();
                }
            }
            throw th;
        }
        return Boolean.valueOf(false);
    }

    public SQLiteDatabase getDB() throws SQLiteException {
        SQLiteDatabase writableDatabase = getWritableDatabase();
        this.mDatabase = writableDatabase;
        return writableDatabase;
    }

    /* JADX WARNING: type inference failed for: r0v1, types: [java.lang.String[], android.database.Cursor] */
    /* JADX WARNING: Multi-variable type inference failed. Error: jadx.core.utils.exceptions.JadxRuntimeException: No candidate types for var: r0v1, types: [java.lang.String[], android.database.Cursor]
      assigns: [?[int, float, boolean, short, byte, char, OBJECT, ARRAY]]
      uses: [?[int, boolean, OBJECT, ARRAY, byte, short, char], android.database.Cursor, java.lang.String[]]
      mth insns count: 39
    	at jadx.core.dex.visitors.typeinference.TypeSearch.fillTypeCandidates(TypeSearch.java:237)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.typeinference.TypeSearch.run(TypeSearch.java:53)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.runMultiVariableSearch(TypeInferenceVisitor.java:104)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:97)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:27)
    	at jadx.core.dex.visitors.DepthTraversal.lambda$visit$1(DepthTraversal.java:14)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:14)
    	at jadx.core.ProcessClass.process(ProcessClass.java:30)
    	at jadx.core.ProcessClass.lambda$processDependencies$0(ProcessClass.java:49)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.ProcessClass.processDependencies(ProcessClass.java:49)
    	at jadx.core.ProcessClass.process(ProcessClass.java:35)
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
     */
    /* JADX WARNING: Unknown variable types count: 1 */
    public boolean validationPackageName(String str) {
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM table_finance_info WHERE FINANCE_PACKAGE_NAME = '");
        sb.append(str);
        sb.append("';");
        String sb2 = sb.toString();
        ? r0 = 0;
        try {
            Cursor rawQuery = getReadableDatabase().rawQuery(sb2, r0);
            if (rawQuery.getCount() > 0) {
                if (rawQuery != null && !rawQuery.isClosed()) {
                    try {
                        closeDatabase();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                return true;
            }
            if (rawQuery != null && !rawQuery.isClosed()) {
                try {
                    closeDatabase();
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }
            return false;
        } catch (Exception e3) {
            e3.printStackTrace();
            if (r0 != 0 && !r0.isClosed()) {
                closeDatabase();
            }
        } catch (Throwable th) {
            if (r0 != 0 && !r0.isClosed()) {
                try {
                    closeDatabase();
                } catch (Exception e4) {
                    e4.printStackTrace();
                }
            }
            throw th;
        }
    }

    public boolean checkHasPackageNameData() {
        long queryNumEntries = DatabaseUtils.queryNumEntries(getReadableDatabase(), TABLE_NAME);
        try {
            closeDatabase();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return queryNumEntries > 0;
    }

    public boolean dropTable(SQLiteDatabase sQLiteDatabase, String str) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("DROP TABLE IF EXISTS ");
            sb.append(str);
            sQLiteDatabase.execSQL(sb.toString());
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public synchronized void closeDatabase() throws Exception {
        if (this.mOpenCounter.decrementAndGet() == 0 && this.mDatabase != null) {
            this.mDatabase.close();
        }
    }
}