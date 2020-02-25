package co.habitfactory.signalfinance_embrain.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.retroapi.request.user.UserAppData;
import java.util.ArrayList;
import java.util.Iterator;

public class DatabaseHelperMyAppInfo extends SQLiteOpenHelper implements SignalLibConsts {
    private static final int DATABASE_VERSION = 1;
    private static final String KEY_MYAPP_APP_NAME = "MYAPP_NAME";
    private static final String KEY_MYAPP_INDEX = "MYAPP_INDEX";
    private static final String KEY_MYAPP_INSTALLED = "MYAPP_INSTALLED";
    private static final String KEY_MYAPP_LASTMODIFIED = "MYAPP_LASTMODIFIED";
    private static final String KEY_MYAPP_PACKAGE_NAME = "MYAPP_PACKAGE_NAME";
    private static final String KEY_MYAPP_REQ_VERSION = "MYAPP_REQ_VERSION";
    private static final String KEY_MYAPP_VERSION = "MYAPP_VERSION";
    public static final String TABLE_NAME = "table_myapp_info";
    private static DatabaseHelperMyAppInfo sInstance;
    private final String TAG = DatabaseHelperMyAppInfo.class.getSimpleName();

    public void onCreate(SQLiteDatabase sQLiteDatabase) {
    }

    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    public static synchronized DatabaseHelperMyAppInfo getInstance(Context context) {
        DatabaseHelperMyAppInfo databaseHelperMyAppInfo;
        synchronized (DatabaseHelperMyAppInfo.class) {
            if (sInstance == null) {
                sInstance = new DatabaseHelperMyAppInfo(context.getApplicationContext());
            }
            databaseHelperMyAppInfo = sInstance;
        }
        return databaseHelperMyAppInfo;
    }

    public DatabaseHelperMyAppInfo(Context context) {
        super(context, SignalLibConsts.DATABASE_NAME, null, 1);
    }

    public void onCreateWithTable(SQLiteDatabase sQLiteDatabase, String str) throws SQLException {
        if (sQLiteDatabase != null && str != null && str.length() > 0) {
            StringBuilder sb = new StringBuilder();
            sb.append("CREATE TABLE IF NOT EXISTS ");
            sb.append(str);
            sb.append(" (");
            sb.append(KEY_MYAPP_INDEX);
            sb.append(" INTEGER PRIMARY KEY AUTOINCREMENT,");
            sb.append(KEY_MYAPP_APP_NAME);
            sb.append(" TEXT,");
            sb.append(KEY_MYAPP_PACKAGE_NAME);
            sb.append(" TEXT,");
            sb.append(KEY_MYAPP_VERSION);
            sb.append(" TEXT,");
            sb.append(KEY_MYAPP_REQ_VERSION);
            sb.append(" TEXT,");
            sb.append(KEY_MYAPP_INSTALLED);
            sb.append(" TEXT,");
            sb.append(KEY_MYAPP_LASTMODIFIED);
            sb.append(" TEXT)");
            sQLiteDatabase.execSQL(sb.toString());
        }
    }

    public void addRowList(ArrayList<UserAppData> arrayList) {
        SQLiteDatabase sQLiteDatabase;
        try {
            sQLiteDatabase = getWritableDatabase();
        } catch (SQLiteException e) {
            e.printStackTrace();
            sQLiteDatabase = null;
        }
        try {
            dropTable(sQLiteDatabase, TABLE_NAME);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        onCreateWithTable(sQLiteDatabase, TABLE_NAME);
        try {
            sQLiteDatabase.beginTransaction();
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        try {
            ContentValues contentValues = new ContentValues();
            if (arrayList != null) {
                Iterator<UserAppData> it = arrayList.iterator();
                while (it.hasNext()) {
                    UserAppData next = it.next();
                    contentValues.clear();
                    contentValues.put(KEY_MYAPP_APP_NAME, next.getApkName());
                    contentValues.put(KEY_MYAPP_PACKAGE_NAME, next.getPackageName());
                    contentValues.put(KEY_MYAPP_VERSION, next.getVersion());
                    contentValues.put(KEY_MYAPP_REQ_VERSION, next.getReqVersion());
                    contentValues.put(KEY_MYAPP_INSTALLED, next.getInstalled());
                    contentValues.put(KEY_MYAPP_LASTMODIFIED, next.getLastModified());
                    sQLiteDatabase.insert(TABLE_NAME, null, contentValues);
                }
                try {
                    sQLiteDatabase.setTransactionSuccessful();
                } catch (Exception e4) {
                    e4.printStackTrace();
                }
            }
            if (sQLiteDatabase == null) {
                return;
            }
        } catch (Exception e5) {
            e5.printStackTrace();
            if (sQLiteDatabase == null) {
                return;
            }
        } catch (Throwable th) {
            if (sQLiteDatabase != null) {
                sQLiteDatabase.endTransaction();
            }
            throw th;
        }
        sQLiteDatabase.endTransaction();
    }

    public SQLiteDatabase getDB() throws SQLiteException {
        return getWritableDatabase();
    }

    public ArrayList<UserAppData> getAppDataFromDb() throws SQLException {
        ArrayList<UserAppData> arrayList = new ArrayList<>();
        try {
            Cursor rawQuery = getWritableDatabase().rawQuery("SELECT * FROM table_myapp_info", null);
            if (rawQuery == null) {
                return null;
            }
            if (rawQuery.moveToFirst()) {
                do {
                    UserAppData userAppData = new UserAppData(rawQuery.getString(1), rawQuery.getString(2), rawQuery.getString(3), rawQuery.getString(4), rawQuery.getString(5), rawQuery.getString(6));
                    arrayList.add(userAppData);
                } while (rawQuery.moveToNext());
            }
            return arrayList;
        } catch (Exception e) {
            try {
                e.printStackTrace();
                return null;
            } catch (Exception e2) {
                e2.printStackTrace();
                return null;
            }
        }
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
}