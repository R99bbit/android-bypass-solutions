package co.habitfactory.signalfinance_embrain.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.dataset.SmsReceiveNumberSet;
import java.util.ArrayList;
import java.util.Iterator;

public class DatabaseHelperSmsReceiveNumber extends SQLiteOpenHelper implements SignalLibConsts {
    private static final int DATABASE_VERSION = 1;
    private static final String KEY_RECEIVE_NUMBER = "RECEIVE_NUMBER";
    private static final String KEY_RECEIVE_NUMBER_INDEX = "RECEIVE_NUMBER_INDEX";
    private static final String KEY_RECEIVE_NUMBER_NAME = "RECEIVE_NUMBER_NAME";
    private static final String KEY_RECEIVE_NUMBER_TYPE = "RECEIVE_NUMBER_TYPE";
    public static final String TABLE_NAME = "tb_sms_receive_number";
    private static DatabaseHelperSmsReceiveNumber sInstance;

    public void onCreate(SQLiteDatabase sQLiteDatabase) {
    }

    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    public static synchronized DatabaseHelperSmsReceiveNumber getInstance(Context context) {
        DatabaseHelperSmsReceiveNumber databaseHelperSmsReceiveNumber;
        synchronized (DatabaseHelperSmsReceiveNumber.class) {
            try {
                if (sInstance == null) {
                    sInstance = new DatabaseHelperSmsReceiveNumber(context.getApplicationContext());
                }
                databaseHelperSmsReceiveNumber = sInstance;
            }
        }
        return databaseHelperSmsReceiveNumber;
    }

    public DatabaseHelperSmsReceiveNumber(Context context) {
        super(context, SignalLibConsts.DATABASE_NAME, null, 1);
    }

    public void onCreateWithTable(SQLiteDatabase sQLiteDatabase, String str) throws SQLException {
        if (sQLiteDatabase != null && str != null && str.length() > 0) {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append("CREATE TABLE IF NOT EXISTS ");
                sb.append(str);
                sb.append(" (");
                sb.append(KEY_RECEIVE_NUMBER_INDEX);
                sb.append(" INTEGER PRIMARY KEY AUTOINCREMENT,");
                sb.append(KEY_RECEIVE_NUMBER);
                sb.append(" TEXT,");
                sb.append(KEY_RECEIVE_NUMBER_NAME);
                sb.append(" TEXT,");
                sb.append(KEY_RECEIVE_NUMBER_TYPE);
                sb.append(" TEXT)");
                sQLiteDatabase.execSQL(sb.toString());
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    public void addRowList(ArrayList<SmsReceiveNumberSet> arrayList) {
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
                Iterator<SmsReceiveNumberSet> it = arrayList.iterator();
                while (it.hasNext()) {
                    SmsReceiveNumberSet next = it.next();
                    contentValues.clear();
                    contentValues.put(KEY_RECEIVE_NUMBER, next.getReceiveNumber());
                    contentValues.put(KEY_RECEIVE_NUMBER_NAME, next.getReceiveNumberName());
                    contentValues.put(KEY_RECEIVE_NUMBER_TYPE, next.getReceiveNumberType());
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

    public void addRowOnlyNewList(ArrayList<SmsReceiveNumberSet> arrayList) {
        SQLiteDatabase sQLiteDatabase;
        try {
            sQLiteDatabase = getWritableDatabase();
        } catch (SQLiteException e) {
            e.printStackTrace();
            sQLiteDatabase = null;
        }
        onCreateWithTable(sQLiteDatabase, TABLE_NAME);
        try {
            sQLiteDatabase.beginTransaction();
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        try {
            ContentValues contentValues = new ContentValues();
            if (arrayList != null) {
                Iterator<SmsReceiveNumberSet> it = arrayList.iterator();
                while (it.hasNext()) {
                    SmsReceiveNumberSet next = it.next();
                    contentValues.clear();
                    contentValues.put(KEY_RECEIVE_NUMBER, next.getReceiveNumber());
                    contentValues.put(KEY_RECEIVE_NUMBER_NAME, next.getReceiveNumberName());
                    contentValues.put(KEY_RECEIVE_NUMBER_TYPE, next.getReceiveNumberType());
                    sQLiteDatabase.insert(TABLE_NAME, null, contentValues);
                }
                if (sQLiteDatabase != null) {
                    sQLiteDatabase.setTransactionSuccessful();
                }
            }
            if (sQLiteDatabase == null) {
                return;
            }
        } catch (Exception e3) {
            e3.printStackTrace();
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

    public String[] getNumber(String str) throws SQLException {
        ArrayList arrayList = new ArrayList();
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM tb_sms_receive_number WHERE RECEIVE_NUMBER_TYPE = '");
        sb.append(str);
        sb.append("'");
        try {
            Cursor rawQuery = getWritableDatabase().rawQuery(sb.toString(), null);
            if (rawQuery == null) {
                return null;
            }
            if (rawQuery.moveToFirst()) {
                do {
                    arrayList.add(rawQuery.getString(1));
                } while (rawQuery.moveToNext());
            }
            return (String[]) arrayList.toArray(new String[arrayList.size()]);
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

    public SQLiteDatabase getDB() throws SQLiteException {
        return getWritableDatabase();
    }

    /* JADX WARNING: Code restructure failed: missing block: B:22:0x004b, code lost:
        if (r1.isClosed() == false) goto L_0x005c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:29:0x005a, code lost:
        if (r1.isClosed() == false) goto L_0x005c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x005c, code lost:
        r1.close();
     */
    public Boolean getRowExist(String str) {
        Cursor cursor = null;
        try {
            SQLiteDatabase readableDatabase = getReadableDatabase();
            if (readableDatabase.isOpen()) {
                boolean z = true;
                cursor = readableDatabase.query(TABLE_NAME, new String[]{KEY_RECEIVE_NUMBER_INDEX}, "RECEIVE_NUMBER=?", new String[]{String.valueOf(str)}, null, null, null, null);
                if (cursor != null) {
                    try {
                        if (cursor.getCount() <= 0) {
                            z = false;
                        }
                        Boolean valueOf = Boolean.valueOf(z);
                        if (cursor != null && !cursor.isClosed()) {
                            cursor.close();
                        }
                        return valueOf;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
            if (cursor != null) {
            }
        } catch (SQLiteException e2) {
            e2.printStackTrace();
            if (cursor != null) {
            }
        } catch (Throwable th) {
            if (cursor != null && !cursor.isClosed()) {
                cursor.close();
            }
            throw th;
        }
        return Boolean.valueOf(false);
    }
}