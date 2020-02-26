package co.habitfactory.signalfinance_embrain.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.dataset.PushDataSet;

public class DatabaseHelperPushSms extends SQLiteOpenHelper implements SignalLibConsts {
    private static final int DATABASE_VERSION = 1;
    private static final String KEY_ADDRESS = "ADDRESS";
    private static final String KEY_IS_POPUP = "IS_POPUP";
    private static final String KEY_LATITUDE = "LATITUDE";
    private static final String KEY_LONGITUDE = "LONGITUDE";
    private static final String KEY_NOTI_SUBTEXT = "NOTI_SUBTEXT";
    private static final String KEY_NOTI_TEXT = "NOTI_TEXT";
    private static final String KEY_NOTI_TITLE = "NOTI_TITLE";
    private static final String KEY_PACKAGE_NAME = "PACKAGE_NAME";
    private static final String KEY_PROVIDER = "PROVIDER";
    private static final String KEY_PUSH_DB_ID = "PUSH_DB_ID";
    private static final String KEY_PUSH_ID = "PUSH_ID";
    private static final String KEY_PUSH_INDEX = "PUSH_INDEX";
    private static final String KEY_REGISTRATION_TIMESTAMP = "REGISTRATION_TIMESTAMP";
    private static final String KEY_REMOTE_IP = "REMOTE_IP";
    private static final String KEY_SEND_TO_SERVER = "SEND_TO_SERVER";
    private static final String KEY_TIMESTAMP_MILLIS = "TIMESTAMP_MILLIS";
    private static final String KEY_USER_AGENT = "USER_AGENT";
    private static final String KEY_USER_SIM_NUMBER = "USER_SIM_NUMBER";
    public static final String TABLE_NAME = "tablepushsms";
    private static DatabaseHelperPushSms sInstance;
    private final String TAG = "DatabaseHelperPush";

    public void onCreate(SQLiteDatabase sQLiteDatabase) {
    }

    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    public static synchronized DatabaseHelperPushSms getInstance(Context context) {
        DatabaseHelperPushSms databaseHelperPushSms;
        synchronized (DatabaseHelperPushSms.class) {
            try {
                if (sInstance == null) {
                    sInstance = new DatabaseHelperPushSms(context.getApplicationContext());
                }
                databaseHelperPushSms = sInstance;
            }
        }
        return databaseHelperPushSms;
    }

    public DatabaseHelperPushSms(Context context) {
        super(context, SignalLibConsts.DATABASE_NAME, null, 1);
    }

    public void onCreateWithTable(SQLiteDatabase sQLiteDatabase, String str) throws SQLException {
        if (sQLiteDatabase != null && str != null && str.length() > 0) {
            StringBuilder sb = new StringBuilder();
            sb.append("CREATE TABLE IF NOT EXISTS ");
            sb.append(str);
            sb.append(" (");
            sb.append(KEY_PUSH_INDEX);
            sb.append(" INTEGER PRIMARY KEY AUTOINCREMENT,");
            sb.append(KEY_PUSH_DB_ID);
            sb.append(" TEXT,");
            sb.append(KEY_PUSH_ID);
            sb.append(" TEXT,");
            sb.append(KEY_USER_SIM_NUMBER);
            sb.append(" TEXT,");
            sb.append(KEY_PACKAGE_NAME);
            sb.append(" TEXT,");
            sb.append(KEY_NOTI_TITLE);
            sb.append(" TEXT,");
            sb.append(KEY_NOTI_TEXT);
            sb.append(" TEXT,");
            sb.append(KEY_NOTI_SUBTEXT);
            sb.append(" TEXT,");
            sb.append(KEY_TIMESTAMP_MILLIS);
            sb.append(" TEXT,");
            sb.append(KEY_USER_AGENT);
            sb.append(" TEXT,");
            sb.append(KEY_REMOTE_IP);
            sb.append(" TEXT,");
            sb.append(KEY_LATITUDE);
            sb.append(" TEXT,");
            sb.append(KEY_LONGITUDE);
            sb.append(" TEXT,");
            sb.append(KEY_ADDRESS);
            sb.append(" TEXT,");
            sb.append(KEY_PROVIDER);
            sb.append(" TEXT,");
            sb.append(KEY_REGISTRATION_TIMESTAMP);
            sb.append(" TEXT,");
            sb.append(KEY_SEND_TO_SERVER);
            sb.append(" TEXT,");
            sb.append(KEY_IS_POPUP);
            sb.append(" TEXT)");
            sQLiteDatabase.execSQL(sb.toString());
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

    /* JADX WARNING: Code restructure failed: missing block: B:22:0x004b, code lost:
        if (r1.isClosed() == false) goto L_0x005c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:29:0x005a, code lost:
        if (r1.isClosed() == false) goto L_0x005c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x005c, code lost:
        r1.close();
     */
    public Boolean getRowExistPushMessage(String str) {
        Cursor cursor = null;
        try {
            SQLiteDatabase readableDatabase = getReadableDatabase();
            if (readableDatabase.isOpen()) {
                boolean z = true;
                cursor = readableDatabase.query(TABLE_NAME, new String[]{KEY_PUSH_INDEX}, "NOTI_SUBTEXT=?", new String[]{String.valueOf(str)}, null, null, null, null);
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

    public long addRow(PushDataSet pushDataSet) throws Exception {
        SQLiteDatabase writableDatabase = getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put(KEY_PUSH_DB_ID, pushDataSet.getPushDbId());
        contentValues.put(KEY_PUSH_ID, pushDataSet.getPushId());
        contentValues.put(KEY_USER_SIM_NUMBER, pushDataSet.getUserSimNumber());
        contentValues.put(KEY_PACKAGE_NAME, pushDataSet.getPackageNm());
        contentValues.put(KEY_NOTI_TITLE, pushDataSet.getNotiTitle());
        contentValues.put(KEY_NOTI_TEXT, pushDataSet.getNotiText());
        contentValues.put(KEY_NOTI_SUBTEXT, pushDataSet.getNotiSubText());
        contentValues.put(KEY_TIMESTAMP_MILLIS, pushDataSet.getTimestampMillis());
        contentValues.put(KEY_USER_AGENT, pushDataSet.getUserAgent());
        contentValues.put(KEY_REMOTE_IP, pushDataSet.getRemoteIp());
        contentValues.put(KEY_LATITUDE, pushDataSet.getLatitude());
        contentValues.put(KEY_LONGITUDE, pushDataSet.getLongitude());
        contentValues.put(KEY_ADDRESS, pushDataSet.getAddress());
        contentValues.put(KEY_PROVIDER, pushDataSet.getProvider());
        contentValues.put(KEY_REGISTRATION_TIMESTAMP, pushDataSet.getRegistrationTimestamp());
        contentValues.put(KEY_SEND_TO_SERVER, pushDataSet.getSendToServer());
        contentValues.put(KEY_IS_POPUP, pushDataSet.getIsPopup());
        writableDatabase.beginTransaction();
        long j = 0;
        try {
            j = writableDatabase.insert(TABLE_NAME, null, contentValues);
            writableDatabase.setTransactionSuccessful();
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Throwable th) {
            writableDatabase.endTransaction();
            throw th;
        }
        writableDatabase.endTransaction();
        return j;
    }

    public void addRow(PushDataSet pushDataSet, String str) throws Exception {
        SQLiteDatabase writableDatabase = getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put(KEY_PUSH_DB_ID, pushDataSet.getPushDbId());
        contentValues.put(KEY_PUSH_ID, pushDataSet.getPushId());
        contentValues.put(KEY_USER_SIM_NUMBER, pushDataSet.getUserSimNumber());
        contentValues.put(KEY_PACKAGE_NAME, pushDataSet.getPackageNm());
        contentValues.put(KEY_NOTI_TITLE, pushDataSet.getNotiTitle());
        contentValues.put(KEY_NOTI_TEXT, pushDataSet.getNotiText());
        contentValues.put(KEY_NOTI_SUBTEXT, pushDataSet.getNotiSubText());
        contentValues.put(KEY_TIMESTAMP_MILLIS, pushDataSet.getTimestampMillis());
        contentValues.put(KEY_USER_AGENT, pushDataSet.getUserAgent());
        contentValues.put(KEY_REMOTE_IP, pushDataSet.getRemoteIp());
        contentValues.put(KEY_LATITUDE, pushDataSet.getLatitude());
        contentValues.put(KEY_LONGITUDE, pushDataSet.getLongitude());
        contentValues.put(KEY_ADDRESS, pushDataSet.getAddress());
        contentValues.put(KEY_PROVIDER, pushDataSet.getProvider());
        contentValues.put(KEY_REGISTRATION_TIMESTAMP, pushDataSet.getRegistrationTimestamp());
        contentValues.put(KEY_SEND_TO_SERVER, pushDataSet.getSendToServer());
        contentValues.put(KEY_IS_POPUP, pushDataSet.getIsPopup());
        writableDatabase.beginTransaction();
        try {
            writableDatabase.insert(str, null, contentValues);
            writableDatabase.setTransactionSuccessful();
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Throwable th) {
            writableDatabase.endTransaction();
            throw th;
        }
        writableDatabase.endTransaction();
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
                cursor = readableDatabase.query(TABLE_NAME, new String[]{KEY_PUSH_INDEX}, "PUSH_DB_ID=?", new String[]{String.valueOf(str)}, null, null, null, null);
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

    public void updateRow(PushDataSet pushDataSet) {
        SQLiteDatabase writableDatabase = getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put(KEY_SEND_TO_SERVER, pushDataSet.getSendToServer());
        writableDatabase.beginTransaction();
        try {
            writableDatabase.update(TABLE_NAME, contentValues, "PUSH_INDEX = ? ", new String[]{pushDataSet.getIndex()});
            writableDatabase.setTransactionSuccessful();
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Throwable th) {
            writableDatabase.endTransaction();
            throw th;
        }
        writableDatabase.endTransaction();
    }

    public SQLiteDatabase getDB() throws SQLiteException {
        return getWritableDatabase();
    }
}