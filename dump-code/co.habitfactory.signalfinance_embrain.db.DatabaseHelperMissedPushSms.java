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
import com.embrain.panelpower.UserInfoManager;
import java.util.ArrayList;
import java.util.Iterator;

public class DatabaseHelperMissedPushSms extends SQLiteOpenHelper implements SignalLibConsts {
    private static final int DATABASE_VERSION = 1;
    private static final String KEY_ADDRESS = "ADDRESS";
    private static final String KEY_IS_POPUP = "IS_POPUP";
    private static final String KEY_LATITUDE = "LATITUDE";
    private static final String KEY_LONGITUDE = "LONGITUDE";
    private static final String KEY_NOTI_BIGTEXT = "NOTI_BIGTEXT";
    private static final String KEY_NOTI_SUBTEXT = "NOTI_SUBTEXT";
    private static final String KEY_NOTI_TEXT = "NOTI_TEXT";
    private static final String KEY_NOTI_TITLE = "NOTI_TITLE";
    private static final String KEY_PACKAGE_NAME = "PACKAGE_NAME";
    private static final String KEY_PROVIDER = "PROVIDER";
    private static final String KEY_PUSH_ID = "PUSH_ID";
    private static final String KEY_PUSH_INDEX = "PUSH_INDEX";
    private static final String KEY_REGISTRATION_TIMESTAMP = "REGISTRATION_TIMESTAMP";
    private static final String KEY_REMOTE_IP = "REMOTE_IP";
    private static final String KEY_SEND_TO_SERVER = "SEND_TO_SERVER";
    private static final String KEY_TIMESTAMP_MILLIS = "TIMESTAMP_MILLIS";
    private static final String KEY_USER_AGENT = "USER_AGENT";
    private static final String KEY_USER_SIM_NUMBER = "USER_SIM_NUMBER";
    public static final String TABLE_NAME = "table_missed_push_sms";
    private static DatabaseHelperMissedPushSms sInstance;
    private final String TAG = "DatabaseHelperMissedNotification";

    public void onCreate(SQLiteDatabase sQLiteDatabase) {
    }

    public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    public static synchronized DatabaseHelperMissedPushSms getInstance(Context context) {
        DatabaseHelperMissedPushSms databaseHelperMissedPushSms;
        synchronized (DatabaseHelperMissedPushSms.class) {
            try {
                if (sInstance == null) {
                    sInstance = new DatabaseHelperMissedPushSms(context.getApplicationContext());
                }
                databaseHelperMissedPushSms = sInstance;
            }
        }
        return databaseHelperMissedPushSms;
    }

    public DatabaseHelperMissedPushSms(Context context) {
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
            sb.append(KEY_NOTI_BIGTEXT);
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
            sb.append(" TEXT ,");
            sb.append(KEY_IS_POPUP);
            sb.append(" TEXT )");
            sQLiteDatabase.execSQL(sb.toString());
        }
    }

    public void deleteTable() throws Exception {
        getWritableDatabase().execSQL("DELETE FROM table_missed_push_sms");
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

    public long addRow(PushDataSet pushDataSet) throws Exception {
        SQLiteDatabase writableDatabase = getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put(KEY_PUSH_ID, pushDataSet.getPushId());
        contentValues.put(KEY_USER_SIM_NUMBER, pushDataSet.getUserSimNumber());
        contentValues.put(KEY_PACKAGE_NAME, pushDataSet.getPackageNm());
        contentValues.put(KEY_NOTI_TITLE, pushDataSet.getNotiTitle());
        contentValues.put(KEY_NOTI_TEXT, pushDataSet.getNotiText());
        contentValues.put(KEY_NOTI_SUBTEXT, pushDataSet.getNotiSubText());
        contentValues.put(KEY_NOTI_BIGTEXT, pushDataSet.getNotificationBigText());
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

    public void updateRows(ArrayList<PushDataSet> arrayList) throws Exception {
        SQLiteDatabase writableDatabase = getWritableDatabase();
        writableDatabase.beginTransaction();
        try {
            Iterator<PushDataSet> it = arrayList.iterator();
            while (it.hasNext()) {
                ContentValues contentValues = new ContentValues();
                contentValues.put(KEY_SEND_TO_SERVER, UserInfoManager.AGREE_Y);
                writableDatabase.update(TABLE_NAME, contentValues, "PUSH_INDEX = ? ", new String[]{it.next().getIndex()});
            }
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
                cursor = readableDatabase.query(TABLE_NAME, new String[]{KEY_PUSH_INDEX}, "NOTI_TEXT=?", new String[]{String.valueOf(str)}, null, null, null, null);
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

    public SQLiteDatabase getDB() throws SQLiteException {
        return getWritableDatabase();
    }

    public ArrayList<PushDataSet> getRowsRecentData(String str, String str2) throws Exception {
        String str3;
        String str4;
        String str5;
        String str6;
        String str7;
        String str8;
        String str9;
        String str10;
        String str11;
        String str12;
        String str13;
        String str14;
        String str15;
        String str16;
        String str17;
        String str18;
        String str19;
        ArrayList<PushDataSet> arrayList = new ArrayList<>();
        Cursor query = getReadableDatabase().query(TABLE_NAME, new String[]{KEY_PUSH_INDEX, KEY_PUSH_ID, KEY_USER_SIM_NUMBER, KEY_PACKAGE_NAME, KEY_NOTI_TITLE, KEY_NOTI_TEXT, KEY_NOTI_SUBTEXT, KEY_NOTI_BIGTEXT, KEY_TIMESTAMP_MILLIS, KEY_USER_AGENT, KEY_REMOTE_IP, KEY_LATITUDE, KEY_LONGITUDE, KEY_ADDRESS, KEY_PROVIDER, KEY_REGISTRATION_TIMESTAMP, KEY_SEND_TO_SERVER, KEY_IS_POPUP}, "SEND_TO_SERVER = ? AND TIMESTAMP_MILLIS BETWEEN ? AND ? ", new String[]{"N", str, str2}, null, null, "TIMESTAMP_MILLIS DESC");
        while (query.moveToNext()) {
            String string = query.isNull(0) ? "" : query.getString(0);
            if (query.isNull(1)) {
                str3 = "";
            } else {
                str3 = query.getString(1);
            }
            if (query.isNull(2)) {
                str4 = "";
            } else {
                str4 = query.getString(2);
            }
            if (query.isNull(3)) {
                str5 = "";
            } else {
                str5 = query.getString(3);
            }
            if (query.isNull(4)) {
                str6 = "";
            } else {
                str6 = query.getString(4);
            }
            if (query.isNull(5)) {
                str7 = "";
            } else {
                str7 = query.getString(5);
            }
            if (query.isNull(6)) {
                str8 = "";
            } else {
                str8 = query.getString(6);
            }
            if (query.isNull(7)) {
                str9 = "";
            } else {
                str9 = query.getString(7);
            }
            if (query.isNull(8)) {
                str10 = "";
            } else {
                str10 = query.getString(8);
            }
            if (query.isNull(9)) {
                str11 = "";
            } else {
                str11 = query.getString(9);
            }
            if (query.isNull(10)) {
                str12 = "";
            } else {
                str12 = query.getString(10);
            }
            if (query.isNull(11)) {
                str13 = "";
            } else {
                str13 = query.getString(11);
            }
            if (query.isNull(12)) {
                str14 = "";
            } else {
                str14 = query.getString(12);
            }
            if (query.isNull(13)) {
                str15 = "";
            } else {
                str15 = query.getString(13);
            }
            if (query.isNull(14)) {
                str16 = "";
            } else {
                str16 = query.getString(14);
            }
            if (query.isNull(15)) {
                str17 = "";
            } else {
                str17 = query.getString(15);
            }
            if (query.isNull(16)) {
                str18 = "";
            } else {
                str18 = query.getString(16);
            }
            if (query.isNull(17)) {
                str19 = "";
            } else {
                str19 = query.getString(17);
            }
            PushDataSet pushDataSet = new PushDataSet(string, str3, str4, str5, str6, str7, str8, str9, str10, str11, str12, str13, str14, str15, str16, str17, str18, str19, SignalLibConsts.g_DataChannel);
            arrayList.add(pushDataSet);
        }
        return arrayList;
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

    /* JADX WARNING: Code restructure failed: missing block: B:22:0x0059, code lost:
        if (r1.isClosed() == false) goto L_0x006a;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:29:0x0068, code lost:
        if (r1.isClosed() == false) goto L_0x006a;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x006a, code lost:
        r1.close();
     */
    public Boolean checkBodyRowExist(String str, String str2, String str3) {
        Cursor cursor = null;
        try {
            SQLiteDatabase readableDatabase = getReadableDatabase();
            if (readableDatabase.isOpen()) {
                String valueOf = String.valueOf(str2);
                boolean z = true;
                cursor = readableDatabase.query(TABLE_NAME, new String[]{KEY_PUSH_INDEX}, "NOTI_TITLE = ? AND NOTI_TEXT = ? AND PACKAGE_NAME = ?", new String[]{String.valueOf(str), valueOf, String.valueOf(str3)}, null, null, null, null);
                if (cursor != null) {
                    try {
                        if (cursor.getCount() <= 0) {
                            z = false;
                        }
                        Boolean valueOf2 = Boolean.valueOf(z);
                        if (cursor != null && !cursor.isClosed()) {
                            cursor.close();
                        }
                        return valueOf2;
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