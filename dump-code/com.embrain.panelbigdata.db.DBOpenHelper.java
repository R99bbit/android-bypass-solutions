package com.embrain.panelbigdata.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import android.database.sqlite.SQLiteOpenHelper;
import com.embrain.panelbigdata.Vo.location.LocationGpsRequest;
import com.embrain.panelbigdata.Vo.location.LocationState;
import com.embrain.panelbigdata.Vo.push.BigdataSessionRequest;
import com.embrain.panelbigdata.Vo.usage.UsageDao;
import com.embrain.panelbigdata.Vo.usage.UsageInsertRequest;
import com.embrain.panelbigdata.Vo.usage.UsageState;
import com.embrain.panelbigdata.common.BigDataCommonVo;
import com.embrain.panelbigdata.db.BigDataQuery.TBAppList;
import com.embrain.panelbigdata.db.BigDataQuery.TBDeviceState;
import com.embrain.panelbigdata.db.BigDataQuery.TBGpsState;
import com.embrain.panelbigdata.db.BigDataQuery.TBUsage;
import com.embrain.panelbigdata.usage.ApplicationDao;
import com.embrain.panelbigdata.usage.UsageInsertRequestExt;
import com.embrain.panelbigdata.utils.PrefUtils;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class DBOpenHelper {
    private static final String DATABASE_NAME = "PanelBigData.db";
    private static final int DATABASE_VERSION = 1;
    public static SQLiteDatabase mDB;
    private static DBOpenHelper mInstance;
    private Context mCtx;
    private DatabaseHelper mDBHelper;

    private class DatabaseHelper extends SQLiteOpenHelper {
        public void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
        }

        public DatabaseHelper(Context context, String str, CursorFactory cursorFactory, int i) {
            super(context, str, cursorFactory, i);
        }

        public void onCreate(SQLiteDatabase sQLiteDatabase) {
            sQLiteDatabase.execSQL(TBUsage._CREATE);
            sQLiteDatabase.execSQL(TBAppList._CREATE);
            sQLiteDatabase.execSQL(TBGpsState._CREATE);
            sQLiteDatabase.execSQL(TBDeviceState._CREATE);
        }
    }

    public static DBOpenHelper getInstance(Context context) {
        if (mInstance == null) {
            mInstance = new DBOpenHelper(context);
        }
        return mInstance;
    }

    private DBOpenHelper(Context context) {
        this.mCtx = context;
        open();
    }

    private void open() throws SQLException {
        DatabaseHelper databaseHelper = new DatabaseHelper(this.mCtx, DATABASE_NAME, null, 1);
        this.mDBHelper = databaseHelper;
        mDB = this.mDBHelper.getWritableDatabase();
    }

    public void close() {
        mDB.close();
        mInstance = null;
    }

    private Context getContext() {
        return this.mCtx;
    }

    public void insertGpsState(LocationGpsRequest locationGpsRequest) {
        ContentValues contentValues = new ContentValues();
        contentValues.put(TBGpsState.EXEC_TIME, Long.valueOf(locationGpsRequest.execute_time));
        contentValues.put(TBGpsState.LAT, Double.valueOf(locationGpsRequest.lat));
        contentValues.put(TBGpsState.LNG, Double.valueOf(locationGpsRequest.lng));
        contentValues.put("gps_state", Integer.valueOf(locationGpsRequest.gps_state ? 1 : 0));
        mDB.insert("gps_state", null, contentValues);
    }

    public void insertDeviceState(BigdataSessionRequest bigdataSessionRequest) {
        ContentValues contentValues = new ContentValues();
        contentValues.put(TBDeviceState.PUSH_RESP_DATE, Long.valueOf(getTime()));
        contentValues.put(TBDeviceState.USAGE_PERMISSION, Boolean.valueOf(bigdataSessionRequest.usageState.permission));
        contentValues.put(TBDeviceState.USAGE_ALIVE_JOB, Boolean.valueOf(bigdataSessionRequest.usageState.aliveUsageJob));
        contentValues.put(TBDeviceState.USAGE_AGREE, Boolean.valueOf(bigdataSessionRequest.usageState.userAgree));
        contentValues.put(TBDeviceState.LOC_PERMISSION, Boolean.valueOf(bigdataSessionRequest.locationState.permission));
        contentValues.put(TBDeviceState.LOC_ALIVE_JOB, Boolean.valueOf(bigdataSessionRequest.locationState.aliveLocationJob));
        contentValues.put(TBDeviceState.LOC_AGREE, Boolean.valueOf(bigdataSessionRequest.locationState.userAgree));
        contentValues.put(TBDeviceState.LOC_GPS_STATE, Boolean.valueOf(bigdataSessionRequest.locationState.gpsState));
        contentValues.put(TBDeviceState.LOC_LOPLAT_STATUS, Integer.valueOf(bigdataSessionRequest.locationState.loplatState));
        contentValues.put(TBDeviceState.MESSAGE_ID, bigdataSessionRequest.messageId);
        mDB.insert(TBDeviceState._TABLE_NAME, null, contentValues);
    }

    public void insertAppUsage(UsageInsertRequest usageInsertRequest) {
        long time = getTime();
        for (UsageDao next : usageInsertRequest.getDailyUsageList()) {
            ContentValues contentValues = new ContentValues();
            contentValues.put("package_name", next.package_name);
            contentValues.put("app_name", next.app_name);
            contentValues.put("exec_time", Long.valueOf(time));
            contentValues.put(TBUsage.TOTAL_USED_TIME, Long.valueOf(next.total_used_time));
            contentValues.put(TBUsage.FIRST_TIME_STAMP, Long.valueOf(next.first_time_stamp));
            contentValues.put(TBUsage.LAST_TIME_STAMP, Long.valueOf(next.last_time_stamp));
            contentValues.put(TBUsage.LAST_USED_TIME_STAMP, Long.valueOf(next.last_used_time_stamp));
            mDB.insert(TBUsage._TABLE_NAME, null, contentValues);
        }
        for (ApplicationDao next2 : usageInsertRequest.getAppList()) {
            ContentValues contentValues2 = new ContentValues();
            contentValues2.put("package_name", next2.package_name);
            contentValues2.put("app_name", next2.app_name);
            contentValues2.put("exec_time", Long.valueOf(time));
            contentValues2.put(TBAppList.LAST_UPDATE_TIME, Long.valueOf(next2.last_update_time));
            contentValues2.put(TBAppList.FIRST_INSTALL_TIME, Long.valueOf(next2.first_install_time));
            contentValues2.put(TBAppList.MARKET_PACKAGE, next2.market_package);
            contentValues2.put(TBAppList.APP_VER, next2.app_ver);
            mDB.insert(TBAppList._TABLE_NAME, null, contentValues2);
        }
    }

    public List<BigdataSessionRequest> getAllDeviceState() {
        Cursor query = mDB.query(TBDeviceState._TABLE_NAME, TBDeviceState.COLUMNS, null, null, null, null, null, null);
        ArrayList arrayList = new ArrayList();
        BigDataCommonVo bigDataCommonVo = new BigDataCommonVo(getContext(), PrefUtils.getPanelId(getContext()), PrefUtils.getGoogleADID(getContext()));
        while (query.moveToNext()) {
            BigdataSessionRequest bigdataSessionRequest = new BigdataSessionRequest();
            bigdataSessionRequest.setDeviceInfo(bigDataCommonVo);
            bigdataSessionRequest.setUsageState(new UsageState(query.getInt(query.getColumnIndex(TBDeviceState.USAGE_PERMISSION)), query.getInt(query.getColumnIndex(TBDeviceState.USAGE_ALIVE_JOB)), query.getInt(query.getColumnIndex(TBDeviceState.USAGE_AGREE))));
            LocationState locationState = new LocationState(query.getInt(query.getColumnIndex(TBDeviceState.LOC_PERMISSION)), query.getInt(query.getColumnIndex(TBDeviceState.LOC_ALIVE_JOB)), query.getInt(query.getColumnIndex(TBDeviceState.LOC_AGREE)), query.getInt(query.getColumnIndex(TBDeviceState.LOC_GPS_STATE)), query.getInt(query.getColumnIndex(TBDeviceState.LOC_LOPLAT_STATUS)));
            bigdataSessionRequest.setLocationState(locationState);
            bigdataSessionRequest.setMessageId(query.getString(query.getColumnIndex(TBDeviceState.MESSAGE_ID)));
            bigdataSessionRequest.setExecTime(query.getLong(query.getColumnIndex(TBDeviceState.PUSH_RESP_DATE)));
            arrayList.add(bigdataSessionRequest);
        }
        query.close();
        return arrayList;
    }

    public List<LocationGpsRequest> getAllGpsState() {
        Cursor query = mDB.query("gps_state", TBGpsState.COLUMNS, null, null, null, null, null, null);
        ArrayList arrayList = new ArrayList();
        while (query.moveToNext()) {
            LocationGpsRequest locationGpsRequest = new LocationGpsRequest(getContext());
            boolean z = true;
            if (query.getInt(query.getColumnIndex("gps_state")) != 1) {
                z = false;
            }
            locationGpsRequest.gps_state = z;
            locationGpsRequest.lat = query.getDouble(query.getColumnIndex(TBGpsState.LAT));
            locationGpsRequest.lng = query.getDouble(query.getColumnIndex(TBGpsState.LNG));
            locationGpsRequest.setExecTime(query.getLong(query.getColumnIndex(TBGpsState.EXEC_TIME)));
            arrayList.add(locationGpsRequest);
        }
        query.close();
        return arrayList;
    }

    public UsageInsertRequest getUsageItem() {
        Context context = getContext();
        UsageInsertRequestExt usageInsertRequestExt = new UsageInsertRequestExt(PrefUtils.getPanelId(context), PrefUtils.getGoogleADID(context), PrefUtils.getFcmToken(context));
        Cursor query = mDB.query(TBUsage._TABLE_NAME, TBUsage.COLUMNS, null, null, null, null, null, null);
        ArrayList arrayList = new ArrayList();
        while (query.moveToNext()) {
            UsageDao usageDao = new UsageDao(query.getString(query.getColumnIndex("package_name")), query.getLong(query.getColumnIndex(TBUsage.TOTAL_USED_TIME)), query.getLong(query.getColumnIndex(TBUsage.FIRST_TIME_STAMP)), query.getLong(query.getColumnIndex(TBUsage.LAST_TIME_STAMP)), query.getLong(query.getColumnIndex(TBUsage.LAST_USED_TIME_STAMP)), query.getString(query.getColumnIndex("app_name")));
            usageDao.setExecTime(query.getLong(query.getColumnIndex("exec_time")));
            arrayList.add(usageDao);
        }
        usageInsertRequestExt.setDailyUsageList(arrayList);
        Cursor query2 = mDB.query(TBAppList._TABLE_NAME, TBAppList.COLUMNS, null, null, null, null, null, null);
        ArrayList arrayList2 = new ArrayList();
        while (query2.moveToNext()) {
            ApplicationDao applicationDao = new ApplicationDao(query2.getString(query2.getColumnIndex("app_name")), query2.getString(query2.getColumnIndex("package_name")), query2.getString(query2.getColumnIndex(TBAppList.MARKET_PACKAGE)), query2.getLong(query2.getColumnIndex(TBAppList.FIRST_INSTALL_TIME)), query2.getLong(query2.getColumnIndex(TBAppList.LAST_UPDATE_TIME)), query2.getString(query2.getColumnIndex(TBAppList.APP_VER)));
            applicationDao.setExecTime(query2.getLong(query2.getColumnIndex("exec_time")));
            arrayList2.add(applicationDao);
        }
        usageInsertRequestExt.setAppList(arrayList2);
        query.close();
        query2.close();
        return usageInsertRequestExt;
    }

    private long getTime() {
        return new Date().getTime();
    }

    public void clearTableDeviceState() {
        mDB.delete(TBDeviceState._TABLE_NAME, null, null);
    }

    public void clearTableGPS() {
        mDB.delete("gps_state", null, null);
    }

    public void clearTableUsage() {
        mDB.delete(TBUsage._TABLE_NAME, null, null);
    }

    public void clearTableAppList() {
        mDB.delete(TBAppList._TABLE_NAME, null, null);
    }
}