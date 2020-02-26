package co.habitfactory.signalfinance_embrain.comm;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences.Editor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.preference.PreferenceManager;
import androidx.core.app.NotificationCompat;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperMissedPushSms;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperPush;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperPushSms;
import co.habitfactory.signalfinance_embrain.jobservice.JGoogleAdidService;
import co.habitfactory.signalfinance_embrain.jobservice.JInitInstallTimeService;
import co.habitfactory.signalfinance_embrain.jobservice.JSignalInitService;
import co.habitfactory.signalfinance_embrain.receiver.AppslistAlarmReceive;
import co.habitfactory.signalfinance_embrain.receiver.BootingReceiver;
import com.google.firebase.analytics.FirebaseAnalytics.Event;
import java.io.File;
import java.util.ArrayList;
import java.util.Calendar;
import org.json.JSONArray;
import org.json.JSONException;

public class SignalLibPrefs implements SignalLibConsts {
    private final String TAG = SignalLibPrefs.class.getSimpleName();
    private Editor edit;
    private NewObscuredSharedPreferences prefs;

    public SignalLibPrefs(Context context) {
        this.prefs = new NewObscuredSharedPreferences(context, context.getSharedPreferences(SignalLibConsts.PREF_FILE_NAME, 0));
        this.edit = this.prefs.edit();
    }

    public void putString(String str, String str2) {
        try {
            this.edit.putString(str, str2);
            this.edit.commit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getString(String str) {
        try {
            return this.prefs.getString(str, "");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public void putInt(String str, int i) {
        try {
            this.edit.putInt(str, i);
            this.edit.commit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public int getInt(String str) {
        try {
            return this.prefs.getInt(str, -1);
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    public long getLong(String str) {
        try {
            return this.prefs.getLong(str, -1);
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    public void putLong(String str, long j) {
        try {
            this.edit.putLong(str, j);
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.edit.commit();
    }

    public int getInt(String str, int i) {
        try {
            return this.prefs.getInt(str, i);
        } catch (Exception e) {
            e.printStackTrace();
            return i;
        }
    }

    public void putBoolean(String str, boolean z) {
        try {
            this.edit.putBoolean(str, z);
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.edit.commit();
    }

    public Boolean getBoolean(String str) {
        try {
            return Boolean.valueOf(this.prefs.getBoolean(str, false));
        } catch (Exception e) {
            e.printStackTrace();
            return Boolean.valueOf(false);
        }
    }

    public Boolean getBoolean(String str, Boolean bool) {
        try {
            return Boolean.valueOf(this.prefs.getBoolean(str, bool.booleanValue()));
        } catch (Exception e) {
            e.printStackTrace();
            return bool;
        }
    }

    public static void setStringArrayPref(Context context, String str, ArrayList<String> arrayList) {
        Editor edit2 = PreferenceManager.getDefaultSharedPreferences(context).edit();
        JSONArray jSONArray = new JSONArray();
        for (int i = 0; i < arrayList.size(); i++) {
            jSONArray.put(arrayList.get(i));
        }
        if (!arrayList.isEmpty()) {
            edit2.putString(str, jSONArray.toString());
        } else {
            edit2.putString(str, null);
        }
        edit2.commit();
    }

    public static ArrayList<String> getStringArrayPref(Context context, String str) {
        String string = PreferenceManager.getDefaultSharedPreferences(context).getString(str, null);
        ArrayList<String> arrayList = new ArrayList<>();
        if (string != null) {
            try {
                JSONArray jSONArray = new JSONArray(string);
                for (int i = 0; i < jSONArray.length(); i++) {
                    arrayList.add(jSONArray.optString(i));
                }
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
        return arrayList;
    }

    private boolean checkNullData(String str) {
        return str != null && str.length() > 0;
    }

    public boolean checkCharValidation(String str) {
        if (str == null) {
            return false;
        }
        char[] charArray = str.toCharArray();
        for (char valueOf : charArray) {
            if (Character.getType(Character.valueOf(valueOf).charValue()) == 5) {
                return false;
            }
        }
        return true;
    }

    public boolean isSmsDataSyncComplete() {
        return getBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_FLAG, Boolean.valueOf(true)).booleanValue();
    }

    public void setDataSyncTerm(int i) {
        putInt(SignalLibConsts.PREF_DATA_SYNC_TERM_VALUE, i);
    }

    public int signalLogin(Context context, String str, String str2, String str3, String str4) {
        if (!checkNullData(str)) {
            return -1;
        }
        putString(SignalLibConsts.PREF_API_SERVER_URL, str);
        if (!checkCharValidation(str2)) {
            return -3;
        }
        putString(SignalLibConsts.PREF_API_USER_USERID, str2);
        if (str3.length() != 4) {
            return -4;
        }
        if (str4.length() != 1) {
            return -5;
        }
        putString(SignalLibConsts.PREF_API_USER_YEAROFBIRTH, str3);
        putString(SignalLibConsts.PREF_API_USER_GENDER, str4);
        Intent intent = new Intent(context, JGoogleAdidService.class);
        intent.putExtra("userId", str2);
        intent.putExtra("isFrom", Event.LOGIN);
        JGoogleAdidService.enqueueWork(context, intent);
        return 0;
    }

    public int createSignalId(Context context, String str, String str2, String str3) {
        if (!checkNullData(str)) {
            return -1;
        }
        putString(SignalLibConsts.PREF_API_SERVER_URL, str);
        if (str2.length() != 4) {
            return -4;
        }
        if (str3.length() != 1) {
            return -5;
        }
        putString(SignalLibConsts.PREF_API_USER_YEAROFBIRTH, str2);
        putString(SignalLibConsts.PREF_API_USER_GENDER, str3);
        Intent intent = new Intent(context, JGoogleAdidService.class);
        intent.putExtra("userId", "");
        intent.putExtra("isFrom", "create");
        JGoogleAdidService.enqueueWork(context, intent);
        return 0;
    }

    public int setInitData(Context context, String str, String str2) {
        return setInitData(context, str, str2, 2, false);
    }

    public int setInitData(Context context, String str, String str2, int i) {
        return setInitData(context, str, str2, i, true);
    }

    public int setInitData(Context context, String str, String str2, int i, boolean z) {
        String str3;
        if (str2 == null || str2.length() <= 0) {
            return -1;
        }
        putString(SignalLibConsts.PREF_IS_CARD_NOTI_OFF, "OFF");
        putString(SignalLibConsts.PREF_IS_BANK_NOTI_OFF, "OFF");
        putBoolean(SignalLibConsts.PREF_IS_QUIT_FOR_SYNC_FLAG, false);
        try {
            str3 = getString(SignalLibConsts.PREF_API_USER_USERID);
        } catch (Exception e) {
            e.printStackTrace();
            str3 = "";
        }
        if (str3 == null || str3.length() <= 0 || str3.equals(str2)) {
            putBoolean(SignalLibConsts.PREF_IS_FROM_AGREE, z);
            if (!checkNullData(str)) {
                return -2;
            }
            putString(SignalLibConsts.PREF_API_SERVER_URL, str);
            if (!checkNullData(str2)) {
                return -1;
            }
            putString(SignalLibConsts.PREF_API_USER_USERID, str2);
            setStartCollectData();
            putInt(SignalLibConsts.PREF_IS_OLD_MESSAGE_COLLECT, i);
            JSignalInitService.enqueueWork(context, new Intent(context, JSignalInitService.class));
            return 0;
        }
        SignalUtil.PRINT_LOG(this.TAG, ">>>>>> saved userId different <<<<<<");
        putBoolean(SignalLibConsts.PREF_SET_CHANGE_INSTALLTIME, true);
        SignalUtil.PRINT_LOG("clear", "===============clear start===================");
        putString(SignalLibConsts.PREF_API_USER_USERID, "");
        putString(SignalLibConsts.PREF_API_INSTALL_TIMESTAMP, "");
        setClearForSync(context);
        return -4;
    }

    public void setStopCollectData(Context context) {
        putBoolean(SignalLibConsts.PREF_STOP_COLLECT, true);
        putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_FLAG, true);
        unregisterRestartAlarm(context);
        unregisterAppsListAlarm(context);
        unregisterMissingAlarm(context);
        SignalUtil.PRINT_LOG(this.TAG, "\uc790\ub3d9\uc218\uc9d1 \uc815\uc9c0.");
    }

    public void setStartCollectData() {
        putBoolean(SignalLibConsts.PREF_STOP_COLLECT, false);
        if (getBoolean(SignalLibConsts.PREF_STOP_COLLECT).booleanValue()) {
            SignalUtil.PRINT_LOG(this.TAG, "\uc2dc\uc791\uc2e4\ud328(\uc790\ub3d9\uc218\uc9d1 \uc815\uc9c0\uc911)");
        }
    }

    public boolean isCheckDB(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("/data//data//");
        sb.append(context.getPackageName());
        sb.append("//databases//");
        sb.append(SignalLibConsts.DATABASE_NAME);
        return new File(sb.toString()).exists();
    }

    public void setCheckMissedData(Context context) {
        Intent intent = new Intent(context, JGoogleAdidService.class);
        intent.putExtra("userId", "");
        intent.putExtra("isFrom", "save");
        JGoogleAdidService.enqueueWork(context, intent);
    }

    public void setNotiOnOff(int i, String str) {
        if (i == 0) {
            putString(SignalLibConsts.PREF_IS_CARD_NOTI_OFF, str);
        } else {
            putString(SignalLibConsts.PREF_IS_BANK_NOTI_OFF, str);
        }
    }

    public String checkNotiOnOff(int i) {
        if (i == 0) {
            String string = getString(SignalLibConsts.PREF_IS_CARD_NOTI_OFF);
            if (string.length() <= 0) {
                string = "OFF";
            }
            return string;
        }
        String string2 = getString(SignalLibConsts.PREF_IS_BANK_NOTI_OFF);
        if (string2.length() <= 0) {
            string2 = "OFF";
        }
        return string2;
    }

    public void setQuitSignalData(Context context) {
        putBoolean(SignalLibConsts.PREF_IS_QUIT_FOR_SYNC_FLAG, true);
        SignalUtil.PRINT_LOG("clear", "===============clear start===================");
        putString(SignalLibConsts.PREF_API_USER_USERID, "");
        putString(SignalLibConsts.PREF_API_USER_EMAIL, "");
        putString(SignalLibConsts.PREF_API_USER_PNUMBER, "");
        putString(SignalLibConsts.PREF_API_USER_ADID, "");
        putString(SignalLibConsts.PREF_API_USER_LASTNAME, "");
        putString(SignalLibConsts.PREF_API_USER_PROFILE_URL, "");
        putString(SignalLibConsts.PREF_API_USER_DATEOFBIRTH, "");
        putString(SignalLibConsts.PREF_API_USER_SEX, "");
        putString(SignalLibConsts.PREF_API_IS_LOGIN_INFLOW, "");
        putString(SignalLibConsts.PREF_API_INSTALL_TIMESTAMP, "");
        putInt(SignalLibConsts.PREF_DELAY_COUNT, 0);
        putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC, true);
        putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_FLAG, true);
        putBoolean(SignalLibConsts.PREF_SYNC_SMS_REQUEST_DONE_FLAG, false);
        putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_EOF, false);
        putBoolean(SignalLibConsts.PREF_IS_FROM_AGREE, false);
        putBoolean(SignalLibConsts.PREF_API_CUT_OFF_CHECK, false);
        putBoolean(SignalLibConsts.PREF_API_GOT_WHITELIST_FROM_API_CHECK, false);
        putBoolean(SignalLibConsts.PREF_API_GOT_WHITEPACKAGE_FROM_API_CHECK, false);
        putInt(SignalLibConsts.PREF_SYNC_SMS_TOTAL_COUNT, 0);
        putInt(SignalLibConsts.PREF_SYNC_SMS_GET_COUNT, 0);
        putInt(SignalLibConsts.PREF_SYNC_MMS_TOTAL_COUNT, 0);
        putInt(SignalLibConsts.PREF_SYNC_MMS_GET_COUNT, 0);
        putString(SignalLibConsts.PREF_OLD_MESSAGESERVICE_RUNNING, "N");
        putInt(SignalLibConsts.PREF_SENDFAILMESSAGE_SERVICE_COUNT, 0);
        setStopCollectData(context);
        SignalUtil.PRINT_LOG("clear", "==============pref clear done===============");
        try {
            DatabaseHelperPush instance = DatabaseHelperPush.getInstance(context);
            SQLiteDatabase db = instance.getDB();
            if (db != null) {
                instance.dropTable(db, DatabaseHelperPush.TABLE_NAME);
                db.close();
            }
        } catch (SQLiteException e) {
            e.printStackTrace();
        }
        SignalUtil.PRINT_LOG("clear", "==============db clear done=================");
        unregisterRestartAlarm(context);
        unregisterAppsListAlarm(context);
        unregisterMissingAlarm(context);
        SignalUtil.PRINT_LOG("clear", "==============unregister done===============");
        SignalUtil.PRINT_LOG("clear", "==============clear complete================");
    }

    public void initInstallTime(Context context) {
        JInitInstallTimeService.enqueueWork(context, new Intent(context, JInitInstallTimeService.class));
    }

    public void setClearForSync(Context context) {
        setClearForSync(context, false);
    }

    public void setClearForSync(Context context, boolean z) {
        if (z) {
            initInstallTime(context);
        }
        putBoolean(SignalLibConsts.PREF_IS_QUIT_FOR_SYNC_FLAG, true);
        putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC, true);
        putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_FLAG, true);
        putBoolean(SignalLibConsts.PREF_SYNC_SMS_REQUEST_DONE_FLAG, false);
        putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_EOF, false);
        putBoolean(SignalLibConsts.PREF_API_CUT_OFF_CHECK, false);
        putInt(SignalLibConsts.PREF_SYNC_SMS_TOTAL_COUNT, 0);
        putInt(SignalLibConsts.PREF_SYNC_SMS_GET_COUNT, 0);
        putInt(SignalLibConsts.PREF_SYNC_MMS_TOTAL_COUNT, 0);
        putInt(SignalLibConsts.PREF_SYNC_MMS_GET_COUNT, 0);
        putString(SignalLibConsts.PREF_OLD_MESSAGESERVICE_RUNNING, "N");
        SignalUtil.PRINT_LOG("clear", "==============sync pref clear done===============");
        try {
            DatabaseHelperMissedPushSms instance = DatabaseHelperMissedPushSms.getInstance(context);
            SQLiteDatabase db = instance.getDB();
            if (db != null) {
                instance.dropTable(db, DatabaseHelperMissedPushSms.TABLE_NAME);
                db.close();
            }
        } catch (SQLiteException e) {
            e.printStackTrace();
        }
        try {
            DatabaseHelperPushSms instance2 = DatabaseHelperPushSms.getInstance(context);
            SQLiteDatabase db2 = instance2.getDB();
            if (db2 != null) {
                instance2.dropTable(db2, DatabaseHelperPushSms.TABLE_NAME);
                db2.close();
            }
        } catch (SQLiteException e2) {
            e2.printStackTrace();
        }
        try {
            DatabaseHelperPush instance3 = DatabaseHelperPush.getInstance(context);
            SQLiteDatabase db3 = instance3.getDB();
            if (db3 != null) {
                instance3.dropTable(db3, DatabaseHelperPush.TABLE_NAME);
                db3.close();
            }
        } catch (SQLiteException e3) {
            e3.printStackTrace();
        }
        SignalUtil.PRINT_LOG("clear", "==============sync db clear done=================");
        SignalUtil.PRINT_LOG("clear", "==============sync clear complete================");
        putBoolean(SignalLibConsts.PREF_IS_QUIT_FOR_SYNC_FLAG, false);
        setStartCollectData();
    }

    public void unregisterRestartAlarm(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        Intent intent = new Intent(context, BootingReceiver.class);
        intent.setAction(SignalLibConsts.ACTION_RESTART_PERSISTENTSERVICE);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.BOOT_ALARM_CODE, intent, 0);
        if (broadcast != null) {
            alarmManager.cancel(broadcast);
            broadcast.cancel();
        }
    }

    public void unregisterAppsListAlarm(Context context) {
        Intent intent = new Intent(context, AppslistAlarmReceive.class);
        intent.setAction(SignalLibConsts.INTENT_APPSLIST_ALARM_ACTION);
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.APPSLIST_ALARM_CODE, intent, 0);
        if (broadcast != null) {
            if (alarmManager != null) {
                alarmManager.cancel(broadcast);
            }
            broadcast.cancel();
        }
    }

    public void unregisterMissingAlarm(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.MISSINGDATA_CHECK_ALARM_CODE, new Intent(SignalLibConsts.INTENT_MISSINGDATA_CHECK_ALARM_ACTION), 0);
        if (broadcast != null) {
            if (alarmManager != null) {
                alarmManager.cancel(broadcast);
            }
            broadcast.cancel();
        }
    }

    public String getSavedUserId() {
        try {
            return getString(SignalLibConsts.PREF_API_USER_USERID);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /* access modifiers changed from: protected */
    public void failResponseToDbTask() {
        String str;
        Calendar instance = Calendar.getInstance();
        instance.get(6);
        try {
            str = String.valueOf(instance.getTimeInMillis());
        } catch (Exception e) {
            e.printStackTrace();
            str = null;
        }
        if (str != null) {
            putString(SignalLibConsts.PREF_API_SYNC_CURRENT_TIMESTAMP, str);
        }
    }
}