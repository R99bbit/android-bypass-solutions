package co.habitfactory.signalfinance_embrain.jobservice;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.database.SQLException;
import android.os.SystemClock;
import android.telephony.TelephonyManager;
import androidx.core.app.NotificationCompat;
import androidx.core.app.SafeJobIntentService;
import co.habitfactory.signalfinance_embrain.asynctask.AppListDataCheckAlarmToDbTask;
import co.habitfactory.signalfinance_embrain.callback.AppListAlarmCallback;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperFinanceInfo;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperMissedNotification;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperMissedPushSms;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperPush;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperPushSms;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperSmsReceiveNumber;
import co.habitfactory.signalfinance_embrain.receiver.AppslistAlarmReceive;
import co.habitfactory.signalfinance_embrain.receiver.BootingReceiver;
import java.util.Calendar;

public class JSignalInitService extends SafeJobIntentService implements SignalLibConsts {
    static final int JOB_ID = 1016;
    private final String TAG = JSignalInitService.class.getSimpleName();
    private Context mContext;
    private SignalLibPrefs mPrefs;

    public void onCreate() {
        super.onCreate();
        this.mPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JSignalInitService.class, 1016, intent);
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        int i = this.mPrefs.getInt(SignalLibConsts.PREF_DATA_SYNC_TERM_VALUE, 180);
        boolean z = false;
        if (this.mPrefs.getBoolean(SignalLibConsts.PREF_IS_FROM_AGREE, Boolean.valueOf(false)).booleanValue()) {
            SignalUtil.PRINT_LOG(this.TAG, "======== \uc2e0\uaddc & \ub85c\uadf8\uc778 ========");
            localTimeInit(i);
            createTable();
            setNetworkOperatorName();
            Intent intent2 = new Intent(this.mContext, JGetCurrentTimeService.class);
            intent2.putExtra("termValue", i);
            JGetCurrentTimeService.enqueueWork(this.mContext, intent2);
            try {
                z = SignalUtil.isNetworkConnect(this.mContext).booleanValue();
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (z) {
                Intent intent3 = new Intent(this.mContext, JSmsReceiveNumberService.class);
                intent3.putExtra("from", "init");
                JSmsReceiveNumberService.enqueueWork(this.mContext, intent3);
            } else {
                try {
                    SignalUtil.getAssetData(1, this.mContext);
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }
        } else {
            SignalUtil.PRINT_LOG(this.TAG, "======== \uc808\uc804\ubaa8\ub4dc ========");
            this.mPrefs.setCheckMissedData(this.mContext);
        }
        unregisterRestartAlarm(this.mContext);
        registerRestartAlarm(this.mContext);
        checkAppListDataAlarmOn();
    }

    private void setNetworkOperatorName() {
        String str;
        String str2;
        try {
            str = SignalUtil.NULL_TO_STRING(this.mPrefs.getString(SignalLibConsts.PREF_API_USER_NETWORK_OPERATOR_NAME));
        } catch (Exception e) {
            e.printStackTrace();
            str = null;
        }
        if (str == null || str.length() <= 0) {
            try {
                str2 = ((TelephonyManager) getSystemService("phone")).getNetworkOperatorName();
            } catch (Exception e2) {
                e2.printStackTrace();
                str2 = "";
            }
            this.mPrefs.putString(SignalLibConsts.PREF_API_USER_NETWORK_OPERATOR_NAME, str2);
        }
    }

    /* access modifiers changed from: 0000 */
    public void createTable() {
        DatabaseHelperSmsReceiveNumber instance = DatabaseHelperSmsReceiveNumber.getInstance(getApplicationContext());
        try {
            instance.onCreateWithTable(instance.getDB(), DatabaseHelperSmsReceiveNumber.TABLE_NAME);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        DatabaseHelperMissedPushSms instance2 = DatabaseHelperMissedPushSms.getInstance(getApplicationContext());
        try {
            instance2.onCreateWithTable(instance2.getDB(), DatabaseHelperMissedPushSms.TABLE_NAME);
        } catch (SQLException e2) {
            e2.printStackTrace();
        }
        DatabaseHelperPushSms instance3 = DatabaseHelperPushSms.getInstance(getApplicationContext());
        try {
            instance3.onCreateWithTable(instance3.getDB(), DatabaseHelperPushSms.TABLE_NAME);
        } catch (SQLException e3) {
            e3.printStackTrace();
        }
        DatabaseHelperPush instance4 = DatabaseHelperPush.getInstance(getApplicationContext());
        try {
            instance4.onCreateWithTable(instance4.getDB(), DatabaseHelperPush.TABLE_NAME);
        } catch (SQLException e4) {
            e4.printStackTrace();
        }
        DatabaseHelperMissedNotification instance5 = DatabaseHelperMissedNotification.getInstance(getApplicationContext());
        try {
            instance5.onCreateWithTable(instance5.getDB(), DatabaseHelperMissedNotification.TABLE_NAME);
        } catch (SQLException e5) {
            e5.printStackTrace();
        }
        DatabaseHelperFinanceInfo instance6 = DatabaseHelperFinanceInfo.getInstance(getApplicationContext());
        try {
            instance6.onCreateWithTable(instance6.getDB(), DatabaseHelperFinanceInfo.TABLE_NAME);
        } catch (SQLException e6) {
            e6.printStackTrace();
        }
    }

    public void unregisterMissingDataCheckAlarm(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.MISSINGDATA_CHECK_ALARM_CODE, new Intent(SignalLibConsts.INTENT_MISSINGDATA_CHECK_ALARM_ACTION), 0);
        if (broadcast != null) {
            alarmManager.cancel(broadcast);
            broadcast.cancel();
        }
    }

    /* access modifiers changed from: 0000 */
    public void checkAppListDataAlarmOn() {
        boolean z;
        try {
            z = SignalUtil.isAppListDataAlarmOn(this.mContext);
        } catch (Exception e) {
            e.printStackTrace();
            z = false;
        }
        if (!z) {
            unregisterAppslistAlarm(this.mContext);
            new AppListDataCheckAlarmToDbTask(this.mContext, new AppListAlarmCallback() {
                public void getAlarmCallback(boolean z) {
                }
            }).execute(new Void[0]);
        }
    }

    public void unregisterAppslistAlarm(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        Intent intent = new Intent(context, AppslistAlarmReceive.class);
        intent.setAction(SignalLibConsts.INTENT_APPSLIST_ALARM_ACTION);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.APPSLIST_ALARM_CODE, intent, 0);
        if (broadcast != null) {
            if (alarmManager != null) {
                alarmManager.cancel(broadcast);
            }
            broadcast.cancel();
        }
    }

    private void registerRestartAlarm(Context context) {
        Intent intent = new Intent(context, BootingReceiver.class);
        intent.setAction(SignalLibConsts.ACTION_RESTART_PERSISTENTSERVICE);
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        alarmManager.setInexactRepeating(2, SystemClock.elapsedRealtime() + 120000, 120000, PendingIntent.getBroadcast(context, SignalLibConsts.BOOT_ALARM_CODE, intent, 268435456));
    }

    private void unregisterRestartAlarm(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        Intent intent = new Intent(context, BootingReceiver.class);
        intent.setAction(SignalLibConsts.ACTION_RESTART_PERSISTENTSERVICE);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.BOOT_ALARM_CODE, intent, 0);
        if (broadcast != null) {
            alarmManager.cancel(broadcast);
            broadcast.cancel();
        }
    }

    /* access modifiers changed from: protected */
    public void localTimeInit(int i) {
        String str;
        Calendar instance = Calendar.getInstance();
        instance.get(6);
        String str2 = null;
        try {
            str = String.valueOf(instance.getTimeInMillis());
        } catch (Exception e) {
            e.printStackTrace();
            str = null;
        }
        instance.add(6, -i);
        try {
            str2 = String.valueOf(instance.getTimeInMillis());
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        if (str != null && str2 != null) {
            this.mPrefs.putString(SignalLibConsts.PREF_API_SYNC_CURRENT_TIMESTAMP, str);
            this.mPrefs.putString(SignalLibConsts.PREF_API_SYNC_BEFORE_TIMESTAMP, str2);
        }
    }
}