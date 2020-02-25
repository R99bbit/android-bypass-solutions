package co.habitfactory.signalfinance_embrain.receiver;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import androidx.core.app.NotificationCompat;
import co.habitfactory.signalfinance_embrain.asynctask.AppListDataCheckAlarmToDbTask;
import co.habitfactory.signalfinance_embrain.callback.AppListAlarmCallback;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import java.util.ArrayList;
import java.util.Iterator;

public class BootingReceiver extends BroadcastReceiver implements SignalLibConsts {
    private Context mContext;
    private SignalLibPrefs mPrefs;

    public void onReceive(Context context, Intent intent) {
        this.mContext = context;
        this.mPrefs = new SignalLibPrefs(context);
        boolean equals = intent.getAction().equals("android.intent.action.BOOT_COMPLETED");
        Boolean valueOf = Boolean.valueOf(true);
        if (equals) {
            unregisterRestartAlarm(context);
            if (this.mPrefs.getBoolean(SignalLibConsts.PREF_STOP_COLLECT, valueOf).booleanValue()) {
                unregisterAppslistAlarm(this.mContext);
                unregisterMissingDataCheckAlarm(this.mContext);
            } else {
                registerRestartAlarm(context);
                checkAppListDataAlarmOn();
            }
        }
        if (intent.getAction().equals(SignalLibConsts.ACTION_RESTART_PERSISTENTSERVICE) && this.mPrefs.getBoolean(SignalLibConsts.PREF_STOP_COLLECT, valueOf).booleanValue()) {
            unregisterRestartAlarm(context);
            unregisterAppslistAlarm(this.mContext);
            unregisterMissingDataCheckAlarm(this.mContext);
        }
    }

    public void unregisterMissingDataCheckAlarm(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.MISSINGDATA_CHECK_ALARM_CODE, new Intent(SignalLibConsts.INTENT_MISSINGDATA_CHECK_ALARM_ACTION), 0);
        if (broadcast != null) {
            if (alarmManager != null) {
                alarmManager.cancel(broadcast);
            }
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
        Intent intent = new Intent(context, AppslistAlarmReceive.class);
        intent.setAction(SignalLibConsts.INTENT_APPSLIST_ALARM_ACTION);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.APPSLIST_ALARM_CODE, intent, 0);
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        if (alarmManager != null) {
            alarmManager.cancel(broadcast);
        }
    }

    private ArrayList<Class<?>> isMyServiceRunning(ArrayList<Class<?>> arrayList, Context context) throws Exception {
        ArrayList<Class<?>> arrayList2 = new ArrayList<>(arrayList);
        ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
        if (activityManager != null) {
            for (RunningServiceInfo next : activityManager.getRunningServices(Integer.MAX_VALUE)) {
                Iterator<Class<?>> it = arrayList2.iterator();
                while (it.hasNext()) {
                    Class next2 = it.next();
                    if (next2.getName().equals(next.service.getClassName())) {
                        try {
                            arrayList2.remove(next2);
                            break;
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
                if (arrayList2.size() == 0) {
                    break;
                }
            }
        }
        return arrayList2;
    }

    private void registerRestartAlarm(Context context) {
        Intent intent = new Intent(context, BootingReceiver.class);
        intent.setAction(SignalLibConsts.ACTION_RESTART_PERSISTENTSERVICE);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.BOOT_ALARM_CODE, intent, 268435456);
        long elapsedRealtime = SystemClock.elapsedRealtime() + 120000;
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        if (alarmManager != null) {
            alarmManager.setInexactRepeating(2, elapsedRealtime, 120000, broadcast);
        }
    }

    private void unregisterRestartAlarm(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(NotificationCompat.CATEGORY_ALARM);
        Intent intent = new Intent(context, BootingReceiver.class);
        intent.setAction(SignalLibConsts.ACTION_RESTART_PERSISTENTSERVICE);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, SignalLibConsts.BOOT_ALARM_CODE, intent, 0);
        if (broadcast != null) {
            if (alarmManager != null) {
                alarmManager.cancel(broadcast);
            }
            broadcast.cancel();
        }
    }
}