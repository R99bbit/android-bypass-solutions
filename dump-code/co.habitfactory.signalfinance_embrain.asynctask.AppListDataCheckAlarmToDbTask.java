package co.habitfactory.signalfinance_embrain.asynctask;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import androidx.core.app.NotificationCompat;
import co.habitfactory.signalfinance_embrain.callback.AppListAlarmCallback;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.receiver.AppslistAlarmReceive;
import java.util.Calendar;
import java.util.Random;

public class AppListDataCheckAlarmToDbTask extends AsyncTask<Void, Integer, Boolean> implements SignalLibConsts {
    private Context mContext;
    private AppListAlarmCallback myCallback;

    public AppListDataCheckAlarmToDbTask(Context context, AppListAlarmCallback appListAlarmCallback) {
        this.myCallback = appListAlarmCallback;
        this.mContext = context;
    }

    private boolean setAppslistAlarm(int i, int i2) {
        try {
            AlarmManager alarmManager = (AlarmManager) this.mContext.getSystemService(NotificationCompat.CATEGORY_ALARM);
            Intent intent = new Intent(this.mContext, AppslistAlarmReceive.class);
            intent.setAction(SignalLibConsts.INTENT_APPSLIST_ALARM_ACTION);
            PendingIntent broadcast = PendingIntent.getBroadcast(this.mContext, SignalLibConsts.APPSLIST_ALARM_CODE, intent, 268435456);
            Calendar instance = Calendar.getInstance();
            instance.set(11, i);
            instance.set(12, i2);
            instance.set(13, 0);
            instance.set(14, 0);
            long timeInMillis = instance.getTimeInMillis();
            if (System.currentTimeMillis() > timeInMillis) {
                timeInMillis += 86400000;
            }
            long j = timeInMillis;
            if (alarmManager != null) {
                alarmManager.setInexactRepeating(0, j, 86400000, broadcast);
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /* access modifiers changed from: protected */
    public void onPreExecute() {
        super.onPreExecute();
    }

    /* access modifiers changed from: protected */
    public Boolean doInBackground(Void... voidArr) {
        int i;
        int i2;
        try {
            i = new Random().nextInt(6);
            if (i == 0 || i == 1) {
                i = 2;
            }
        } catch (Exception e) {
            e.printStackTrace();
            i = 0;
        }
        try {
            i2 = new Random().nextInt(50);
        } catch (Exception e2) {
            e2.printStackTrace();
            i2 = 0;
        }
        this.myCallback.getAlarmCallback(setAppslistAlarm(i, i2));
        return Boolean.valueOf(false);
    }

    /* access modifiers changed from: protected */
    public void onPostExecute(Boolean bool) {
        super.onPostExecute(bool);
    }
}