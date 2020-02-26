package co.habitfactory.signalfinance_embrain.jobservice;

import android.content.Context;
import android.content.Intent;
import android.os.Build.VERSION;
import android.provider.Settings.Secure;
import androidx.core.app.SafeJobIntentService;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import co.habitfactory.signalfinance_embrain.comm.ResultCode;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.retroapi.APIHelper;
import co.habitfactory.signalfinance_embrain.retroapi.RestfulAdapter;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptServerTime;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptServerTime;
import java.util.Calendar;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JGetSaveModeSmsService extends SafeJobIntentService implements SignalLibConsts {
    private static final String COUNT_BEFOREDATE = "15";
    private static final int ICOUNT_BEFOREDATE = -15;
    static final int JOB_ID = 1008;
    private final String TAG = JGetSaveModeSmsService.class.getSimpleName();
    private String mBeforeTime;
    private Context mContext;
    private String mCurrentTime;
    private SignalLibPrefs mPrefs;

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JGetSaveModeSmsService.class, 1008, intent);
    }

    public void onCreate() {
        super.onCreate();
        this.mPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        String str;
        if (this.mPrefs.getBoolean(SignalLibConsts.PREF_STOP_COLLECT, Boolean.valueOf(true)).booleanValue()) {
            SignalUtil.PRINT_LOG(this.TAG, "\uc218\uc9d1\uc815\uc9c0 : \ubb38\uc790 \ub370\uc774\ud130 \uc804\uc1a1 \uc548\ud568.");
            return;
        }
        try {
            str = SignalUtil.getUserId(this);
        } catch (Exception e) {
            e.printStackTrace();
            str = "";
        }
        if (str.length() <= 0) {
            SignalUtil.PRINT_LOG(this.TAG, " : userId\uc5c6\uc74c");
            stopSelf();
            return;
        }
        String string = this.mPrefs.getString(SignalLibConsts.PREF_API_CURRENT_TIMESTAMP);
        String string2 = this.mPrefs.getString(SignalLibConsts.PREF_API_BEFORE_TIMESTAMP);
        if (string.length() <= 0 || string2.length() <= 0) {
            try {
                requestRetrofit("15");
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        } else {
            String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(this.mPrefs.getString(SignalLibConsts.PREF_API_INSTALL_TIMESTAMP));
            this.mCurrentTime = string;
            this.mBeforeTime = string2;
            try {
                if (this.mCurrentTime.length() > 0 && this.mBeforeTime.length() > 0) {
                    if (NULL_TO_STRING.length() > 0 && Long.valueOf(NULL_TO_STRING).longValue() > Long.valueOf(this.mBeforeTime).longValue()) {
                        this.mBeforeTime = NULL_TO_STRING;
                    }
                    Intent intent2 = new Intent(getApplicationContext(), JGetSaveModePushSmsService.class);
                    intent2.putExtra("currentTime", this.mCurrentTime);
                    intent2.putExtra("beforeTime", this.mBeforeTime);
                    JGetSaveModePushSmsService.enqueueWork(getApplicationContext(), intent2);
                    if (VERSION.SDK_INT >= 18) {
                        boolean hasNotificationAccess = hasNotificationAccess();
                        StringBuilder sb = new StringBuilder();
                        sb.append(hasNotificationAccess);
                        sb.append("");
                        SignalUtil.PRINT_LOG("\ud478\uc2dc\uc54c\ub9bcON : ", sb.toString());
                        if (hasNotificationAccess) {
                            Intent intent3 = new Intent(this.mContext, JGetSaveModePushService.class);
                            intent3.putExtra("currentTime", this.mCurrentTime);
                            intent3.putExtra("beforeTime", this.mBeforeTime);
                            JGetSaveModePushService.enqueueWork(this.mContext, intent3);
                        }
                    }
                }
            } catch (NumberFormatException e3) {
                e3.printStackTrace();
            }
        }
    }

    private void requestRetrofit(String str) throws Exception {
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this).requestServerDateTime(new IptServerTime(SignalUtil.getUserId(this.mContext), str)), 1, new Callback<OptServerTime>() {
            public void onResponse(Call<OptServerTime> call, Response<OptServerTime> response) {
                if (response.code() == 200) {
                    OptServerTime optServerTime = (OptServerTime) response.body();
                    if (optServerTime != null) {
                        try {
                            JGetSaveModeSmsService.this.parseResult(optServerTime);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        JGetSaveModeSmsService.this.failResponseToDbTask();
                    }
                } else {
                    JGetSaveModeSmsService.this.failResponseToDbTask();
                }
            }

            public void onFailure(Call<OptServerTime> call, Throwable th) {
                JGetSaveModeSmsService.this.failResponseToDbTask();
            }
        });
    }

    private boolean hasNotificationAccess() {
        boolean z = false;
        try {
            String string = Secure.getString(getContentResolver(), "enabled_notification_listeners");
            String packageName = getPackageName();
            if (string != null && string.contains(packageName)) {
                z = true;
            }
            return z;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public void parseResult(OptServerTime optServerTime) throws Exception {
        String resultcode = optServerTime.getResultcode();
        if ("00".equals(resultcode)) {
            String str = optServerTime.getbMillis();
            String str2 = optServerTime.getcMillis();
            try {
                str2 = String.format("%-13s", new Object[]{str2}).replace(' ', '0');
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                str = String.format("%-13s", new Object[]{str}).replace(' ', '0');
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            this.mPrefs.putString(SignalLibConsts.PREF_API_CURRENT_TIMESTAMP, str2);
            this.mPrefs.putString(SignalLibConsts.PREF_API_BEFORE_TIMESTAMP, str);
            String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(this.mPrefs.getString(SignalLibConsts.PREF_API_INSTALL_TIMESTAMP));
            this.mCurrentTime = str2;
            this.mBeforeTime = str;
            try {
                if (this.mCurrentTime.length() > 0 && this.mBeforeTime.length() > 0) {
                    if (NULL_TO_STRING.length() > 0 && Long.valueOf(NULL_TO_STRING).longValue() > Long.valueOf(this.mBeforeTime).longValue()) {
                        this.mBeforeTime = NULL_TO_STRING;
                    }
                    Intent intent = new Intent(getApplicationContext(), JGetSaveModePushSmsService.class);
                    intent.putExtra("currentTime", this.mCurrentTime);
                    intent.putExtra("beforeTime", this.mBeforeTime);
                    JGetSaveModePushSmsService.enqueueWork(getApplicationContext(), intent);
                    if (VERSION.SDK_INT >= 18) {
                        boolean hasNotificationAccess = hasNotificationAccess();
                        StringBuilder sb = new StringBuilder();
                        sb.append(hasNotificationAccess);
                        sb.append("");
                        SignalUtil.PRINT_LOG("\ud478\uc2dc\uc54c\ub9bcON : ", sb.toString());
                        if (hasNotificationAccess) {
                            Intent intent2 = new Intent(this.mContext, JGetSaveModePushService.class);
                            intent2.putExtra("currentTime", this.mCurrentTime);
                            intent2.putExtra("beforeTime", this.mBeforeTime);
                            JGetSaveModePushService.enqueueWork(this.mContext, intent2);
                        }
                    }
                }
            } catch (NumberFormatException e3) {
                e3.printStackTrace();
            }
        } else if (ResultCode.CODE_m9999.equals(resultcode)) {
            this.mPrefs.putBoolean(SignalLibConsts.PREF_STOP_COLLECT, true);
            this.mPrefs.putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_FLAG, true);
            Intent intent3 = new Intent(SignalLibConsts.ACTION_SIGNALID_RECEIVE);
            intent3.addFlags(536870912);
            intent3.putExtra("signalId", ResultCode.CODE_m9999);
            LocalBroadcastManager.getInstance(this.mContext).sendBroadcast(intent3);
        } else {
            failResponseToDbTask();
        }
    }

    /* access modifiers changed from: protected */
    public void failResponseToDbTask() {
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
        instance.add(6, 15);
        try {
            str2 = String.valueOf(instance.getTimeInMillis());
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        if (str != null && str2 != null) {
            this.mPrefs.putString(SignalLibConsts.PREF_API_CURRENT_TIMESTAMP, str);
            this.mPrefs.putString(SignalLibConsts.PREF_API_BEFORE_TIMESTAMP, str2);
            String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(this.mPrefs.getString(SignalLibConsts.PREF_API_INSTALL_TIMESTAMP));
            if (str.length() > 0 && str2.length() > 0) {
                if (NULL_TO_STRING.length() <= 0 || Long.valueOf(NULL_TO_STRING).longValue() <= Long.valueOf(str2).longValue()) {
                    NULL_TO_STRING = str2;
                }
                Intent intent = new Intent(getApplicationContext(), JGetSaveModePushSmsService.class);
                intent.putExtra("currentTime", str);
                intent.putExtra("beforeTime", NULL_TO_STRING);
                JGetSaveModePushSmsService.enqueueWork(getApplicationContext(), intent);
                if (VERSION.SDK_INT >= 18) {
                    boolean hasNotificationAccess = hasNotificationAccess();
                    StringBuilder sb = new StringBuilder();
                    sb.append(hasNotificationAccess);
                    sb.append("");
                    SignalUtil.PRINT_LOG("\ud478\uc2dc\uc54c\ub9bcON : ", sb.toString());
                    if (hasNotificationAccess) {
                        Intent intent2 = new Intent(getApplicationContext(), JGetSaveModePushService.class);
                        intent2.putExtra("currentTime", this.mCurrentTime);
                        intent2.putExtra("beforeTime", this.mBeforeTime);
                        JGetSaveModePushService.enqueueWork(getApplicationContext(), intent2);
                    }
                }
            }
        }
    }

    public boolean onStopCurrentWork() {
        String str = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("onStopCurrentWork : ");
        sb.append(super.onStopCurrentWork());
        SignalUtil.PRINT_LOG(str, sb.toString());
        return false;
    }
}