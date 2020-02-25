package co.habitfactory.signalfinance_embrain.jobservice;

import android.content.Context;
import android.content.Intent;
import androidx.core.app.SafeJobIntentService;
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

public class JGetCurrentTimeService extends SafeJobIntentService implements SignalLibConsts {
    static final int JOB_ID = 1004;
    private int ICOUNT_BEFOREDATE = 180;
    /* access modifiers changed from: private */
    public final String TAG = JGetCurrentTimeService.class.getSimpleName();
    private Context mContext;
    private SignalLibPrefs mPrefs;

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JGetCurrentTimeService.class, 1004, intent);
    }

    public void onCreate() {
        super.onCreate();
        this.mPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        String str;
        String str2;
        try {
            str = SignalUtil.getUserId(this);
        } catch (Exception e) {
            e.printStackTrace();
            str = "";
        }
        if (str.length() <= 0) {
            stopSelf();
            return;
        }
        int i = 180;
        try {
            i = intent.getIntExtra("termValue", 180);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        this.ICOUNT_BEFOREDATE = i;
        try {
            str2 = String.valueOf(i);
        } catch (Exception e3) {
            e3.printStackTrace();
            str2 = "180";
        }
        try {
            requestRetrofit(str2);
        } catch (Exception e4) {
            e4.printStackTrace();
        }
    }

    private void requestRetrofit(String str) throws Exception {
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this.mContext).requestServerDateTime(new IptServerTime(SignalUtil.getUserId(this.mContext), str)), 1, new Callback<OptServerTime>() {
            public void onResponse(Call<OptServerTime> call, Response<OptServerTime> response) {
                int code = response.code();
                if (code == 200) {
                    OptServerTime optServerTime = (OptServerTime) response.body();
                    if (optServerTime != null) {
                        String access$000 = JGetCurrentTimeService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$000, sb.toString());
                        JGetCurrentTimeService.this.parseResult(optServerTime);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JGetCurrentTimeService.this.TAG, "response : result null");
                    JGetCurrentTimeService.this.failResponseToDbTask();
                    return;
                }
                String access$0002 = JGetCurrentTimeService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$0002, sb2.toString());
                JGetCurrentTimeService.this.failResponseToDbTask();
            }

            public void onFailure(Call<OptServerTime> call, Throwable th) {
                String access$000 = JGetCurrentTimeService.this.TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("fail : ");
                sb.append(th.toString());
                SignalUtil.PRINT_LOG(access$000, sb.toString());
                JGetCurrentTimeService.this.failResponseToDbTask();
            }
        });
    }

    public void parseResult(OptServerTime optServerTime) {
        String str = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("resultcode  : ");
        sb.append(optServerTime.getResultcode());
        SignalUtil.PRINT_LOG(str, sb.toString());
        String str2 = this.TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("message     : ");
        sb2.append(optServerTime.getMessage());
        SignalUtil.PRINT_LOG(str2, sb2.toString());
        String resultcode = optServerTime.getResultcode();
        if (resultcode.equals("00")) {
            String str3 = optServerTime.getbMillis();
            String str4 = optServerTime.getcMillis();
            String str5 = optServerTime.getgMillis();
            String str6 = this.TAG;
            StringBuilder sb3 = new StringBuilder();
            sb3.append("cMillis : ");
            sb3.append(str4);
            SignalUtil.PRINT_LOG(str6, sb3.toString());
            try {
                str3 = SignalUtil.getTimemillisFirstDay(str3);
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                str4 = String.format("%-13s", new Object[]{str4}).replace(' ', '0');
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            try {
                str3 = String.format("%-13s", new Object[]{str3}).replace(' ', '0');
            } catch (Exception e3) {
                e3.printStackTrace();
            }
            try {
                str5 = String.format("%-13s", new Object[]{str5}).replace(' ', '0');
            } catch (Exception e4) {
                e4.printStackTrace();
            }
            this.mPrefs.putString(SignalLibConsts.PREF_API_SYNC_CURRENT_TIMESTAMP, str4);
            this.mPrefs.putString(SignalLibConsts.PREF_API_SYNC_BEFORE_TIMESTAMP, str3);
            String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(SignalLibConsts.PREF_API_INSTALL_TIMESTAMP);
            boolean booleanValue = this.mPrefs.getBoolean(SignalLibConsts.PREF_IS_FROM_AGREE, Boolean.valueOf(false)).booleanValue();
            boolean booleanValue2 = this.mPrefs.getBoolean(SignalLibConsts.PREF_SET_CHANGE_INSTALLTIME, Boolean.valueOf(false)).booleanValue();
            if (booleanValue || booleanValue2 || NULL_TO_STRING.length() <= 0) {
                SignalUtil.PRINT_LOG(this.TAG, "change installTime");
                this.mPrefs.putString(SignalLibConsts.PREF_API_INSTALL_TIMESTAMP, str5);
                this.mPrefs.putBoolean(SignalLibConsts.PREF_SET_CHANGE_INSTALLTIME, false);
            }
        } else if (resultcode.equals(ResultCode.CODE_m9999)) {
            this.mPrefs.putBoolean(SignalLibConsts.PREF_STOP_COLLECT, true);
            this.mPrefs.putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_FLAG, true);
        } else {
            failResponseToDbTask();
        }
        stopSelf();
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
        instance.add(6, -this.ICOUNT_BEFOREDATE);
        try {
            instance.set(5, 1);
            str2 = String.valueOf(instance.getTimeInMillis());
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        if (!(str == null || str2 == null)) {
            this.mPrefs.putString(SignalLibConsts.PREF_API_SYNC_CURRENT_TIMESTAMP, str);
            this.mPrefs.putString(SignalLibConsts.PREF_API_SYNC_BEFORE_TIMESTAMP, str2);
        }
        stopSelf();
    }

    public boolean onStopCurrentWork() {
        return super.onStopCurrentWork();
    }
}