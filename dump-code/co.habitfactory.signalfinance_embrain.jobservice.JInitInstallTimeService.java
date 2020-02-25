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
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JInitInstallTimeService extends SafeJobIntentService implements SignalLibConsts {
    static final int JOB_ID = 1011;
    /* access modifiers changed from: private */
    public final String TAG = JGetCurrentTimeService.class.getSimpleName();
    private Context mContext;
    private SignalLibPrefs mPrefs;

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JInitInstallTimeService.class, 1011, intent);
    }

    public void onCreate() {
        super.onCreate();
        this.mPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        String str;
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
        try {
            requestRetrofit("0");
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    private void requestRetrofit(String str) throws Exception {
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this.mContext).requestServerDateTime(new IptServerTime(SignalUtil.getUserId(this.mContext), str)), 1, new Callback<OptServerTime>() {
            public void onResponse(Call<OptServerTime> call, Response<OptServerTime> response) {
                int code = response.code();
                if (code == 200) {
                    OptServerTime optServerTime = (OptServerTime) response.body();
                    if (optServerTime != null) {
                        String access$000 = JInitInstallTimeService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$000, sb.toString());
                        JInitInstallTimeService.this.parseResult(optServerTime);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JInitInstallTimeService.this.TAG, "response : result null");
                    JInitInstallTimeService.this.stopSelf();
                    return;
                }
                String access$0002 = JInitInstallTimeService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$0002, sb2.toString());
                JInitInstallTimeService.this.stopSelf();
            }

            public void onFailure(Call<OptServerTime> call, Throwable th) {
                String access$000 = JInitInstallTimeService.this.TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("fail : ");
                sb.append(th.toString());
                SignalUtil.PRINT_LOG(access$000, sb.toString());
                JInitInstallTimeService.this.stopSelf();
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
            String str3 = optServerTime.getgMillis();
            try {
                str3 = String.format("%-13s", new Object[]{str3}).replace(' ', '0');
            } catch (Exception e) {
                e.printStackTrace();
            }
            this.mPrefs.putString(SignalLibConsts.PREF_API_INSTALL_TIMESTAMP, str3);
            this.mPrefs.putBoolean(SignalLibConsts.PREF_SET_CHANGE_INSTALLTIME, false);
        } else if (resultcode.equals(ResultCode.CODE_m9999)) {
            this.mPrefs.putBoolean(SignalLibConsts.PREF_STOP_COLLECT, true);
            this.mPrefs.putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_FLAG, true);
        }
        stopSelf();
    }
}