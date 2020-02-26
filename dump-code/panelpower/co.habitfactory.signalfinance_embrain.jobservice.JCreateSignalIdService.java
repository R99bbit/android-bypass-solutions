package co.habitfactory.signalfinance_embrain.jobservice;

import android.content.Context;
import android.content.Intent;
import androidx.core.app.SafeJobIntentService;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.retroapi.APIHelper;
import co.habitfactory.signalfinance_embrain.retroapi.RestfulAdapter;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptSignUp;
import co.habitfactory.signalfinance_embrain.retroapi.response.layout.member.OptSignUp;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JCreateSignalIdService extends SafeJobIntentService implements SignalLibConsts {
    static final int JOB_ID = 1001;
    /* access modifiers changed from: private */
    public final String TAG = JCreateSignalIdService.class.getSimpleName();
    private Context mContext;
    private SignalLibPrefs mLibPrefs;

    public void onCreate() {
        super.onCreate();
        this.mLibPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JCreateSignalIdService.class, 1001, intent);
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        this.mLibPrefs.setClearForSync(this.mContext);
        requestRetrofit();
    }

    private void requestRetrofit() {
        IptSignUp iptSignUp = r4;
        IptSignUp iptSignUp2 = new IptSignUp(SignalUtil.NULL_TO_STRING(SignalUtil.NULL_TO_STRING(this.mLibPrefs.getString(SignalLibConsts.PREF_API_USER_ADID))), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(SignalUtil.NULL_TO_STRING(this.mLibPrefs.getString(SignalLibConsts.PREF_API_USER_YEAROFBIRTH))), SignalUtil.NULL_TO_STRING(SignalUtil.NULL_TO_STRING(this.mLibPrefs.getString(SignalLibConsts.PREF_API_USER_GENDER))), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(SignalLibConsts.g_DeviceType), SignalUtil.NULL_TO_STRING(""), SignalUtil.NULL_TO_STRING(""), SignalLibConsts.g_DataChannel);
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this.mContext).signUpForPartner(iptSignUp), 1, new Callback<OptSignUp>() {
            public void onResponse(Call<OptSignUp> call, Response<OptSignUp> response) {
                int code = response.code();
                if (code == 200) {
                    OptSignUp optSignUp = (OptSignUp) response.body();
                    if (optSignUp != null) {
                        String access$000 = JCreateSignalIdService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$000, sb.toString());
                        JCreateSignalIdService.this.parseResult(optSignUp);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JCreateSignalIdService.this.TAG, "response : result null");
                    JCreateSignalIdService.this.stopSelf();
                    return;
                }
                String access$0002 = JCreateSignalIdService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$0002, sb2.toString());
                JCreateSignalIdService.this.stopSelf();
            }

            public void onFailure(Call<OptSignUp> call, Throwable th) {
                String access$000 = JCreateSignalIdService.this.TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("fail : ");
                sb.append(th.toString());
                SignalUtil.PRINT_LOG(access$000, sb.toString());
                JCreateSignalIdService.this.stopSelf();
            }
        });
    }

    public void parseResult(OptSignUp optSignUp) {
        String str = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("resultcode  : ");
        sb.append(optSignUp.getResultcode());
        SignalUtil.PRINT_LOG(str, sb.toString());
        String str2 = this.TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("message     : ");
        sb2.append(optSignUp.getMessage());
        SignalUtil.PRINT_LOG(str2, sb2.toString());
        if (optSignUp.getResultcode().equals("00")) {
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_ADID, SignalUtil.NULL_TO_STRING(optSignUp.getAdid()));
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_EMAIL, SignalUtil.NULL_TO_STRING(optSignUp.getEmail()));
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_LASTNAME, SignalUtil.NULL_TO_STRING(optSignUp.getLastName()));
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_DATEOFBIRTH, SignalUtil.NULL_TO_STRING(optSignUp.getDateOfBirth()));
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_PNUMBER, SignalUtil.NULL_TO_STRING(optSignUp.getMobilePhone()));
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_IS_LOGIN_INFLOW, SignalUtil.NULL_TO_STRING(optSignUp.getLoginType()));
            this.mLibPrefs.putString(SignalLibConsts.PREF_IS_BANK_NOTI_OFF, "OFF");
            this.mLibPrefs.putString(SignalLibConsts.PREF_IS_CARD_NOTI_OFF, "OFF");
            this.mLibPrefs.initInstallTime(this.mContext);
            this.mLibPrefs.putBoolean(SignalLibConsts.PREF_STOP_COLLECT, false);
            this.mLibPrefs.putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_FLAG, true);
            String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(optSignUp.getUserId());
            Intent intent = new Intent(SignalLibConsts.ACTION_SIGNALID_RECEIVE);
            intent.putExtra("signalId", NULL_TO_STRING);
            intent.addFlags(536870912);
            LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
        }
        stopSelf();
    }

    public void onDestroy() {
        super.onDestroy();
    }
}