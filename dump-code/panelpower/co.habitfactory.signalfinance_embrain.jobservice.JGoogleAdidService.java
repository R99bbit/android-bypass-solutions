package co.habitfactory.signalfinance_embrain.jobservice;

import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import androidx.core.app.SafeJobIntentService;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import co.habitfactory.signalfinance_embrain.comm.ResultCode;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.retroapi.APIHelper;
import co.habitfactory.signalfinance_embrain.retroapi.RestfulAdapter;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptAdid;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptServerTime;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptYearGender;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptServerTime;
import co.habitfactory.signalfinance_embrain.retroapi.response.ResponseResult;
import com.embrain.panelpower.UserInfoManager;
import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.firebase.analytics.FirebaseAnalytics.Event;
import java.io.IOException;
import java.net.ConnectException;
import java.util.Calendar;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JGoogleAdidService extends SafeJobIntentService implements SignalLibConsts {
    private static final String COUNT_BEFOREDATE = "15";
    private static final int ICOUNT_BEFOREDATE = -15;
    static final int JOB_ID = 1010;
    /* access modifiers changed from: private */
    public final String TAG = JGoogleAdidService.class.getSimpleName();
    /* access modifiers changed from: private */
    public boolean isReLogin = false;
    private String mBeforeTime;
    /* access modifiers changed from: private */
    public Context mContext;
    private String mCurrentTime;
    /* access modifiers changed from: private */
    public String mIsFrom = "";
    /* access modifiers changed from: private */
    public SignalLibPrefs mLibPrefs;
    /* access modifiers changed from: private */
    public String mUserId = "";

    private class GoogleAppIdTask extends AsyncTask<Void, Void, String> {
        private final String TAG;

        private GoogleAppIdTask() {
            this.TAG = "GoogleAppIdTask";
        }

        /* access modifiers changed from: protected */
        public String doInBackground(Void... voidArr) {
            try {
                return AdvertisingIdClient.getAdvertisingIdInfo(JGoogleAdidService.this.getApplicationContext()).getId();
            } catch (IllegalStateException e) {
                e.printStackTrace();
                SignalUtil.PRINT_LOG("GoogleAppIdTask", "IllegalStateException");
                return null;
            } catch (GooglePlayServicesRepairableException e2) {
                e2.printStackTrace();
                SignalUtil.PRINT_LOG("GoogleAppIdTask", "GooglePlayServicesRepairableException");
                return null;
            } catch (IOException e3) {
                e3.printStackTrace();
                SignalUtil.PRINT_LOG("GoogleAppIdTask", "IOException");
                return null;
            } catch (GooglePlayServicesNotAvailableException e4) {
                e4.printStackTrace();
                SignalUtil.PRINT_LOG("GoogleAppIdTask", "GooglePlayServicesNotAvailableException");
                return null;
            }
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(String str) {
            String str2;
            try {
                str2 = JGoogleAdidService.this.mLibPrefs.getString(SignalLibConsts.PREF_API_USER_ADID);
            } catch (Exception e) {
                e.printStackTrace();
                str2 = null;
            }
            String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(str);
            JGoogleAdidService.this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_ADID, NULL_TO_STRING);
            if (str2 == null || str2.length() <= 0) {
                if (NULL_TO_STRING != null && NULL_TO_STRING.length() > 0) {
                    JGoogleAdidService.this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_ADID_CHANGED_FLAG, UserInfoManager.AGREE_Y);
                }
            } else if (NULL_TO_STRING != null && NULL_TO_STRING.length() > 0) {
                if (NULL_TO_STRING.equals(str2)) {
                    JGoogleAdidService.this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_ADID_CHANGED_FLAG, "N");
                } else {
                    JGoogleAdidService.this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_ADID_CHANGED_FLAG, UserInfoManager.AGREE_Y);
                }
            }
            String NULL_TO_STRING2 = SignalUtil.NULL_TO_STRING(JGoogleAdidService.this.mLibPrefs.getString(SignalLibConsts.PREF_API_USER_ADID));
            String NULL_TO_STRING3 = SignalUtil.NULL_TO_STRING(JGoogleAdidService.this.mLibPrefs.getString(SignalLibConsts.PREF_API_USER_ADID_CHANGED_FLAG));
            if (NULL_TO_STRING2.length() <= 0) {
                SignalUtil.PRINT_LOG("GoogleAppIdTask", "id\ub97c \uac00\uc838\uc624\uc9c0 \ubabb\ud588\uc2b5\ub2c8\ub2e4 ");
                Intent intent = new Intent(SignalLibConsts.ACTION_SIGNALID_RECEIVE);
                intent.addFlags(536870912);
                intent.putExtra("signalId", ResultCode.CODE_m8888);
                LocalBroadcastManager.getInstance(JGoogleAdidService.this.mContext).sendBroadcast(intent);
                JGoogleAdidService.this.stopSelf();
                return;
            }
            if ("create".equals(JGoogleAdidService.this.mIsFrom)) {
                if (JGoogleAdidService.this.mUserId.length() <= 0) {
                    JGoogleAdidService.this.mLibPrefs.putString(SignalLibConsts.PREF_API_USER_USERID, JGoogleAdidService.this.mUserId);
                    SignalUtil.PRINT_LOG("GoogleAppIdTask", " : \uc2e0\uaddc\uac00\uc785");
                    JCreateSignalIdService.enqueueWork(JGoogleAdidService.this.mContext, new Intent(JGoogleAdidService.this.mContext, JCreateSignalIdService.class));
                    JGoogleAdidService.this.stopSelf();
                }
            } else if (Event.LOGIN.equals(JGoogleAdidService.this.mIsFrom)) {
                JGoogleAdidService.this.isReLogin = true;
                if (JGoogleAdidService.this.mUserId.length() > 0) {
                    SignalUtil.PRINT_LOG("GoogleAppIdTask", " : \ub85c\uadf8\uc778");
                    String NULL_TO_STRING4 = SignalUtil.NULL_TO_STRING(JGoogleAdidService.this.mLibPrefs.getString(SignalLibConsts.PREF_API_USER_YEAROFBIRTH));
                    String NULL_TO_STRING5 = SignalUtil.NULL_TO_STRING(JGoogleAdidService.this.mLibPrefs.getString(SignalLibConsts.PREF_API_USER_GENDER));
                    JGoogleAdidService jGoogleAdidService = JGoogleAdidService.this;
                    jGoogleAdidService.profileUpdateForPartner(jGoogleAdidService.mUserId, NULL_TO_STRING4, NULL_TO_STRING5);
                }
            } else {
                String savedUserId = JGoogleAdidService.this.mLibPrefs.getSavedUserId();
                if (savedUserId.length() <= 0) {
                    SignalUtil.PRINT_LOG("GoogleAppIdTask", " : signalId \uc5c6\uc74c");
                    JGoogleAdidService.this.mLibPrefs.setStopCollectData(JGoogleAdidService.this.mContext);
                    Intent intent2 = new Intent(SignalLibConsts.ACTION_SIGNALID_RECEIVE);
                    intent2.addFlags(536870912);
                    intent2.putExtra("signalId", ResultCode.CODE_m9999);
                    LocalBroadcastManager.getInstance(JGoogleAdidService.this.mContext).sendBroadcast(intent2);
                } else if (NULL_TO_STRING3.equals(UserInfoManager.AGREE_Y)) {
                    JGoogleAdidService.this.requestRetrofit(NULL_TO_STRING2, savedUserId);
                }
                JGoogleAdidService.this.stopSelf();
            }
        }
    }

    public void onCreate() {
        super.onCreate();
        this.mLibPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JGoogleAdidService.class, 1010, intent);
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        try {
            this.mUserId = intent.getStringExtra("userId");
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            this.mIsFrom = intent.getStringExtra("isFrom");
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        if ("create".equals(this.mIsFrom)) {
            new GoogleAppIdTask().execute(new Void[0]);
            return;
        }
        try {
            requestRetrofitGetTime();
        } catch (Exception e3) {
            e3.printStackTrace();
        }
    }

    private void requestRetrofitGetTime() throws Exception {
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this.mContext).requestServerDateTime(new IptServerTime(SignalUtil.getUserId(this.mContext), "15")), 1, new Callback<OptServerTime>() {
            public void onResponse(Call<OptServerTime> call, Response<OptServerTime> response) {
                if (response.code() == 200) {
                    OptServerTime optServerTime = (OptServerTime) response.body();
                    if (optServerTime != null) {
                        try {
                            JGoogleAdidService.this.parseResultGetTime(optServerTime);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        JGoogleAdidService.this.failResponseToDbTask();
                    }
                } else {
                    JGoogleAdidService.this.failResponseToDbTask();
                }
            }

            public void onFailure(Call<OptServerTime> call, Throwable th) {
                JGoogleAdidService.this.failResponseToDbTask();
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestRetrofit(String str, String str2) {
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this.mContext).updateAdid(new IptAdid(str2, str, SignalLibConsts.g_DataChannel)), 1, new Callback<OptResultDataset>() {
            public void onResponse(Call<OptResultDataset> call, Response<OptResultDataset> response) {
                int code = response.code();
                if (code == 200) {
                    OptResultDataset optResultDataset = (OptResultDataset) response.body();
                    if (optResultDataset != null) {
                        String access$800 = JGoogleAdidService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$800, sb.toString());
                        JGoogleAdidService.this.parseResult(optResultDataset);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JGoogleAdidService.this.TAG, "response : result null");
                    JGoogleAdidService.this.isReLogin = false;
                    return;
                }
                String access$8002 = JGoogleAdidService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$8002, sb2.toString());
                JGoogleAdidService.this.isReLogin = false;
            }

            public void onFailure(Call<OptResultDataset> call, Throwable th) {
                if (th.getCause() instanceof ConnectException) {
                    SignalUtil.PRINT_LOG(JGoogleAdidService.this.TAG, "\ub124\ud2b8\uc6cc\ud06c \uc5f0\uacb0\uc774 \uc6d0\ud65c\ud558\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4.\n\uc7a0\uc2dc \ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.");
                    return;
                }
                try {
                    String th2 = th.getCause().toString();
                    if (th2 == null) {
                        th2 = "\ub124\ud2b8\uc6cc\ud06c \uc5f0\uacb0\uc774 \uc6d0\ud65c\ud558\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4.\n\uc7a0\uc2dc \ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.";
                    }
                    SignalUtil.PRINT_LOG(JGoogleAdidService.this.TAG, th2);
                } catch (Exception e) {
                    SignalUtil.PRINT_LOG(JGoogleAdidService.this.TAG, "\ub124\ud2b8\uc6cc\ud06c \uc5f0\uacb0\uc774 \uc6d0\ud65c\ud558\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4.\n\uc7a0\uc2dc \ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.");
                    e.printStackTrace();
                }
            }
        });
    }

    public void parseResult(OptResultDataset optResultDataset) {
        String str = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("resultcode  : ");
        sb.append(optResultDataset.getResultcode());
        SignalUtil.PRINT_LOG(str, sb.toString());
        String str2 = this.TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("message     : ");
        sb2.append(optResultDataset.getMessage());
        SignalUtil.PRINT_LOG(str2, sb2.toString());
        if (ResultCode.CODE_m9999.equals(optResultDataset.getResultcode())) {
            this.mLibPrefs.setStopCollectData(this.mContext);
            Intent intent = new Intent(SignalLibConsts.ACTION_SIGNALID_RECEIVE);
            intent.addFlags(536870912);
            intent.putExtra("signalId", ResultCode.CODE_m9999);
            LocalBroadcastManager.getInstance(this.mContext).sendBroadcast(intent);
        } else {
            SignalUtil.PRINT_LOG(this.TAG, "SIGNAL_SDK_OK");
            if (this.isReLogin) {
                Intent intent2 = new Intent(SignalLibConsts.ACTION_SIGNALID_RECEIVE);
                intent2.addFlags(536870912);
                intent2.putExtra("signalId", this.mUserId);
                LocalBroadcastManager.getInstance(this.mContext).sendBroadcast(intent2);
            }
        }
        this.isReLogin = false;
        stopSelf();
    }

    /* access modifiers changed from: private */
    public void profileUpdateForPartner(String str, String str2, String str3) {
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this.mContext).profileUpdateForPartner(new IptYearGender(str, str2, str3, SignalLibConsts.g_DataChannel)), 1, new Callback<ResponseResult>() {
            public void onResponse(Call<ResponseResult> call, Response<ResponseResult> response) {
                int code = response.code();
                if (code == 200) {
                    ResponseResult responseResult = (ResponseResult) response.body();
                    if (responseResult != null) {
                        String access$800 = JGoogleAdidService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$800, sb.toString());
                        JGoogleAdidService.this.parseResult(responseResult);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JGoogleAdidService.this.TAG, "response : result null");
                    JGoogleAdidService.this.isReLogin = false;
                    return;
                }
                String access$8002 = JGoogleAdidService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$8002, sb2.toString());
                JGoogleAdidService.this.isReLogin = false;
            }

            public void onFailure(Call<ResponseResult> call, Throwable th) {
                if (th.getCause() instanceof ConnectException) {
                    SignalUtil.PRINT_LOG(JGoogleAdidService.this.TAG, "\ub124\ud2b8\uc6cc\ud06c \uc5f0\uacb0\uc774 \uc6d0\ud65c\ud558\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4.\n\uc7a0\uc2dc \ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.");
                    return;
                }
                try {
                    String th2 = th.getCause().toString();
                    if (th2 == null) {
                        th2 = "\ub124\ud2b8\uc6cc\ud06c \uc5f0\uacb0\uc774 \uc6d0\ud65c\ud558\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4.\n\uc7a0\uc2dc \ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.";
                    }
                    SignalUtil.PRINT_LOG(JGoogleAdidService.this.TAG, th2);
                } catch (Exception e) {
                    SignalUtil.PRINT_LOG(JGoogleAdidService.this.TAG, "\ub124\ud2b8\uc6cc\ud06c \uc5f0\uacb0\uc774 \uc6d0\ud65c\ud558\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4.\n\uc7a0\uc2dc \ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.");
                    e.printStackTrace();
                }
            }
        });
    }

    public void parseResult(ResponseResult responseResult) {
        String str = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("resultcode  : ");
        sb.append(responseResult.getResultcode());
        SignalUtil.PRINT_LOG(str, sb.toString());
        String str2 = this.TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("message     : ");
        sb2.append(responseResult.getMessage());
        SignalUtil.PRINT_LOG(str2, sb2.toString());
        if (ResultCode.CODE_m9999.equals(responseResult.getResultcode())) {
            this.mLibPrefs.setStopCollectData(this.mContext);
            Intent intent = new Intent(SignalLibConsts.ACTION_SIGNALID_RECEIVE);
            intent.addFlags(536870912);
            intent.putExtra("signalId", ResultCode.CODE_m9999);
            LocalBroadcastManager.getInstance(this.mContext).sendBroadcast(intent);
        } else if (this.isReLogin) {
            Intent intent2 = new Intent(SignalLibConsts.ACTION_SIGNALID_RECEIVE);
            intent2.addFlags(536870912);
            intent2.putExtra("signalId", this.mUserId);
            LocalBroadcastManager.getInstance(this.mContext).sendBroadcast(intent2);
        }
        this.isReLogin = false;
        stopSelf();
    }

    public void parseResultGetTime(OptServerTime optServerTime) throws Exception {
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
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_CURRENT_TIMESTAMP, str2);
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_BEFORE_TIMESTAMP, str);
            new GoogleAppIdTask().execute(new Void[0]);
            if ("save".equals(this.mIsFrom)) {
                JGetSaveModeSmsService.enqueueWork(this.mContext, new Intent(this.mContext, JGetSaveModeSmsService.class));
            }
        } else if (ResultCode.CODE_m9999.equals(resultcode)) {
            this.mLibPrefs.setStopCollectData(this.mContext);
            Intent intent = new Intent(SignalLibConsts.ACTION_SIGNALID_RECEIVE);
            intent.addFlags(536870912);
            intent.putExtra("signalId", ResultCode.CODE_m9999);
            LocalBroadcastManager.getInstance(this.mContext).sendBroadcast(intent);
        } else {
            new GoogleAppIdTask().execute(new Void[0]);
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
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_CURRENT_TIMESTAMP, str);
            this.mLibPrefs.putString(SignalLibConsts.PREF_API_BEFORE_TIMESTAMP, str2);
            JGetSaveModeSmsService.enqueueWork(this.mContext, new Intent(this.mContext, JGetSaveModeSmsService.class));
        }
    }
}