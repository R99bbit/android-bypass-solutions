package co.habitfactory.signalfinance_embrain.jobservice;

import android.content.Context;
import android.content.Intent;
import android.database.SQLException;
import android.os.AsyncTask;
import android.os.AsyncTask.Status;
import androidx.core.app.SafeJobIntentService;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.dataset.PushDataSet;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperMissedNotification;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperMissedPushSms;
import co.habitfactory.signalfinance_embrain.retroapi.APIHelper;
import co.habitfactory.signalfinance_embrain.retroapi.RestfulAdapter;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptSaveBundlePushData;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import java.util.ArrayList;
import java.util.Iterator;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JGetSaveModePushSmsService extends SafeJobIntentService implements SignalLibConsts {
    static final int JOB_ID = 1023;
    /* access modifiers changed from: private */
    public final String TAG = JGetSaveModePushSmsService.class.getSimpleName();
    /* access modifiers changed from: private */
    public ArrayList<PushDataSet> arrPushData;
    /* access modifiers changed from: private */
    public String mBeforeTime;
    private Context mContext;
    /* access modifiers changed from: private */
    public String mCurrentTime;
    private SignalLibPrefs mPrefs;
    private mMissedPushSmsSendDataTask mSendTask = null;

    private class mMissedPushSmsSendDataTask extends AsyncTask<Integer, Void, Boolean> {
        private mMissedPushSmsSendDataTask() {
        }

        /* access modifiers changed from: protected */
        public void onPreExecute() {
            super.onPreExecute();
        }

        /* access modifiers changed from: protected */
        public Boolean doInBackground(Integer... numArr) {
            DatabaseHelperMissedPushSms instance = DatabaseHelperMissedPushSms.getInstance(JGetSaveModePushSmsService.this.getApplicationContext());
            try {
                instance.onCreateWithTable(instance.getDB(), DatabaseHelperMissedPushSms.TABLE_NAME);
            } catch (SQLException e) {
                e.printStackTrace();
            }
            try {
                if (JGetSaveModePushSmsService.this.mCurrentTime.length() <= 0 || JGetSaveModePushSmsService.this.mBeforeTime.length() <= 0) {
                    return Boolean.valueOf(false);
                }
                JGetSaveModePushSmsService.this.arrPushData = instance.getRowsRecentData(JGetSaveModePushSmsService.this.mBeforeTime, JGetSaveModePushSmsService.this.mCurrentTime);
                try {
                    if (JGetSaveModePushSmsService.this.arrPushData == null) {
                        return Boolean.valueOf(false);
                    }
                    if (JGetSaveModePushSmsService.this.arrPushData.size() > 0) {
                        return Boolean.valueOf(true);
                    }
                    return Boolean.valueOf(false);
                } catch (Exception e2) {
                    e2.printStackTrace();
                    return Boolean.valueOf(false);
                }
            } catch (Exception e3) {
                e3.printStackTrace();
            }
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(Boolean bool) {
            String access$400 = JGetSaveModePushSmsService.this.TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("\ubbf8\uc804\uc1a1PushSms : ");
            sb.append(bool);
            SignalUtil.PRINT_LOG(access$400, sb.toString());
            if (bool.booleanValue()) {
                try {
                    JGetSaveModePushSmsService.this.requestRetrofit(JGetSaveModePushSmsService.this.arrPushData);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                JGetSaveModePushSmsService.this.stopSelf();
            }
            super.onPostExecute(bool);
        }
    }

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JGetSaveModePushSmsService.class, (int) JOB_ID, intent);
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
            SignalUtil.PRINT_LOG(this.TAG, "\uc218\uc9d1\uc815\uc9c0 : \uc808\uc804\ubaa8\ub4dc\uc2dc \ud478\uc2dc \ub370\uc774\ud130 \uc804\uc1a1 \uc548\ud568.");
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
        this.mCurrentTime = intent.getStringExtra("currentTime");
        this.mBeforeTime = intent.getStringExtra("beforeTime");
        compareMessageData();
    }

    private void compareMessageData() {
        mMissedPushSmsSendDataTask mmissedpushsmssenddatatask = this.mSendTask;
        if (mmissedpushsmssenddatatask == null) {
            this.arrPushData = null;
            this.mSendTask = new mMissedPushSmsSendDataTask();
            this.mSendTask.execute(new Integer[0]);
        } else if (mmissedpushsmssenddatatask.getStatus() != Status.RUNNING) {
            this.arrPushData.clear();
            this.arrPushData = null;
            this.mSendTask = new mMissedPushSmsSendDataTask();
            this.mSendTask.execute(new Integer[0]);
        }
    }

    /* access modifiers changed from: private */
    public void requestRetrofit(ArrayList<PushDataSet> arrayList) throws Exception {
        if (arrayList != null) {
            ArrayList arrayList2 = new ArrayList();
            Iterator<PushDataSet> it = arrayList.iterator();
            while (it.hasNext()) {
                PushDataSet next = it.next();
                if (next.getNotiText() != null && next.getNotiText().length() > 0) {
                    arrayList2.add(next);
                }
            }
            if (arrayList2.size() > 0) {
                APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this.mContext).requestSaveBundlePushSmsData(new IptSaveBundlePushData(SignalUtil.getUserId(this.mContext), SignalUtil.getDeviceLineNumber(this.mContext), arrayList)), 1, new Callback<OptResultDataset>() {
                    public void onResponse(Call<OptResultDataset> call, Response<OptResultDataset> response) {
                        int code = response.code();
                        if (code == 200) {
                            OptResultDataset optResultDataset = (OptResultDataset) response.body();
                            if (optResultDataset != null) {
                                String access$400 = JGetSaveModePushSmsService.this.TAG;
                                StringBuilder sb = new StringBuilder();
                                sb.append("response : ");
                                sb.append(String.valueOf(code));
                                SignalUtil.PRINT_LOG(access$400, sb.toString());
                                JGetSaveModePushSmsService.this.parseResult(optResultDataset);
                                return;
                            }
                            SignalUtil.PRINT_LOG(JGetSaveModePushSmsService.this.TAG, "response : result null");
                            JGetSaveModePushSmsService.this.stopSelf();
                            return;
                        }
                        String access$4002 = JGetSaveModePushSmsService.this.TAG;
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("response : ");
                        sb2.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$4002, sb2.toString());
                    }

                    public void onFailure(Call<OptResultDataset> call, Throwable th) {
                        String access$400 = JGetSaveModePushSmsService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("fail : ");
                        sb.append(th.toString());
                        SignalUtil.PRINT_LOG(access$400, sb.toString());
                        JGetSaveModePushSmsService.this.stopSelf();
                    }
                });
            }
        }
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
        if (optResultDataset.getResultcode().equals("00")) {
            DatabaseHelperMissedPushSms instance = DatabaseHelperMissedPushSms.getInstance(getApplicationContext());
            try {
                instance.updateRows(this.arrPushData);
            } catch (Exception e) {
                e.printStackTrace();
            }
            this.arrPushData.clear();
            try {
                instance.dropTable(instance.getDB(), DatabaseHelperMissedNotification.TABLE_NAME);
            } catch (SQLException e2) {
                e2.printStackTrace();
            }
        }
        stopSelf();
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