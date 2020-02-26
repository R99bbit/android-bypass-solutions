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
import co.habitfactory.signalfinance_embrain.retroapi.APIHelper;
import co.habitfactory.signalfinance_embrain.retroapi.RestfulAdapter;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptSaveBundlePushData;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import java.util.ArrayList;
import java.util.Iterator;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JGetSaveModePushService extends SafeJobIntentService implements SignalLibConsts {
    static final int JOB_ID = 1007;
    /* access modifiers changed from: private */
    public final String TAG = JGetSaveModePushService.class.getSimpleName();
    /* access modifiers changed from: private */
    public ArrayList<PushDataSet> arrPushData;
    /* access modifiers changed from: private */
    public String mBeforeTime;
    private Context mContext;
    /* access modifiers changed from: private */
    public String mCurrentTime;
    private SignalLibPrefs mPrefs;
    private mMissedPushSendDataTask mSendTask = null;

    private class mMissedPushSendDataTask extends AsyncTask<Integer, Void, Boolean> {
        private mMissedPushSendDataTask() {
        }

        /* access modifiers changed from: protected */
        public void onPreExecute() {
            super.onPreExecute();
        }

        /* access modifiers changed from: protected */
        public Boolean doInBackground(Integer... numArr) {
            DatabaseHelperMissedNotification instance = DatabaseHelperMissedNotification.getInstance(JGetSaveModePushService.this.getApplicationContext());
            try {
                instance.onCreateWithTable(instance.getDB(), DatabaseHelperMissedNotification.TABLE_NAME);
            } catch (SQLException e) {
                e.printStackTrace();
            }
            try {
                if (JGetSaveModePushService.this.mCurrentTime.length() <= 0 || JGetSaveModePushService.this.mBeforeTime.length() <= 0) {
                    return Boolean.valueOf(false);
                }
                try {
                    JGetSaveModePushService.this.arrPushData = instance.getRowsRecentData(JGetSaveModePushService.this.mBeforeTime, JGetSaveModePushService.this.mCurrentTime);
                    String access$400 = JGetSaveModePushService.this.TAG;
                    StringBuilder sb = new StringBuilder();
                    sb.append("\uc804\uc1a1\ub418\uc9c0 \uc54a\uc740 \ud478\uc2dc\uac74\uc218 : ");
                    sb.append(JGetSaveModePushService.this.arrPushData.size());
                    SignalUtil.PRINT_LOG(access$400, sb.toString());
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
                try {
                    if (JGetSaveModePushService.this.arrPushData == null) {
                        return Boolean.valueOf(false);
                    }
                    if (JGetSaveModePushService.this.arrPushData.size() > 0) {
                        return Boolean.valueOf(true);
                    }
                    return Boolean.valueOf(false);
                } catch (Exception e3) {
                    e3.printStackTrace();
                    return Boolean.valueOf(false);
                }
            } catch (Exception e4) {
                e4.printStackTrace();
            }
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(Boolean bool) {
            if (bool.booleanValue()) {
                try {
                    JGetSaveModePushService.this.requestRetrofit(JGetSaveModePushService.this.arrPushData);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                JGetSaveModePushService.this.stopSelf();
            }
            super.onPostExecute(bool);
        }
    }

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JGetSaveModePushService.class, 1007, intent);
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
        mMissedPushSendDataTask mmissedpushsenddatatask = this.mSendTask;
        if (mmissedpushsenddatatask == null) {
            this.arrPushData = null;
            this.mSendTask = new mMissedPushSendDataTask();
            this.mSendTask.execute(new Integer[0]);
        } else if (mmissedpushsenddatatask.getStatus() != Status.RUNNING) {
            this.arrPushData.clear();
            this.arrPushData = null;
            this.mSendTask = new mMissedPushSendDataTask();
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
                String NULL_TO_STRING = SignalUtil.NULL_TO_STRING(next.getNotiText());
                String NULL_TO_STRING2 = SignalUtil.NULL_TO_STRING(next.getNotiTitle());
                try {
                    if ("null".equals(NULL_TO_STRING) && "null".equals(NULL_TO_STRING2)) {
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                try {
                    if (next.getPackageNm().toUpperCase().equals("VIVA.REPUBLICA.TOSS") && NULL_TO_STRING2.length() == 0 && NULL_TO_STRING.matches("([0-9]{1,3}(?:,?[0-9]{3})*)")) {
                    }
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
                if (NULL_TO_STRING != null && NULL_TO_STRING.length() > 0) {
                    arrayList2.add(next);
                }
            }
            if (arrayList2.size() <= 0) {
                try {
                    DatabaseHelperMissedNotification.getInstance(getApplicationContext()).updateRows(this.arrPushData);
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
                this.arrPushData.clear();
                DatabaseHelperMissedNotification instance = DatabaseHelperMissedNotification.getInstance(getApplicationContext());
                try {
                    instance.dropTable(instance.getDB(), DatabaseHelperMissedNotification.TABLE_NAME);
                } catch (SQLException e4) {
                    e4.printStackTrace();
                }
                return;
            }
            APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this.mContext).requestSaveBundlePushData(new IptSaveBundlePushData(SignalUtil.getUserId(this.mContext), SignalUtil.getDeviceLineNumber(this.mContext), arrayList)), 1, new Callback<OptResultDataset>() {
                public void onResponse(Call<OptResultDataset> call, Response<OptResultDataset> response) {
                    int code = response.code();
                    if (code == 200) {
                        OptResultDataset optResultDataset = (OptResultDataset) response.body();
                        if (optResultDataset != null) {
                            String access$400 = JGetSaveModePushService.this.TAG;
                            StringBuilder sb = new StringBuilder();
                            sb.append("response : ");
                            sb.append(String.valueOf(code));
                            SignalUtil.PRINT_LOG(access$400, sb.toString());
                            JGetSaveModePushService.this.parseResult(optResultDataset);
                            return;
                        }
                        SignalUtil.PRINT_LOG(JGetSaveModePushService.this.TAG, "response : result null");
                        JGetSaveModePushService.this.stopSelf();
                        return;
                    }
                    String access$4002 = JGetSaveModePushService.this.TAG;
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("response : ");
                    sb2.append(String.valueOf(code));
                    SignalUtil.PRINT_LOG(access$4002, sb2.toString());
                }

                public void onFailure(Call<OptResultDataset> call, Throwable th) {
                    String access$400 = JGetSaveModePushService.this.TAG;
                    StringBuilder sb = new StringBuilder();
                    sb.append("fail : ");
                    sb.append(th.toString());
                    SignalUtil.PRINT_LOG(access$400, sb.toString());
                    JGetSaveModePushService.this.stopSelf();
                }
            });
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
            try {
                DatabaseHelperMissedNotification.getInstance(getApplicationContext()).updateRows(this.arrPushData);
            } catch (Exception e) {
                e.printStackTrace();
            }
            this.arrPushData.clear();
            DatabaseHelperMissedNotification instance = DatabaseHelperMissedNotification.getInstance(getApplicationContext());
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