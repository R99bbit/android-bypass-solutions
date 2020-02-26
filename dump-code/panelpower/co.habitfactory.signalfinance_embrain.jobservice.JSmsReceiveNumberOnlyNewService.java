package co.habitfactory.signalfinance_embrain.jobservice;

import android.content.Context;
import android.content.Intent;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import androidx.core.app.SafeJobIntentService;
import co.habitfactory.signalfinance_embrain.comm.ResultCode;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.dataset.SmsReceiveNumberSet;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperSmsReceiveNumber;
import co.habitfactory.signalfinance_embrain.retroapi.APIHelper;
import co.habitfactory.signalfinance_embrain.retroapi.RestfulAdapter;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import co.habitfactory.signalfinance_embrain.retroapi.response.OptSmsNumber;
import co.habitfactory.signalfinance_embrain.retroapi.response.SmsNumber;
import java.util.ArrayList;
import java.util.Iterator;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JSmsReceiveNumberOnlyNewService extends SafeJobIntentService implements SignalLibConsts {
    static final int JOB_ID = 1020;
    private final String TAG = JSmsReceiveNumberOnlyNewService.class.getSimpleName();
    private Context mContext;
    private SignalLibPrefs mPrefs;

    public void onCreate() {
        super.onCreate();
        this.mPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JSmsReceiveNumberOnlyNewService.class, 1020, intent);
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        String str;
        try {
            str = SignalUtil.getUserId(this);
        } catch (Exception e) {
            e.printStackTrace();
            str = null;
        }
        if (str == null || str.length() <= 1) {
            SignalUtil.PRINT_LOG(this.TAG, " : userId\uc5c6\uc74c");
            stopSelf();
            return;
        }
        if (this.mPrefs.getBoolean(SignalLibConsts.PREF_STOP_COLLECT, Boolean.valueOf(true)).booleanValue()) {
            SignalUtil.PRINT_LOG(this.TAG, "\uc218\uc9d1\uc815\uc9c0 : \ud654\uc774\ud2b8\ubc88\ud638 \uc218\uc9d1 \uc548\ud568.");
            stopSelf();
        } else {
            try {
                requestRetrofit();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    private void requestRetrofit() throws Exception {
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this).requestGetSmsNumberListOnlyNew(new IptCommon(SignalUtil.getUserId(this.mContext))), 1, new Callback<OptSmsNumber>() {
            public void onResponse(Call<OptSmsNumber> call, Response<OptSmsNumber> response) {
                if (response.code() == 200) {
                    OptSmsNumber optSmsNumber = (OptSmsNumber) response.body();
                    if (optSmsNumber != null) {
                        JSmsReceiveNumberOnlyNewService.this.parseResult(optSmsNumber);
                        return;
                    }
                    JSmsReceiveNumberOnlyNewService.this.closeDb();
                    JSmsReceiveNumberOnlyNewService.this.stopSelf();
                    return;
                }
                JSmsReceiveNumberOnlyNewService.this.stopSelf();
            }

            public void onFailure(Call<OptSmsNumber> call, Throwable th) {
                JSmsReceiveNumberOnlyNewService.this.closeDb();
                JSmsReceiveNumberOnlyNewService.this.stopSelf();
            }
        });
    }

    public void parseResult(OptSmsNumber optSmsNumber) {
        String str = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("resultcode  : ");
        sb.append(optSmsNumber.getResultcode());
        SignalUtil.PRINT_LOG(str, sb.toString());
        String str2 = this.TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("message     : ");
        sb2.append(optSmsNumber.getMessage());
        SignalUtil.PRINT_LOG(str2, sb2.toString());
        String resultcode = optSmsNumber.getResultcode();
        if (resultcode.equals("00")) {
            DatabaseHelperSmsReceiveNumber instance = DatabaseHelperSmsReceiveNumber.getInstance(getApplicationContext());
            try {
                instance.onCreateWithTable(instance.getDB(), DatabaseHelperSmsReceiveNumber.TABLE_NAME);
            } catch (SQLException e) {
                e.printStackTrace();
            }
            ArrayList<SmsNumber> numList = optSmsNumber.getNumList();
            ArrayList arrayList = new ArrayList();
            if (numList != null) {
                String str3 = this.TAG;
                StringBuilder sb3 = new StringBuilder();
                sb3.append("numList size    : ");
                sb3.append(numList.size());
                SignalUtil.PRINT_LOG(str3, sb3.toString());
                Iterator<SmsNumber> it = numList.iterator();
                while (it.hasNext()) {
                    SmsNumber next = it.next();
                    if (next.getNumber() != null && !instance.getRowExist(next.getNumber()).booleanValue()) {
                        arrayList.add(new SmsReceiveNumberSet(next.getNumber(), "", next.getType()));
                    }
                }
                String str4 = this.TAG;
                StringBuilder sb4 = new StringBuilder();
                sb4.append("arrDataSet size    : ");
                sb4.append(arrayList.size());
                SignalUtil.PRINT_LOG(str4, sb4.toString());
                if (arrayList.size() > 0) {
                    instance.addRowOnlyNewList(arrayList);
                }
            }
        } else if (resultcode.equals(ResultCode.CODE_m9999)) {
            this.mPrefs.putBoolean(SignalLibConsts.PREF_STOP_COLLECT, true);
            this.mPrefs.putBoolean(SignalLibConsts.PREF_OLD_SMS_SYNC_FLAG, true);
        } else {
            SignalUtil.PRINT_LOG(this.TAG, "\uc720\uc800 \uc544\uc774\ub514\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.");
        }
        closeDb();
        stopSelf();
    }

    /* access modifiers changed from: private */
    public void closeDb() {
        try {
            SQLiteDatabase db = DatabaseHelperSmsReceiveNumber.getInstance(getApplicationContext()).getDB();
            if (db != null) {
                db.close();
            }
        } catch (SQLiteException e) {
            e.printStackTrace();
        }
    }

    public boolean onStopCurrentWork() {
        return super.onStopCurrentWork();
    }
}