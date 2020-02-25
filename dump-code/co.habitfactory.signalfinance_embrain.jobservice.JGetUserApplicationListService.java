package co.habitfactory.signalfinance_embrain.jobservice;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.os.AsyncTask;
import androidx.core.app.SafeJobIntentService;
import co.habitfactory.signalfinance_embrain.comm.SignalLibConsts;
import co.habitfactory.signalfinance_embrain.comm.SignalLibPrefs;
import co.habitfactory.signalfinance_embrain.comm.SignalUtil;
import co.habitfactory.signalfinance_embrain.dataset.FinanceInfoDataSet;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperFinanceInfo;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperMyAppInfo;
import co.habitfactory.signalfinance_embrain.retroapi.APIHelper;
import co.habitfactory.signalfinance_embrain.retroapi.RestfulAdapter;
import co.habitfactory.signalfinance_embrain.retroapi.request.IptCommon;
import co.habitfactory.signalfinance_embrain.retroapi.request.user.IptUserAppList;
import co.habitfactory.signalfinance_embrain.retroapi.request.user.UserAppData;
import co.habitfactory.signalfinance_embrain.retroapi.response.ResponseResult;
import co.habitfactory.signalfinance_embrain.retroapi.response.layout.comm.OptPushPackageNameList;
import co.habitfactory.signalfinance_embrain.retroapi.response.layout.comm.PushPackageName;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class JGetUserApplicationListService extends SafeJobIntentService implements SignalLibConsts {
    static final String FILTER_CONTAINS_RULE1 = "com.google.android.gsf.login";
    static final String FILTER_EQUALS_RULE1 = "com.android.providers.telephony";
    static final String FILTER_STARTSWITH_RULE1 = "com.sec.android.";
    static final String FILTER_STARTSWITH_RULE2 = "com.android.";
    static final String FILTER_STARTSWITH_RULE3 = "com.google.";
    static final String FILTER_STARTSWITH_RULE4 = "com.sec.android.";
    static final String FILTER_STARTSWITH_RULE5 = "com.monotype.android.font.";
    static final int JOB_ID = 1009;
    /* access modifiers changed from: private */
    public final String TAG = JGetUserApplicationListService.class.getSimpleName();
    /* access modifiers changed from: private */
    public Context mContext;
    /* access modifiers changed from: private */
    public PackageManager mPackageManager;
    /* access modifiers changed from: private */
    public SignalLibPrefs mPrefs;
    /* access modifiers changed from: private */
    public OptPushPackageNameList mResult;

    private class getAppListTask extends AsyncTask<Integer, Void, Boolean> {
        List<PackageInfo> mPackageList;

        private getAppListTask() {
            this.mPackageList = null;
        }

        /* access modifiers changed from: protected */
        public void onPreExecute() {
            super.onPreExecute();
        }

        /* access modifiers changed from: protected */
        public Boolean doInBackground(Integer... numArr) {
            List<PackageInfo> list;
            try {
                DatabaseHelperFinanceInfo instance = DatabaseHelperFinanceInfo.getInstance(JGetUserApplicationListService.this.getApplicationContext());
                SQLiteDatabase db = instance.getDB();
                if (db != null) {
                    instance.dropTable(db, DatabaseHelperFinanceInfo.TABLE_NAME);
                    db.close();
                }
            } catch (SQLiteException e) {
                e.printStackTrace();
            }
            ArrayList<PushPackageName> packageList = JGetUserApplicationListService.this.mResult.getPackageList();
            DatabaseHelperFinanceInfo instance2 = DatabaseHelperFinanceInfo.getInstance(JGetUserApplicationListService.this.getApplicationContext());
            try {
                instance2.onCreateWithTable(instance2.getDB(), DatabaseHelperFinanceInfo.TABLE_NAME);
            } catch (SQLException e2) {
                e2.printStackTrace();
            }
            Iterator<PushPackageName> it = packageList.iterator();
            while (it.hasNext()) {
                try {
                    instance2.addRow(new FinanceInfoDataSet("", it.next().getPackageName()));
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
            }
            JGetUserApplicationListService.this.mPrefs.putBoolean(SignalLibConsts.PREF_API_GOT_WHITEPACKAGE_FROM_API_CHECK, true);
            JGetUserApplicationListService jGetUserApplicationListService = JGetUserApplicationListService.this;
            jGetUserApplicationListService.mPackageManager = jGetUserApplicationListService.getPackageManager();
            try {
                list = JGetUserApplicationListService.this.mPackageManager.getInstalledPackages(4096);
            } catch (Exception e4) {
                e4.printStackTrace();
                list = null;
            }
            if (list == null) {
                return Boolean.valueOf(false);
            }
            this.mPackageList = new ArrayList();
            ArrayList arrayList = new ArrayList();
            Intent intent = new Intent("android.intent.action.MAIN", null);
            intent.addCategory("android.intent.category.LAUNCHER");
            intent.setFlags(270532608);
            for (ResolveInfo next : JGetUserApplicationListService.this.mContext.getPackageManager().queryIntentActivities(intent, 0)) {
                ActivityInfo activityInfo = next.activityInfo;
                if (!JGetUserApplicationListService.this.isSystemPackage(next)) {
                    arrayList.add(activityInfo.applicationInfo.packageName);
                }
            }
            for (PackageInfo packageInfo : list) {
                try {
                    String lowerCase = packageInfo.packageName.toLowerCase();
                    if (!JGetUserApplicationListService.this.checkExceptSendAppList(lowerCase)) {
                        if (arrayList.indexOf(lowerCase) > 0) {
                            this.mPackageList.add(packageInfo);
                        }
                    }
                } catch (Exception e5) {
                    e5.printStackTrace();
                }
            }
            return Boolean.valueOf(true);
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(Boolean bool) {
            if (bool.booleanValue()) {
                if (JGetUserApplicationListService.this.mPrefs.getBoolean(SignalLibConsts.PREF_API_GOT_WHITELIST_FROM_API_CHECK, Boolean.valueOf(false)).booleanValue()) {
                    JSmsReceiveNumberOnlyNewService.enqueueWork(JGetUserApplicationListService.this, new Intent(JGetUserApplicationListService.this, JSmsReceiveNumberOnlyNewService.class));
                } else {
                    JSmsReceiveNumberService.enqueueWork(JGetUserApplicationListService.this, new Intent(JGetUserApplicationListService.this, JSmsReceiveNumberService.class));
                }
                try {
                    if (this.mPackageList.size() > 0) {
                        JGetUserApplicationListService.this.requestRetrofit(this.mPackageList);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    JGetUserApplicationListService.this.stopSelf();
                }
            } else {
                JGetUserApplicationListService.this.stopSelf();
            }
            super.onPostExecute(bool);
        }
    }

    public void onCreate() {
        super.onCreate();
        SignalUtil.PRINT_LOG(this.TAG, "onCreate");
        this.mPrefs = new SignalLibPrefs(this);
        this.mContext = this;
    }

    public static void enqueueWork(Context context, Intent intent) {
        enqueueWork(context, JGetUserApplicationListService.class, 1009, intent);
    }

    /* access modifiers changed from: protected */
    public void onHandleWork(Intent intent) {
        if (this.mPrefs.getBoolean(SignalLibConsts.PREF_STOP_COLLECT, Boolean.valueOf(true)).booleanValue()) {
            SignalUtil.PRINT_LOG(this.TAG, "\uc218\uc9d1\uc815\uc9c0 : \uc808\uc804\ubaa8\ub4dc\uc2dc \uae08\uc735\ud328\ud0a4\uc9c0 \uc804\uc1a1 \uc548\ud568.");
            return;
        }
        try {
            requestRetrofit();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void requestRetrofit() throws Exception {
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
        requestRetrofit(str);
    }

    private void requestRetrofit(String str) throws Exception {
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this).retrievePushPackageName(new IptCommon(str)), 1, new Callback<OptPushPackageNameList>() {
            public void onResponse(Call<OptPushPackageNameList> call, Response<OptPushPackageNameList> response) {
                int code = response.code();
                if (code == 200) {
                    OptPushPackageNameList optPushPackageNameList = (OptPushPackageNameList) response.body();
                    if (optPushPackageNameList != null) {
                        String access$000 = JGetUserApplicationListService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$000, sb.toString());
                        JGetUserApplicationListService.this.parseResult(optPushPackageNameList);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JGetUserApplicationListService.this.TAG, "response : result null");
                    JGetUserApplicationListService.this.stopSelf();
                    return;
                }
                String access$0002 = JGetUserApplicationListService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$0002, sb2.toString());
                JGetUserApplicationListService.this.stopSelf();
            }

            public void onFailure(Call<OptPushPackageNameList> call, Throwable th) {
                String access$000 = JGetUserApplicationListService.this.TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("fail : ");
                sb.append(th.toString());
                SignalUtil.PRINT_LOG(access$000, sb.toString());
                JGetUserApplicationListService.this.stopSelf();
            }
        });
    }

    public void parseResult(OptPushPackageNameList optPushPackageNameList) {
        String str = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("retrievePushPackageName resultcode  : ");
        sb.append(optPushPackageNameList.getResultcode());
        SignalUtil.PRINT_LOG(str, sb.toString());
        String str2 = this.TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("retrievePushPackageName message     : ");
        sb2.append(optPushPackageNameList.getMessage());
        SignalUtil.PRINT_LOG(str2, sb2.toString());
        if (optPushPackageNameList.getResultcode().equals("00")) {
            this.mResult = optPushPackageNameList;
            new getAppListTask().execute(new Integer[0]);
        }
    }

    /* access modifiers changed from: private */
    public boolean checkExceptSendAppList(String str) {
        if (str == null || str.length() <= 0 || FILTER_EQUALS_RULE1.equals(str) || str.toString().startsWith("com.sec.android.") || str.toString().startsWith(FILTER_STARTSWITH_RULE2) || str.toString().startsWith(FILTER_STARTSWITH_RULE3) || str.toString().startsWith("com.sec.android.") || str.toString().startsWith(FILTER_STARTSWITH_RULE5) || str.toString().contains(FILTER_CONTAINS_RULE1)) {
            return true;
        }
        return false;
    }

    public boolean isSystemPackage(ResolveInfo resolveInfo) {
        return (resolveInfo.activityInfo.applicationInfo.flags & 1) != 0;
    }

    /* access modifiers changed from: private */
    public void requestRetrofit(List<PackageInfo> list) throws Exception {
        String userId = SignalUtil.getUserId(this);
        ArrayList arrayList = new ArrayList();
        for (int i = 0; list.size() > i; i++) {
            UserAppData userAppData = new UserAppData(String.valueOf(getPackageManager().getApplicationLabel(list.get(i).applicationInfo)), String.valueOf(list.get(i).packageName), String.valueOf(list.get(i).versionName), String.valueOf(list.get(i).applicationInfo.targetSdkVersion), String.valueOf(list.get(i).firstInstallTime), String.valueOf(list.get(i).lastUpdateTime));
            arrayList.add(userAppData);
        }
        DatabaseHelperMyAppInfo instance = DatabaseHelperMyAppInfo.getInstance(getApplicationContext());
        try {
            instance.onCreateWithTable(instance.getDB(), DatabaseHelperMyAppInfo.TABLE_NAME);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        instance.addRowList(arrayList);
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this).requestSaveUserApp(new IptUserAppList(userId, arrayList, SignalLibConsts.g_DataChannel)), 1, new Callback<ResponseResult>() {
            public void onResponse(Call<ResponseResult> call, Response<ResponseResult> response) {
                int code = response.code();
                if (code == 200) {
                    ResponseResult responseResult = (ResponseResult) response.body();
                    if (responseResult != null) {
                        String access$000 = JGetUserApplicationListService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$000, sb.toString());
                        JGetUserApplicationListService.this.parseResult(responseResult);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JGetUserApplicationListService.this.TAG, "response : result null");
                    JGetUserApplicationListService.this.stopSelf();
                    return;
                }
                String access$0002 = JGetUserApplicationListService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$0002, sb2.toString());
                JGetUserApplicationListService.this.stopSelf();
            }

            public void onFailure(Call<ResponseResult> call, Throwable th) {
                String access$000 = JGetUserApplicationListService.this.TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("fail : ");
                sb.append(th.toString());
                SignalUtil.PRINT_LOG(access$000, sb.toString());
                JGetUserApplicationListService.this.stopSelf();
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