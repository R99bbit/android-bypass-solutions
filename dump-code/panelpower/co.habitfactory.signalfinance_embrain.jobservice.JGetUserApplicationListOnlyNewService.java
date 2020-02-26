package co.habitfactory.signalfinance_embrain.jobservice;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.database.SQLException;
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
import co.habitfactory.signalfinance_embrain.retroapi.request.IptUserAppFilteredList;
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

public class JGetUserApplicationListOnlyNewService extends SafeJobIntentService implements SignalLibConsts {
    static final String FILTER_CONTAINS_RULE1 = "com.google.android.gsf.login";
    static final String FILTER_EQUALS_RULE1 = "com.android.providers.telephony";
    static final String FILTER_STARTSWITH_RULE1 = "com.sec.android.";
    static final String FILTER_STARTSWITH_RULE2 = "com.android.";
    static final String FILTER_STARTSWITH_RULE3 = "com.google.";
    static final String FILTER_STARTSWITH_RULE4 = "com.sec.android.";
    static final String FILTER_STARTSWITH_RULE5 = "com.monotype.android.font.";
    static final int JOB_ID = 1021;
    /* access modifiers changed from: private */
    public final String TAG = JGetUserApplicationListOnlyNewService.class.getSimpleName();
    /* access modifiers changed from: private */
    public Context mContext;
    private ArrayList<UserAppData> mDbAppDataList;
    private ArrayList<UserAppData> mNewList;
    private ArrayList<UserAppData> mNowAppList;
    /* access modifiers changed from: private */
    public PackageManager mPackageManager;
    /* access modifiers changed from: private */
    public SignalLibPrefs mPrefs;
    private ArrayList<UserAppData> mRemoveList;
    /* access modifiers changed from: private */
    public OptPushPackageNameList mResult;
    private ArrayList<UserAppData> mUpdateList;

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
            ArrayList<PushPackageName> packageList = JGetUserApplicationListOnlyNewService.this.mResult.getPackageList();
            Boolean valueOf = Boolean.valueOf(false);
            if (packageList == null) {
                return valueOf;
            }
            DatabaseHelperFinanceInfo instance = DatabaseHelperFinanceInfo.getInstance(JGetUserApplicationListOnlyNewService.this.getApplicationContext());
            try {
                instance.onCreateWithTable(instance.getDB(), DatabaseHelperFinanceInfo.TABLE_NAME);
            } catch (SQLException e) {
                e.printStackTrace();
            }
            String access$000 = JGetUserApplicationListOnlyNewService.this.TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("ruialPackageRow size    : ");
            sb.append(packageList.size());
            SignalUtil.PRINT_LOG(access$000, sb.toString());
            Iterator<PushPackageName> it = packageList.iterator();
            while (it.hasNext()) {
                PushPackageName next = it.next();
                FinanceInfoDataSet financeInfoDataSet = new FinanceInfoDataSet("", next.getPackageName());
                try {
                    if (!instance.getRowExist(next.getPackageName()).booleanValue()) {
                        instance.addRow(financeInfoDataSet);
                        String access$0002 = JGetUserApplicationListOnlyNewService.this.TAG;
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("addRow getPackageName    : ");
                        sb2.append(next.getPackageName());
                        SignalUtil.PRINT_LOG(access$0002, sb2.toString());
                    }
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }
            JGetUserApplicationListOnlyNewService jGetUserApplicationListOnlyNewService = JGetUserApplicationListOnlyNewService.this;
            jGetUserApplicationListOnlyNewService.mPackageManager = jGetUserApplicationListOnlyNewService.getPackageManager();
            try {
                list = JGetUserApplicationListOnlyNewService.this.mPackageManager.getInstalledPackages(4096);
            } catch (Exception e3) {
                e3.printStackTrace();
                list = null;
            }
            if (list == null) {
                return valueOf;
            }
            this.mPackageList = new ArrayList();
            ArrayList arrayList = new ArrayList();
            Intent intent = new Intent("android.intent.action.MAIN", null);
            intent.addCategory("android.intent.category.LAUNCHER");
            intent.setFlags(270532608);
            for (ResolveInfo next2 : JGetUserApplicationListOnlyNewService.this.mContext.getPackageManager().queryIntentActivities(intent, 0)) {
                ActivityInfo activityInfo = next2.activityInfo;
                if (!JGetUserApplicationListOnlyNewService.this.isSystemPackage(next2)) {
                    arrayList.add(activityInfo.applicationInfo.packageName);
                }
            }
            for (PackageInfo packageInfo : list) {
                try {
                    String lowerCase = packageInfo.packageName.toLowerCase();
                    if (!JGetUserApplicationListOnlyNewService.this.checkExceptSendAppList(lowerCase)) {
                        if (arrayList.indexOf(lowerCase) > 0) {
                            this.mPackageList.add(packageInfo);
                        }
                    }
                } catch (Exception e4) {
                    e4.printStackTrace();
                }
            }
            return Boolean.valueOf(true);
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(Boolean bool) {
            if (bool.booleanValue()) {
                if (JGetUserApplicationListOnlyNewService.this.mPrefs.getBoolean(SignalLibConsts.PREF_API_GOT_WHITELIST_FROM_API_CHECK, Boolean.valueOf(false)).booleanValue()) {
                    JSmsReceiveNumberOnlyNewService.enqueueWork(JGetUserApplicationListOnlyNewService.this.mContext, new Intent(JGetUserApplicationListOnlyNewService.this.mContext, JSmsReceiveNumberOnlyNewService.class));
                } else {
                    JSmsReceiveNumberService.enqueueWork(JGetUserApplicationListOnlyNewService.this.mContext, new Intent(JGetUserApplicationListOnlyNewService.this.mContext, JSmsReceiveNumberService.class));
                }
                try {
                    if (this.mPackageList.size() > 0) {
                        JGetUserApplicationListOnlyNewService.this.checkMyAppThenRequest(this.mPackageList);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    JGetUserApplicationListOnlyNewService.this.stopSelf();
                }
            } else {
                JGetUserApplicationListOnlyNewService.this.stopSelf();
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
        enqueueWork(context, JGetUserApplicationListOnlyNewService.class, 1021, intent);
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
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this).retrievePushPackageNameOnlyNew(new IptCommon(str)), 1, new Callback<OptPushPackageNameList>() {
            public void onResponse(Call<OptPushPackageNameList> call, Response<OptPushPackageNameList> response) {
                int code = response.code();
                if (code == 200) {
                    OptPushPackageNameList optPushPackageNameList = (OptPushPackageNameList) response.body();
                    if (optPushPackageNameList != null) {
                        String access$000 = JGetUserApplicationListOnlyNewService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$000, sb.toString());
                        JGetUserApplicationListOnlyNewService.this.parseResult(optPushPackageNameList);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JGetUserApplicationListOnlyNewService.this.TAG, "response : result null");
                    JGetUserApplicationListOnlyNewService.this.stopSelf();
                    return;
                }
                String access$0002 = JGetUserApplicationListOnlyNewService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$0002, sb2.toString());
                JGetUserApplicationListOnlyNewService.this.stopSelf();
            }

            public void onFailure(Call<OptPushPackageNameList> call, Throwable th) {
                String access$000 = JGetUserApplicationListOnlyNewService.this.TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("fail : ");
                sb.append(th.toString());
                SignalUtil.PRINT_LOG(access$000, sb.toString());
                JGetUserApplicationListOnlyNewService.this.stopSelf();
            }
        });
    }

    public void parseResult(OptPushPackageNameList optPushPackageNameList) {
        String str = this.TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("resultcode  : ");
        sb.append(optPushPackageNameList.getResultcode());
        SignalUtil.PRINT_LOG(str, sb.toString());
        String str2 = this.TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("message     : ");
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

    private void requestSaveUserAppFiltered(ArrayList<UserAppData> arrayList, ArrayList<UserAppData> arrayList2, ArrayList<UserAppData> arrayList3) throws Exception {
        String userId = SignalUtil.getUserId(this.mContext);
        if (userId.length() < 0) {
            SignalUtil.PRINT_LOG(this.TAG, "userId \uc5c6\uc74c");
            stopSelf();
            return;
        }
        IptUserAppFilteredList iptUserAppFilteredList = new IptUserAppFilteredList(userId, SignalLibConsts.g_DataChannel, arrayList, arrayList2, arrayList3);
        APIHelper.enqueueWithRetry(RestfulAdapter.getInstance(this.mContext).requestSaveUserAppFiltered(iptUserAppFilteredList), 1, new Callback<ResponseResult>() {
            public void onResponse(Call<ResponseResult> call, Response<ResponseResult> response) {
                int code = response.code();
                if (code == 200) {
                    ResponseResult responseResult = (ResponseResult) response.body();
                    if (responseResult != null) {
                        String access$000 = JGetUserApplicationListOnlyNewService.this.TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("response");
                        sb.append(String.valueOf(code));
                        SignalUtil.PRINT_LOG(access$000, sb.toString());
                        JGetUserApplicationListOnlyNewService.this.parseResultSaveUserAppFiltered(responseResult);
                        return;
                    }
                    SignalUtil.PRINT_LOG(JGetUserApplicationListOnlyNewService.this.TAG, "response : result null");
                    JGetUserApplicationListOnlyNewService.this.stopSelf();
                    return;
                }
                String access$0002 = JGetUserApplicationListOnlyNewService.this.TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("response : ");
                sb2.append(String.valueOf(code));
                SignalUtil.PRINT_LOG(access$0002, sb2.toString());
                JGetUserApplicationListOnlyNewService.this.stopSelf();
            }

            public void onFailure(Call<ResponseResult> call, Throwable th) {
                String access$000 = JGetUserApplicationListOnlyNewService.this.TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("fail : ");
                sb.append(th.toString());
                SignalUtil.PRINT_LOG(access$000, sb.toString());
                JGetUserApplicationListOnlyNewService.this.stopSelf();
            }
        });
    }

    public void parseResultSaveUserAppFiltered(ResponseResult responseResult) {
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
        DatabaseHelperMyAppInfo instance = DatabaseHelperMyAppInfo.getInstance(getApplicationContext());
        try {
            instance.onCreateWithTable(instance.getDB(), DatabaseHelperMyAppInfo.TABLE_NAME);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        instance.addRowList(this.mNowAppList);
        stopSelf();
    }

    /* access modifiers changed from: private */
    public void checkMyAppThenRequest(List<PackageInfo> list) {
        boolean z;
        boolean z2;
        List<PackageInfo> list2 = list;
        DatabaseHelperMyAppInfo instance = DatabaseHelperMyAppInfo.getInstance(getApplicationContext());
        try {
            instance.onCreateWithTable(instance.getDB(), DatabaseHelperMyAppInfo.TABLE_NAME);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        this.mDbAppDataList = new ArrayList<>();
        this.mDbAppDataList = instance.getAppDataFromDb();
        this.mNowAppList = new ArrayList<>();
        this.mNewList = new ArrayList<>();
        this.mUpdateList = new ArrayList<>();
        this.mRemoveList = new ArrayList<>();
        for (int i = 0; list.size() > i; i++) {
            String valueOf = String.valueOf(getPackageManager().getApplicationLabel(list2.get(i).applicationInfo));
            String valueOf2 = String.valueOf(list2.get(i).packageName);
            String valueOf3 = String.valueOf(list2.get(i).versionName);
            String valueOf4 = String.valueOf(list2.get(i).applicationInfo.targetSdkVersion);
            String valueOf5 = String.valueOf(list2.get(i).firstInstallTime);
            UserAppData userAppData = r7;
            String valueOf6 = String.valueOf(list2.get(i).lastUpdateTime);
            String str = valueOf5;
            String str2 = valueOf4;
            UserAppData userAppData2 = new UserAppData(valueOf, valueOf2, valueOf3, valueOf4, valueOf5, valueOf6);
            this.mNowAppList.add(userAppData);
            if (this.mDbAppDataList.size() > 0) {
                int i2 = 0;
                while (true) {
                    if (this.mDbAppDataList.size() <= i2) {
                        z2 = false;
                        break;
                    } else if (valueOf2.equals(this.mDbAppDataList.get(i2).getPackageName())) {
                        String apkName = this.mDbAppDataList.get(i2).getApkName();
                        String version = this.mDbAppDataList.get(i2).getVersion();
                        String reqVersion = this.mDbAppDataList.get(i2).getReqVersion();
                        String installed = this.mDbAppDataList.get(i2).getInstalled();
                        String lastModified = this.mDbAppDataList.get(i2).getLastModified();
                        if (!apkName.equals(valueOf) || !version.equals(valueOf3) || !reqVersion.equals(str2) || !installed.equals(str) || !lastModified.equals(valueOf6)) {
                            this.mUpdateList.add(userAppData);
                        }
                        z2 = true;
                    } else {
                        String str3 = valueOf6;
                        String str4 = str;
                        i2++;
                    }
                }
                if (!z2) {
                    this.mNewList.add(userAppData);
                }
            }
        }
        if (this.mDbAppDataList.size() <= 0) {
            SignalUtil.PRINT_LOG(this.TAG, " : db\uc5d0 userApp\ub370\uc774\ud130 \uc5c6\uc74c.");
            instance.addRowList(this.mNowAppList);
            stopSelf();
            return;
        }
        try {
            String str5 = this.TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("dbApp count :");
            sb.append(this.mDbAppDataList.size());
            SignalUtil.PRINT_LOG(str5, sb.toString());
            String str6 = this.TAG;
            StringBuilder sb2 = new StringBuilder();
            sb2.append("nowApp count :");
            sb2.append(list.size());
            SignalUtil.PRINT_LOG(str6, sb2.toString());
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        if (this.mDbAppDataList.size() != list.size()) {
            for (int i3 = 0; this.mDbAppDataList.size() > i3; i3++) {
                String packageName = this.mDbAppDataList.get(i3).getPackageName();
                int i4 = 0;
                while (true) {
                    if (list.size() <= i4) {
                        z = false;
                        break;
                    } else if (String.valueOf(list2.get(i4).packageName).equals(packageName)) {
                        z = true;
                        break;
                    } else {
                        i4++;
                    }
                }
                if (!z) {
                    this.mRemoveList.add(this.mDbAppDataList.get(i3));
                }
            }
        }
        try {
            if (this.mNewList.size() > 0 || this.mUpdateList.size() > 0 || this.mRemoveList.size() > 0) {
                try {
                    String str7 = this.TAG;
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("newList size :");
                    sb3.append(this.mNewList.size());
                    SignalUtil.PRINT_LOG(str7, sb3.toString());
                    String str8 = this.TAG;
                    StringBuilder sb4 = new StringBuilder();
                    sb4.append("updateList size :");
                    sb4.append(this.mUpdateList.size());
                    SignalUtil.PRINT_LOG(str8, sb4.toString());
                    String str9 = this.TAG;
                    StringBuilder sb5 = new StringBuilder();
                    sb5.append("removeList size :");
                    sb5.append(this.mRemoveList.size());
                    SignalUtil.PRINT_LOG(str9, sb5.toString());
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
                requestSaveUserAppFiltered(this.mNewList, this.mUpdateList, this.mRemoveList);
                return;
            }
            SignalUtil.PRINT_LOG(this.TAG, " : \uc720\uc800 \ud328\ud0a4\uc9c0 \ubcc0\ub3d9 \uc5c6\uc74c.");
            stopSelf();
        } catch (Exception e4) {
            e4.printStackTrace();
        }
    }
}