package com.embrain.panelbigdata.usage;

import android.app.AppOpsManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build.VERSION;
import androidx.annotation.NonNull;
import com.embrain.panelbigdata.Vo.usage.UsageInsertRequest;
import com.embrain.panelbigdata.db.DBOpenHelper;
import com.embrain.panelbigdata.network.HttpManager;
import com.embrain.panelbigdata.utils.LogUtil;
import com.embrain.panelbigdata.utils.PrefUtils;
import com.embrain.panelbigdata.utils.StringUtils;
import com.evernote.android.job.DailyJob;
import com.evernote.android.job.DailyJob.DailyJobResult;
import com.evernote.android.job.Job.Params;
import com.evernote.android.job.JobManager;
import com.evernote.android.job.JobRequest.Builder;
import com.evernote.android.job.JobRequest.NetworkType;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class UsageJob extends DailyJob {
    private static final int MAX_GROUP_DELAY = 900000;
    public static final String TAG = "usage_job";

    public static void schedule(Context context) {
        JobManager.instance().cancelAllForTag(TAG);
        setJobIdUsage(context, DailyJob.schedule(new Builder((String) TAG).setRequiredNetworkType(NetworkType.ANY).setUpdateCurrent(true), TimeUnit.MINUTES.toMillis(1), TimeUnit.HOURS.toMillis(1)));
        PrefUtils.setUsagePolicyVersion(context, 9);
        LogUtil.write("UsageJob : schedule()");
    }

    private static long getTimeMs() {
        Calendar instance = Calendar.getInstance();
        return TimeUnit.HOURS.toMillis((long) instance.get(11)) + TimeUnit.MINUTES.toMillis((long) (instance.get(12) + 1));
    }

    private static void setJobIdUsage(Context context, int i) {
        PrefUtils.setJobIdUsage(context, i);
    }

    /* access modifiers changed from: protected */
    @NonNull
    public DailyJobResult onRunDailyJob(@NonNull Params params) {
        LogUtil.write("UsageJob : onRunDailyJob()");
        if (checkPermission()) {
            sendUsage();
        }
        return DailyJobResult.SUCCESS;
    }

    private boolean sendUsage() {
        Context context = getContext();
        String panelId = PrefUtils.getPanelId(context);
        String googleADID = PrefUtils.getGoogleADID(context);
        String fcmToken = PrefUtils.getFcmToken(context);
        if (StringUtils.isEmpty(panelId)) {
            LogUtil.write("Not Login ");
            return false;
        }
        final UsageInsertRequest usageInfo = UStats.getUsageInfo(context, panelId, googleADID, fcmToken, PrefUtils.getUsageLastSendDate(context));
        try {
            HttpManager.getInstance().sendUsageInfo(usageInfo, new Callback() {
                public void onFailure(Call call, IOException iOException) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("sendUsageInfo.onFailure : ");
                    sb.append(iOException.getMessage());
                    LogUtil.write(sb.toString());
                    DBOpenHelper.getInstance(UsageJob.this.getContext()).insertAppUsage(usageInfo);
                    PrefUtils.setUsageLastSendDate(UsageJob.this.getContext(), new Date().getTime());
                }

                public void onResponse(Call call, Response response) throws IOException {
                    if (response.code() == 200) {
                        PrefUtils.setUsageLastSendDate(UsageJob.this.getContext(), new Date().getTime());
                    }
                    try {
                        StringBuilder sb = new StringBuilder();
                        sb.append("sendUsageInfo.onResponse : ");
                        sb.append(response.body().string());
                        LogUtil.write(sb.toString());
                    } catch (Exception e) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("sendUsageInfo.onResponse : ");
                        sb2.append(e.getMessage());
                        LogUtil.write(sb2.toString());
                    }
                }
            });
            LogUtil.write("============================================================");
            return true;
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder();
            sb.append("usage request error : ");
            sb.append(e.getMessage());
            LogUtil.write(sb.toString());
            e.printStackTrace();
            return false;
        }
    }

    private void threadSleep(long j) {
        try {
            long currentTimeMillis = System.currentTimeMillis();
            StringBuilder sb = new StringBuilder();
            sb.append("UsageTask sleep : ");
            sb.append(j);
            LogUtil.write(sb.toString());
            Thread.sleep(j);
            StringBuilder sb2 = new StringBuilder();
            sb2.append("UsageTask sleep complete : start from - ");
            sb2.append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.sss").format(Long.valueOf(currentTimeMillis)));
            LogUtil.write(sb2.toString());
        } catch (InterruptedException e) {
            e.printStackTrace();
            StringBuilder sb3 = new StringBuilder();
            sb3.append("UsageTask sleep InterruptedException() : ");
            sb3.append(e.getMessage());
            LogUtil.write(sb3.toString());
        }
    }

    private boolean checkPermission() {
        try {
            Context context = getContext();
            ApplicationInfo applicationInfo = context.getPackageManager().getApplicationInfo(context.getPackageName(), 0);
            if ((VERSION.SDK_INT > 19 ? ((AppOpsManager) context.getSystemService("appops")).checkOpNoThrow("android:get_usage_stats", applicationInfo.uid, applicationInfo.packageName) : 0) == 0) {
                return true;
            }
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    private static long getDelayByPanelId(String str) {
        try {
            return (long) (Integer.parseInt(str.substring(str.length() - 1)) * MAX_GROUP_DELAY);
        } catch (Exception unused) {
            return 0;
        }
    }

    private static long getTimeDelay() {
        return (long) new Random().nextInt(MAX_GROUP_DELAY);
    }
}