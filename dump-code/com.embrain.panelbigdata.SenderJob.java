package com.embrain.panelbigdata;

import android.content.Context;
import android.os.PowerManager;
import androidx.annotation.NonNull;
import com.embrain.panelbigdata.Vo.location.LocationGpsListRequest;
import com.embrain.panelbigdata.Vo.push.BigdataSessionListRequest;
import com.embrain.panelbigdata.Vo.usage.UsageInsertRequest;
import com.embrain.panelbigdata.db.DBOpenHelper;
import com.embrain.panelbigdata.network.HttpManager;
import com.embrain.panelbigdata.utils.LogUtil;
import com.embrain.panelbigdata.utils.PrefUtils;
import com.evernote.android.job.Job;
import com.evernote.android.job.Job.Params;
import com.evernote.android.job.Job.Result;
import com.evernote.android.job.JobManager;
import com.evernote.android.job.JobRequest.Builder;
import com.evernote.android.job.JobRequest.NetworkType;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class SenderJob extends Job {
    public static final String TAG = "sender_job";
    private static Context mContext;

    public static void schedule(Context context) {
        JobManager.instance().cancelAllForTag(TAG);
        new Builder((String) TAG).setPeriodic(TimeUnit.HOURS.toMillis(2)).setUpdateCurrent(true).setRequiredNetworkType(NetworkType.ANY).build().schedule();
        PrefUtils.setSenderPolicyVersion(context, 3);
        LogUtil.write("SenderJob : schedule()");
    }

    /* access modifiers changed from: protected */
    @NonNull
    public Result onRunJob(@NonNull Params params) {
        LogUtil.write("SenderJob : onRunJob()");
        PowerManager powerManager = (PowerManager) getContext().getSystemService("power");
        StringBuilder sb = new StringBuilder();
        sb.append("SenderJob : Power save mode : ");
        sb.append(powerManager.isPowerSaveMode());
        LogUtil.write(sb.toString());
        if (powerManager.isPowerSaveMode()) {
            return Result.SUCCESS;
        }
        sendGPS();
        sendDeviceState();
        sendUsage(getContext());
        return Result.SUCCESS;
    }

    private void sendGPS() {
        LocationGpsListRequest locationGpsListRequest = new LocationGpsListRequest();
        locationGpsListRequest.list = DBOpenHelper.getInstance(getContext()).getAllGpsState();
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("SenderJob : GPS STATE SIZE : ");
            sb.append(locationGpsListRequest.list.size());
            LogUtil.write(sb.toString());
            if (locationGpsListRequest.list.size() > 0) {
                HttpManager.getInstance().sendGpsStateList(locationGpsListRequest, new Callback() {
                    public void onFailure(Call call, IOException iOException) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("sendGpsState.onFailure : ");
                        sb.append(iOException.getMessage());
                        LogUtil.write(sb.toString());
                    }

                    public void onResponse(Call call, Response response) throws IOException {
                        if (response.code() == 200) {
                            DBOpenHelper.getInstance(SenderJob.this.getContext()).clearTableGPS();
                            LogUtil.write("sendGpsState.onResponse : ");
                        }
                    }
                });
            }
        } catch (Exception e) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("gps request error : ");
            sb2.append(e.getMessage());
            LogUtil.write(sb2.toString());
            e.printStackTrace();
        }
    }

    private void sendDeviceState() {
        BigdataSessionListRequest bigdataSessionListRequest = new BigdataSessionListRequest();
        bigdataSessionListRequest.list = DBOpenHelper.getInstance(getContext()).getAllDeviceState();
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("SenderJob : DEVICE STATE SIZE : ");
            sb.append(bigdataSessionListRequest.list.size());
            LogUtil.write(sb.toString());
            if (bigdataSessionListRequest.list.size() > 0) {
                HttpManager.getInstance().sendBigdataSessionList(bigdataSessionListRequest, new Callback() {
                    public void onFailure(Call call, IOException iOException) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("sendBigdataSessionList.onFailure : ");
                        sb.append(iOException.getMessage());
                        LogUtil.write(sb.toString());
                    }

                    public void onResponse(Call call, Response response) throws IOException {
                        if (response.code() == 200) {
                            DBOpenHelper.getInstance(SenderJob.this.getContext()).clearTableDeviceState();
                            LogUtil.write("sendBigdataSessionList.onResponse : ");
                        }
                    }
                });
            }
        } catch (Exception e) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("device request error : ");
            sb2.append(e.getMessage());
            LogUtil.write(sb2.toString());
            e.printStackTrace();
        }
    }

    public static void sendUsage(final Context context) {
        try {
            UsageInsertRequest usageItem = DBOpenHelper.getInstance(context).getUsageItem();
            if (usageItem.getAppList().size() > 0 || usageItem.getDailyUsageList().size() > 0) {
                HttpManager.getInstance().sendUsageInfo(usageItem, new Callback() {
                    public void onFailure(Call call, IOException iOException) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("sendUsageInfo.onFailure : ");
                        sb.append(iOException.getMessage());
                        LogUtil.write(sb.toString());
                    }

                    public void onResponse(Call call, Response response) throws IOException {
                        if (response.code() == 200) {
                            DBOpenHelper.getInstance(context).clearTableAppList();
                            DBOpenHelper.getInstance(context).clearTableUsage();
                            LogUtil.write("sendUsageInfo.onResponse : ");
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
            }
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder();
            sb.append("usage request error : ");
            sb.append(e.getMessage());
            LogUtil.write(sb.toString());
            e.printStackTrace();
        }
    }
}