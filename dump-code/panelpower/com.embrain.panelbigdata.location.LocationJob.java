package com.embrain.panelbigdata.location;

import android.content.Context;
import android.location.Location;
import android.location.LocationManager;
import android.os.Build.VERSION;
import androidx.annotation.NonNull;
import com.embrain.panelbigdata.Vo.location.LocationGpsRequest;
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
import com.loplat.placeengine.Plengi;
import java.io.IOException;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class LocationJob extends Job {
    public static final String TAG = "location_job";
    private static Context mContext;

    public static void schedule(Context context) {
        JobManager.instance().cancelAllForTag(TAG);
        setJobIdLocation(context, new Builder((String) TAG).setPeriodic(TimeUnit.HOURS.toMillis(1)).setUpdateCurrent(true).setRequiredNetworkType(NetworkType.ANY).build().schedule());
        PrefUtils.setLocationPolicyVersion(context, 6);
        LogUtil.write("LocationJob : schedule()");
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x003f, code lost:
        if (r0 != 2) goto L_0x0056;
     */
    @NonNull
    public Result onRunJob(@NonNull Params params) {
        if (mContext == null) {
            mContext = getContext();
        }
        LogUtil.write("location job  : onRunJob() ");
        String panelId = PrefUtils.getPanelId(mContext);
        if (panelId == null || "".equals(panelId)) {
            LogUtil.write("location job not operate : Not Login");
            return Result.SUCCESS;
        } else if (!checkPermission()) {
            LogUtil.write("location job not operate : no have permission");
            return Result.SUCCESS;
        } else {
            int engineStatus = Plengi.getInstance(mContext).getEngineStatus();
            if (engineStatus == -1) {
                LoplatManager.initLoplatEngine(mContext, panelId);
                LogUtil.write("Loplat SDK NOT INITIALIZED : init ok");
            } else if (engineStatus != 0) {
            }
            LoplatManager.start(mContext);
            LogUtil.write("Loplat SDK STOPPED : start ok");
            final LocationGpsRequest locationGpsRequest = new LocationGpsRequest(getContext());
            locationGpsRequest.gps_state = LocationStateExt.getGpsState(getContext());
            locationGpsRequest.execute_time = new Date().getTime();
            try {
                Location lastKnownLocation = ((LocationManager) getContext().getSystemService("location")).getLastKnownLocation("gps");
                locationGpsRequest.lat = lastKnownLocation.getLatitude();
                locationGpsRequest.lng = lastKnownLocation.getLongitude();
            } catch (Exception unused) {
            }
            HttpManager.getInstance().sendGpsState(locationGpsRequest, new Callback() {
                public void onFailure(Call call, IOException iOException) {
                    DBOpenHelper.getInstance(LocationJob.this.getContext()).insertGpsState(locationGpsRequest);
                    StringBuilder sb = new StringBuilder();
                    sb.append("sendGpsState.onFailure : ");
                    sb.append(iOException.getMessage());
                    LogUtil.write(sb.toString());
                }

                public void onResponse(Call call, Response response) throws IOException {
                    try {
                        StringBuilder sb = new StringBuilder();
                        sb.append("sendGpsState.onResponse : ");
                        sb.append(response.body().string());
                        LogUtil.write(sb.toString());
                    } catch (Exception e) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("sendGpsState.onResponse : ");
                        sb2.append(e.getMessage());
                        LogUtil.write(sb2.toString());
                    }
                }
            });
            LogUtil.write("Loplat SDK state check complete");
            return Result.SUCCESS;
        }
    }

    private static void setJobIdLocation(Context context, int i) {
        PrefUtils.setJobIdLocation(context, i);
    }

    private boolean checkPermission() {
        if (VERSION.SDK_INT >= 23) {
            int checkSelfPermission = mContext.checkSelfPermission("android.permission.ACCESS_FINE_LOCATION");
            int checkSelfPermission2 = mContext.checkSelfPermission("android.permission.ACCESS_COARSE_LOCATION");
            if (checkSelfPermission == 0 && checkSelfPermission2 == 0) {
                return true;
            }
            LogUtil.write("location job not operate : Need permission");
            return false;
        } else if (VERSION.SDK_INT >= 21) {
            return true;
        } else {
            LogUtil.write("location job not operate : Not support O/S version(under LOLLIPOP)");
            return false;
        }
    }
}