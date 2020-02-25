package com.embrain.panelbigdata;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.embrain.panelbigdata.Vo.push.BigdataSessionRequest;
import com.embrain.panelbigdata.Vo.token.RegistTokenRequest;
import com.embrain.panelbigdata.common.BigDataCommonVo;
import com.embrain.panelbigdata.db.DBOpenHelper;
import com.embrain.panelbigdata.location.LocationJob;
import com.embrain.panelbigdata.location.LocationStateExt;
import com.embrain.panelbigdata.location.LoplatManager;
import com.embrain.panelbigdata.network.HttpManager;
import com.embrain.panelbigdata.usage.UsageJob;
import com.embrain.panelbigdata.usage.UsageStateExt;
import com.embrain.panelbigdata.utils.LogUtil;
import com.embrain.panelbigdata.utils.PrefUtils;
import com.embrain.panelbigdata.utils.StringUtils;
import com.evernote.android.job.Job;
import com.evernote.android.job.JobCreator;
import com.evernote.android.job.JobManager;
import com.evernote.android.job.JobRequest;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Set;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class EmBigDataManager {
    public static final int CURRENT_LOCATION_POLICY_VERSION = 6;
    public static final int CURRENT_SENDER_POLICY_VERSION = 3;
    public static final int CURRENT_USAGE_POLICY_VERSION = 9;
    private static final long EXECUTE_TRIGGER_DELAY = 60000;
    private static final SimpleDateFormat FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.sss");

    public static class BigdataJobCreator implements JobCreator {
        /* JADX WARNING: Removed duplicated region for block: B:17:0x0037  */
        /* JADX WARNING: Removed duplicated region for block: B:25:0x0049  */
        @Nullable
        public Job create(@NonNull String str) {
            char c;
            int hashCode = str.hashCode();
            if (hashCode != -57964493) {
                if (hashCode != 774475807) {
                    if (hashCode == 997900979 && str.equals(SenderJob.TAG)) {
                        c = 2;
                        if (c != 0) {
                            return new UsageJob();
                        }
                        if (c == 1) {
                            return new LocationJob();
                        }
                        if (c != 2) {
                            return null;
                        }
                        return new SenderJob();
                    }
                } else if (str.equals(UsageJob.TAG)) {
                    c = 0;
                    if (c != 0) {
                    }
                }
            } else if (str.equals(LocationJob.TAG)) {
                c = 1;
                if (c != 0) {
                }
            }
            c = 65535;
            if (c != 0) {
            }
        }
    }

    public static Context getContext() {
        return EmBigdataApplication.getContext();
    }

    public static void initBigdata(String str, String str2, String str3) {
        LogUtil.write("bigdata init values : ");
        StringBuilder sb = new StringBuilder();
        sb.append("panel_id  : ");
        sb.append(str);
        LogUtil.write(sb.toString());
        StringBuilder sb2 = new StringBuilder();
        sb2.append("ad_id  : ");
        sb2.append(str2);
        LogUtil.write(sb2.toString());
        StringBuilder sb3 = new StringBuilder();
        sb3.append("fcm_token  : ");
        sb3.append(str3);
        LogUtil.write(sb3.toString());
        Context context = getContext();
        JobManager.create(context).addJobCreator(new BigdataJobCreator());
        if (!checkDefaultInfo(str, str2, str3)) {
            cancelAllJobs();
            return;
        }
        String panelId = PrefUtils.getPanelId(context);
        String googleADID = PrefUtils.getGoogleADID(context);
        String fcmToken = PrefUtils.getFcmToken(context);
        LogUtil.write("bigdata saved values : ");
        StringBuilder sb4 = new StringBuilder();
        sb4.append("panel_id  : ");
        sb4.append(panelId);
        LogUtil.write(sb4.toString());
        StringBuilder sb5 = new StringBuilder();
        sb5.append("ad_id  : ");
        sb5.append(googleADID);
        LogUtil.write(sb5.toString());
        StringBuilder sb6 = new StringBuilder();
        sb6.append("fcm_token  : ");
        sb6.append(fcmToken);
        LogUtil.write(sb6.toString());
        if (StringUtils.isEmpty(panelId) || StringUtils.isEmpty(googleADID) || StringUtils.isEmpty(fcmToken) || !panelId.equals(str) || !googleADID.equals(str2) || !fcmToken.equals(str3)) {
            requestRegistToken(str, str2, str3);
        } else {
            start(context, false);
        }
    }

    public static void start(Context context, boolean z) {
        if (!z || checkDefaultInfo(PrefUtils.getPanelId(context), PrefUtils.getGoogleADID(context), PrefUtils.getFcmToken(context))) {
            LogUtil.write("EmBigDataManager ======START===============");
            if (!UsageStateExt.canExecute(context)) {
                LogUtil.write("UsageJob can't execute");
                stopUsageJob(context);
            } else if (PrefUtils.getUsagePolicyVersion(context) != 9) {
                LogUtil.write("Usage policy version change");
                startUsageJob(context, true);
            } else {
                startUsageJob(context, false);
            }
            if (LocationStateExt.canExecute(context)) {
                LoplatManager.initLoplatEngine(context, PrefUtils.getPanelId(context));
                LoplatManager.start(context);
                if (PrefUtils.getLocationPolicyVersion(context) != 6) {
                    LogUtil.write("Location policy version change");
                    startLocationJob(context, true);
                } else {
                    startLocationJob(context, false);
                }
            } else {
                LogUtil.write("LocationJob can't execute");
                stopLocationJob(context);
            }
            if (PrefUtils.getSenderPolicyVersion(context) != 3) {
                LogUtil.write("Sender policy version change");
                startSenderJob(context, true);
            } else {
                startSenderJob(context, false);
            }
            LogUtil.write("EmBigDataManager ======START=COMPLETE==========");
        }
    }

    public static boolean checkDefaultInfo(String str, String str2, String str3) {
        if (StringUtils.isEmpty(str)) {
            LogUtil.write("big data init failed. ( panel_id = empty )");
            return false;
        } else if (StringUtils.isEmpty(str2)) {
            LogUtil.write("big data init failed. ( ad_id = empty )");
            return false;
        } else if (!StringUtils.isEmpty(str3)) {
            return true;
        } else {
            LogUtil.write("big data init failed. ( panel_id = fcm_token )");
            return false;
        }
    }

    public static void startSenderJob(Context context, boolean z) {
        if (z) {
            LogUtil.write("EmBigDataManager Senderjob force start");
            stopSenderJob(context);
            SenderJob.schedule(context);
        } else if (!aliveSenderJob(context)) {
            SenderJob.schedule(context);
        } else {
            LogUtil.write("EmBigDataManager Senderjob already executing");
        }
        LogUtil.write("EmBigDataManager.startSenderJob()  === ok ===");
    }

    public static void startUsageJob(Context context, boolean z) {
        LogUtil.write("EmBigDataManager.startUsageJob()");
        if (z) {
            LogUtil.write("EmBigDataManager usagejob force start");
            stopUsageJob(context);
            UsageJob.schedule(context);
        } else if (!aliveUsageJob(context)) {
            UsageJob.schedule(context);
        } else {
            LogUtil.write("EmBigDataManager UsageJob already executing");
        }
        LogUtil.write("EmBigDataManager.startUsageJob()  === ok ===");
    }

    public static void startLocationJob(Context context, boolean z) {
        LogUtil.write("EmBigDataManager.startLocationJob()");
        if (z) {
            LogUtil.write("EmBigDataManager locationjob force start");
            stopLocationJob(context);
            LocationJob.schedule(context);
        } else if (!aliveLocationJob()) {
            LocationJob.schedule(context);
        } else {
            LogUtil.write("EmBigDataManager LocationJob already executing");
        }
        LogUtil.write("EmBigDataManager.startLocationJob()  === ok ===");
    }

    public static boolean aliveSenderJob(Context context) {
        try {
            Set<JobRequest> allJobRequestsForTag = JobManager.instance().getAllJobRequestsForTag(SenderJob.TAG);
            for (JobRequest next : allJobRequestsForTag) {
                StringBuilder sb = new StringBuilder();
                sb.append("Sender job id : ");
                sb.append(next.getJobId());
                LogUtil.write(sb.toString());
                StringBuilder sb2 = new StringBuilder();
                sb2.append("ScheduledAt : ");
                sb2.append(FORMAT.format(new Date(next.getScheduledAt())));
                LogUtil.write(sb2.toString());
                StringBuilder sb3 = new StringBuilder();
                sb3.append("LastRun : ");
                sb3.append(FORMAT.format(new Date(next.getLastRun())));
                LogUtil.write(sb3.toString());
            }
            if (allJobRequestsForTag.size() > 0) {
                return true;
            }
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    public static boolean aliveUsageJob(Context context) {
        try {
            Set<JobRequest> allJobRequestsForTag = JobManager.instance().getAllJobRequestsForTag(UsageJob.TAG);
            for (JobRequest next : allJobRequestsForTag) {
                StringBuilder sb = new StringBuilder();
                sb.append("Usage job id : ");
                sb.append(next.getJobId());
                LogUtil.write(sb.toString());
                StringBuilder sb2 = new StringBuilder();
                sb2.append("ScheduledAt : ");
                sb2.append(FORMAT.format(new Date(next.getScheduledAt())));
                LogUtil.write(sb2.toString());
                StringBuilder sb3 = new StringBuilder();
                sb3.append("LastRun : ");
                sb3.append(FORMAT.format(new Date(next.getLastRun())));
                LogUtil.write(sb3.toString());
            }
            if (allJobRequestsForTag.size() > 0) {
                return true;
            }
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    public static boolean aliveLocationJob() {
        try {
            Set<JobRequest> allJobRequestsForTag = JobManager.instance().getAllJobRequestsForTag(LocationJob.TAG);
            for (JobRequest next : allJobRequestsForTag) {
                StringBuilder sb = new StringBuilder();
                sb.append("Location job id : ");
                sb.append(next.getJobId());
                LogUtil.write(sb.toString());
                StringBuilder sb2 = new StringBuilder();
                sb2.append("ScheduledAt : ");
                sb2.append(FORMAT.format(new Date(next.getScheduledAt())));
                LogUtil.write(sb2.toString());
                StringBuilder sb3 = new StringBuilder();
                sb3.append("LastRun : ");
                sb3.append(FORMAT.format(new Date(next.getLastRun())));
                LogUtil.write(sb3.toString());
            }
            if (allJobRequestsForTag.size() > 0) {
                return true;
            }
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    public static void cancelAllJobs() {
        try {
            int cancelAll = JobManager.instance().cancelAll();
            StringBuilder sb = new StringBuilder();
            sb.append("EmBigDataManager.cancelAllJobs()  === cancel ");
            sb.append(cancelAll);
            sb.append(" jobs ===");
            LogUtil.write(sb.toString());
        } catch (Exception unused) {
            JobManager.create(getContext()).addJobCreator(new BigdataJobCreator());
            int cancelAll2 = JobManager.instance().cancelAll();
            StringBuilder sb2 = new StringBuilder();
            sb2.append("EmBigDataManager.cancelAllJobs()  === cancel ");
            sb2.append(cancelAll2);
            sb2.append(" jobs ===");
            LogUtil.write(sb2.toString());
        }
    }

    public static void stopSenderJob(Context context) {
        LogUtil.write("========  EmBigDataManager.stopSenderJob()  ======== ");
        if (aliveUsageJob(context)) {
            JobManager.instance().cancelAllForTag(SenderJob.TAG);
        }
    }

    public static void stopUsageJob(Context context) {
        LogUtil.write("========  EmBigDataManager.stopUsageJob()  ======== ");
        if (aliveUsageJob(context)) {
            JobManager.instance().cancelAllForTag(UsageJob.TAG);
        }
    }

    public static void stopLocationJob(Context context) {
        LogUtil.write("========  EmBigDataManager.stopLocationJob()  ======== ");
        if (aliveLocationJob()) {
            JobManager.instance().cancelAllForTag(LocationJob.TAG);
        }
        LoplatManager.stop(context);
    }

    public static void setUsageAgree(Context context, boolean z) {
        PrefUtils.setUserAgreeUsage(context, z);
        if (z) {
            startUsageJob(context, false);
        } else {
            stopUsageJob(context);
        }
    }

    public static void setLocationAgree(Context context, boolean z) {
        PrefUtils.setUserAgreeLocation(context, z);
        if (z) {
            startLocationJob(context, false);
        } else {
            stopLocationJob(context);
        }
    }

    public static void setPanelId(Context context, String str) {
        StringBuilder sb = new StringBuilder();
        sb.append("EmBigDataManager.setPanelId : ");
        sb.append(str);
        LogUtil.write(sb.toString());
        String panelId = PrefUtils.getPanelId(context);
        StringBuilder sb2 = new StringBuilder();
        sb2.append("EmBigDataManager saved_panel_id : ");
        sb2.append(panelId);
        LogUtil.write(sb2.toString());
        if (!StringUtils.isEmpty(str) && !str.equals(panelId)) {
            PrefUtils.setPanelId(context, str);
            StringBuilder sb3 = new StringBuilder();
            sb3.append("EmBigDataManager panel_id has change : ");
            sb3.append(str);
            LogUtil.write(sb3.toString());
            requestRegistToken(str, PrefUtils.getGoogleADID(context), PrefUtils.getFcmToken(context));
        }
    }

    public static void setGoogleADID(Context context, String str) {
        StringBuilder sb = new StringBuilder();
        sb.append("EmBigDataManager.setGoogleADID : ");
        sb.append(str);
        LogUtil.write(sb.toString());
        String googleADID = PrefUtils.getGoogleADID(context);
        StringBuilder sb2 = new StringBuilder();
        sb2.append("EmBigDataManager saved_ad_id : ");
        sb2.append(googleADID);
        LogUtil.write(sb2.toString());
        if (!StringUtils.isEmpty(str) && !str.equals(googleADID)) {
            PrefUtils.setGoogleADID(context, str);
            StringBuilder sb3 = new StringBuilder();
            sb3.append("EmBigDataManager ad_id has change : ");
            sb3.append(str);
            LogUtil.write(sb3.toString());
            requestRegistToken(PrefUtils.getPanelId(context), str, PrefUtils.getFcmToken(context));
        }
    }

    public static void setFCMToken(Context context, String str) {
        StringBuilder sb = new StringBuilder();
        sb.append("EmBigDataManager.setFCMToken : ");
        sb.append(str);
        LogUtil.write(sb.toString());
        String fcmToken = PrefUtils.getFcmToken(context);
        StringBuilder sb2 = new StringBuilder();
        sb2.append("EmBigDataManager saved_token : ");
        sb2.append(fcmToken);
        LogUtil.write(sb2.toString());
        if (!StringUtils.isEmpty(str) && !str.equals(fcmToken)) {
            PrefUtils.setFcmToken(context, str);
            StringBuilder sb3 = new StringBuilder();
            sb3.append("EmBigDataManager token has change : ");
            sb3.append(str);
            LogUtil.write(sb3.toString());
            requestRegistToken(PrefUtils.getPanelId(context), PrefUtils.getGoogleADID(context), str);
        }
    }

    private static synchronized void requestRegistToken(final String str, final String str2, final String str3) {
        synchronized (EmBigDataManager.class) {
            LogUtil.write("requestRegistToken ============== ");
            StringBuilder sb = new StringBuilder();
            sb.append("panel_id = ");
            sb.append(str);
            LogUtil.write(sb.toString());
            StringBuilder sb2 = new StringBuilder();
            sb2.append("ad_id = ");
            sb2.append(str2);
            LogUtil.write(sb2.toString());
            StringBuilder sb3 = new StringBuilder();
            sb3.append("token = ");
            sb3.append(str3);
            LogUtil.write(sb3.toString());
            if (StringUtils.isEmpty(str)) {
                LogUtil.write("requestRegistToken ======ERROR==== (panel id is null)");
            } else if (StringUtils.isEmpty(str2)) {
                LogUtil.write("requestRegistToken ======ERROR==== (ad_id id is null)");
            } else if (StringUtils.isEmpty(str3)) {
                LogUtil.write("requestRegistToken ======ERROR==== (token id is null)");
            } else {
                RegistTokenRequest registTokenRequest = new RegistTokenRequest();
                registTokenRequest.panel_id = str;
                registTokenRequest.ad_id = str2;
                registTokenRequest.token = str3;
                HttpManager.getInstance().sendToken(registTokenRequest, new Callback() {
                    public void onFailure(Call call, IOException iOException) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("sendToken.onFailure : ");
                        sb.append(iOException.getMessage());
                        LogUtil.write(sb.toString());
                    }

                    public void onResponse(Call call, Response response) throws IOException {
                        LogUtil.write("requestRegistToken ======END ");
                        if (response.code() == 200) {
                            PrefUtils.setPanelId(EmBigDataManager.getContext(), str);
                            PrefUtils.setGoogleADID(EmBigDataManager.getContext(), str2);
                            PrefUtils.setFcmToken(EmBigDataManager.getContext(), str3);
                            EmBigDataManager.start(EmBigDataManager.getContext(), false);
                        }
                        try {
                            StringBuilder sb = new StringBuilder();
                            sb.append("sendToken.onResponse : ");
                            sb.append(response.body().string());
                            LogUtil.write(sb.toString());
                        } catch (Exception e) {
                            StringBuilder sb2 = new StringBuilder();
                            sb2.append("sendToken.onResponse : ");
                            sb2.append(e.getMessage());
                            LogUtil.write(sb2.toString());
                        }
                    }
                });
            }
        }
    }

    public static void requestBigdataSession(final Context context, String str, String str2, String str3) {
        if (!StringUtils.isEmpty(str2) && !StringUtils.isEmpty(str3)) {
            final BigdataSessionRequest bigdataSessionRequest = new BigdataSessionRequest();
            bigdataSessionRequest.setDeviceInfo(new BigDataCommonVo(context, str2, str3));
            bigdataSessionRequest.setUsageState(new UsageStateExt(context));
            bigdataSessionRequest.setLocationState(new LocationStateExt(context));
            bigdataSessionRequest.setMessageId(str);
            HttpManager.getInstance().sendBigdataSession(bigdataSessionRequest, new Callback() {
                public void onFailure(Call call, IOException iOException) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("requestBigdataSession.onFailure : ");
                    sb.append(iOException.getMessage());
                    LogUtil.write(sb.toString());
                    iOException.printStackTrace();
                    DBOpenHelper.getInstance(context).insertDeviceState(bigdataSessionRequest);
                }

                public void onResponse(Call call, Response response) throws IOException {
                    try {
                        StringBuilder sb = new StringBuilder();
                        sb.append("requestBigdataSession.onResponse : ");
                        sb.append(response.body().string());
                        LogUtil.write(sb.toString());
                    } catch (Exception e) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("requestBigdataSession.onResponse : ");
                        sb2.append(e.getMessage());
                        LogUtil.write(sb2.toString());
                    }
                }
            });
        }
    }
}