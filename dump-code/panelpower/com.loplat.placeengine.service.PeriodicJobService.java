package com.loplat.placeengine.service;

import a.b.a.a.a.b;
import android.app.job.JobInfo.Builder;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.os.Build.VERSION;
import androidx.annotation.RequiresApi;

@RequiresApi(26)
public class PeriodicJobService extends JobService {

    /* renamed from: a reason: collision with root package name */
    public static final String f58a = "PeriodicJobService";
    public Context b;

    public static void a(Context context, int i, long j) {
        String str = f58a;
        StringBuilder sb = new StringBuilder();
        sb.append("scheduleJob: ");
        sb.append(i);
        new Object[1][0] = sb.toString();
        try {
            JobScheduler jobScheduler = (JobScheduler) context.getSystemService("jobscheduler");
            if (jobScheduler != null) {
                String str2 = f58a;
                Object[] objArr = new Object[1];
                StringBuilder sb2 = new StringBuilder();
                sb2.append("setScheduleJob: ");
                sb2.append(((float) j) / 60000.0f);
                sb2.append(", sdk: ");
                sb2.append(VERSION.SDK_INT);
                objArr[0] = sb2.toString();
                Builder builder = new Builder(i, new ComponentName(context, PeriodicJobService.class));
                builder.setMinimumLatency(j);
                jobScheduler.schedule(builder.build());
            }
        } catch (Exception unused) {
        }
    }

    public static void b(Context context) {
        String str = f58a;
        new Object[1][0] = "startKeepAliveCheckJob";
        try {
            JobScheduler jobScheduler = (JobScheduler) context.getSystemService("jobscheduler");
            if (jobScheduler != null) {
                Builder builder = new Builder(28867, new ComponentName(context, PeriodicJobService.class));
                builder.setMinimumLatency(120000);
                jobScheduler.schedule(builder.build());
            }
        } catch (Exception unused) {
        }
    }

    public static void c(Context context) {
        try {
            JobScheduler jobScheduler = (JobScheduler) context.getSystemService("jobscheduler");
            if (jobScheduler != null && jobScheduler.getPendingJob(28867) != null) {
                String str = f58a;
                new Object[1][0] = "stopKeepAliveCheckJob";
                jobScheduler.cancel(28867);
            }
        } catch (Exception unused) {
        }
    }

    public void onCreate() {
        super.onCreate();
        this.b = getApplicationContext();
    }

    public void onDestroy() {
        super.onDestroy();
    }

    public boolean onStartJob(JobParameters jobParameters) {
        int jobId = jobParameters.getJobId();
        String str = f58a;
        StringBuilder sb = new StringBuilder();
        sb.append("on start job: ");
        sb.append(jobId);
        new Object[1][0] = sb.toString();
        if (jobId == 28867) {
            b(this.b);
        } else if (jobId == 181029) {
            b.a(this.b).d();
        }
        return false;
    }

    public boolean onStopJob(JobParameters jobParameters) {
        return false;
    }

    public static void a(Context context) {
        try {
            JobScheduler jobScheduler = (JobScheduler) context.getSystemService("jobscheduler");
            if (jobScheduler != null && jobScheduler.getPendingJob(28867) == null) {
                String str = f58a;
                new Object[1][0] = "re-startKeepAliveCheckJob";
                b(context);
            }
        } catch (Exception unused) {
        }
    }
}