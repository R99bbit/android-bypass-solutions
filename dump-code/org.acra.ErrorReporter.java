package org.acra;

import android.app.Activity;
import android.app.Application;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import android.os.Looper;
import android.os.Process;
import android.text.format.Time;
import android.util.Log;
import java.io.File;
import java.lang.Thread.UncaughtExceptionHandler;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.acra.collector.Compatibility;
import org.acra.collector.ConfigurationCollector;
import org.acra.collector.CrashReportData;
import org.acra.collector.CrashReportDataFactory;
import org.acra.jraf.android.util.activitylifecyclecallbackscompat.ActivityLifecycleCallbacksCompat;
import org.acra.jraf.android.util.activitylifecyclecallbackscompat.ApplicationHelper;
import org.acra.log.ACRALog;
import org.acra.sender.EmailIntentSender;
import org.acra.sender.GoogleFormSender;
import org.acra.sender.HttpSender;
import org.acra.sender.ReportSender;
import org.acra.util.PackageManagerWrapper;
import org.acra.util.ToastSender;

public class ErrorReporter implements UncaughtExceptionHandler {
    private static int mNotificationCounter = 0;
    /* access modifiers changed from: private */
    public static boolean toastWaitEnded = true;
    private Thread brokenThread;
    private final CrashReportDataFactory crashReportDataFactory;
    private boolean enabled = false;
    private final CrashReportFileNameParser fileNameParser = new CrashReportFileNameParser();
    /* access modifiers changed from: private */
    public transient Activity lastActivityCreated;
    /* access modifiers changed from: private */
    public final Application mContext;
    private final UncaughtExceptionHandler mDfltExceptionHandler;
    private final List<ReportSender> mReportSenders = new ArrayList();
    private final SharedPreferences prefs;
    private Throwable unhandledThrowable;

    ErrorReporter(Application application, SharedPreferences sharedPreferences, boolean z) {
        this.mContext = application;
        this.prefs = sharedPreferences;
        this.enabled = z;
        String collectConfiguration = ConfigurationCollector.collectConfiguration(this.mContext);
        Time time = new Time();
        time.setToNow();
        if (Compatibility.getAPILevel() >= 14) {
            ApplicationHelper.registerActivityLifecycleCallbacks(application, new ActivityLifecycleCallbacksCompat() {
                public void onActivityDestroyed(Activity activity) {
                }

                public void onActivityPaused(Activity activity) {
                }

                public void onActivityResumed(Activity activity) {
                }

                public void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
                }

                public void onActivityStarted(Activity activity) {
                }

                public void onActivityStopped(Activity activity) {
                }

                public void onActivityCreated(Activity activity, Bundle bundle) {
                    if (!(activity instanceof CrashReportDialog)) {
                        ErrorReporter.this.lastActivityCreated = activity;
                    }
                }
            });
        }
        this.crashReportDataFactory = new CrashReportDataFactory(this.mContext, sharedPreferences, time, collectConfiguration);
        this.mDfltExceptionHandler = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(this);
        checkReportsOnApplicationStart();
    }

    public static ErrorReporter getInstance() {
        return ACRA.getErrorReporter();
    }

    @Deprecated
    public void addCustomData(String str, String str2) {
        this.crashReportDataFactory.putCustomData(str, str2);
    }

    public String putCustomData(String str, String str2) {
        return this.crashReportDataFactory.putCustomData(str, str2);
    }

    public String removeCustomData(String str) {
        return this.crashReportDataFactory.removeCustomData(str);
    }

    public String getCustomData(String str) {
        return this.crashReportDataFactory.getCustomData(str);
    }

    public void addReportSender(ReportSender reportSender) {
        this.mReportSenders.add(reportSender);
    }

    public void removeReportSender(ReportSender reportSender) {
        this.mReportSenders.remove(reportSender);
    }

    public void removeReportSenders(Class<?> cls) {
        if (ReportSender.class.isAssignableFrom(cls)) {
            for (ReportSender next : this.mReportSenders) {
                if (cls.isInstance(next)) {
                    this.mReportSenders.remove(next);
                }
            }
        }
    }

    public void removeAllReportSenders() {
        this.mReportSenders.clear();
    }

    public void setReportSender(ReportSender reportSender) {
        removeAllReportSenders();
        addReportSender(reportSender);
    }

    public void uncaughtException(Thread thread, Throwable th) {
        try {
            if (!this.enabled) {
                if (this.mDfltExceptionHandler != null) {
                    String str = ACRA.LOG_TAG;
                    StringBuilder sb = new StringBuilder();
                    sb.append("ACRA is disabled for ");
                    sb.append(this.mContext.getPackageName());
                    sb.append(" - forwarding uncaught Exception on to default ExceptionHandler");
                    Log.e(str, sb.toString());
                    this.mDfltExceptionHandler.uncaughtException(thread, th);
                } else {
                    String str2 = ACRA.LOG_TAG;
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("ACRA is disabled for ");
                    sb2.append(this.mContext.getPackageName());
                    sb2.append(" - no default ExceptionHandler");
                    Log.e(str2, sb2.toString());
                }
                return;
            }
            this.brokenThread = thread;
            this.unhandledThrowable = th;
            String str3 = ACRA.LOG_TAG;
            StringBuilder sb3 = new StringBuilder();
            sb3.append("ACRA caught a ");
            sb3.append(th.getClass().getSimpleName());
            sb3.append(" exception for ");
            sb3.append(this.mContext.getPackageName());
            sb3.append(". Building report.");
            Log.e(str3, sb3.toString());
            handleException(th, ACRA.getConfig().mode(), false, true);
        } catch (Throwable unused) {
            UncaughtExceptionHandler uncaughtExceptionHandler = this.mDfltExceptionHandler;
            if (uncaughtExceptionHandler != null) {
                uncaughtExceptionHandler.uncaughtException(thread, th);
            }
        }
    }

    /* access modifiers changed from: private */
    public void endApplication() {
        if (ACRA.getConfig().mode() == ReportingInteractionMode.SILENT || (ACRA.getConfig().mode() == ReportingInteractionMode.TOAST && ACRA.getConfig().forceCloseDialogAfterToast())) {
            this.mDfltExceptionHandler.uncaughtException(this.brokenThread, this.unhandledThrowable);
            return;
        }
        String str = ACRA.LOG_TAG;
        StringBuilder sb = new StringBuilder();
        sb.append(this.mContext.getPackageName());
        sb.append(" fatal error : ");
        sb.append(this.unhandledThrowable.getMessage());
        Log.e(str, sb.toString(), this.unhandledThrowable);
        if (this.lastActivityCreated != null) {
            Log.i(ACRA.LOG_TAG, "Finishing the last Activity prior to killing the Process");
            this.lastActivityCreated.finish();
            String str2 = ACRA.LOG_TAG;
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Finished ");
            sb2.append(this.lastActivityCreated.getClass());
            Log.i(str2, sb2.toString());
            this.lastActivityCreated = null;
        }
        Process.killProcess(Process.myPid());
        System.exit(10);
    }

    public void handleSilentException(Throwable th) {
        if (this.enabled) {
            handleException(th, ReportingInteractionMode.SILENT, true, false);
            Log.d(ACRA.LOG_TAG, "ACRA sent Silent report.");
            return;
        }
        Log.d(ACRA.LOG_TAG, "ACRA is disabled. Silent report not sent.");
    }

    public void setEnabled(boolean z) {
        String str = ACRA.LOG_TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("ACRA is ");
        sb.append(z ? "enabled" : "disabled");
        sb.append(" for ");
        sb.append(this.mContext.getPackageName());
        Log.i(str, sb.toString());
        this.enabled = z;
    }

    /* access modifiers changed from: 0000 */
    public SendWorker startSendingReports(boolean z, boolean z2) {
        SendWorker sendWorker = new SendWorker(this.mContext, this.mReportSenders, z, z2);
        sendWorker.start();
        return sendWorker;
    }

    /* access modifiers changed from: 0000 */
    public void deletePendingReports() {
        deletePendingReports(true, true, 0);
    }

    public void checkReportsOnApplicationStart() {
        long j = (long) this.prefs.getInt(ACRA.PREF_LAST_VERSION_NR, 0);
        PackageInfo packageInfo = new PackageManagerWrapper(this.mContext).getPackageInfo();
        if (packageInfo != null && ((long) packageInfo.versionCode) > j) {
            if (ACRA.getConfig().deleteOldUnsentReportsOnApplicationStart()) {
                deletePendingReports();
            }
            Editor edit = this.prefs.edit();
            edit.putInt(ACRA.PREF_LAST_VERSION_NR, packageInfo.versionCode);
            edit.commit();
        }
        if ((ACRA.getConfig().mode() == ReportingInteractionMode.NOTIFICATION || ACRA.getConfig().mode() == ReportingInteractionMode.DIALOG) && ACRA.getConfig().deleteUnapprovedReportsOnApplicationStart()) {
            deletePendingNonApprovedReports(true);
        }
        CrashReportFinder crashReportFinder = new CrashReportFinder(this.mContext);
        String[] crashReportFiles = crashReportFinder.getCrashReportFiles();
        if (crashReportFiles != null && crashReportFiles.length > 0) {
            ReportingInteractionMode mode = ACRA.getConfig().mode();
            String[] crashReportFiles2 = crashReportFinder.getCrashReportFiles();
            boolean containsOnlySilentOrApprovedReports = containsOnlySilentOrApprovedReports(crashReportFiles2);
            if (mode == ReportingInteractionMode.SILENT || mode == ReportingInteractionMode.TOAST || (containsOnlySilentOrApprovedReports && (mode == ReportingInteractionMode.NOTIFICATION || mode == ReportingInteractionMode.DIALOG))) {
                if (mode == ReportingInteractionMode.TOAST && !containsOnlySilentOrApprovedReports) {
                    ToastSender.sendToast(this.mContext, ACRA.getConfig().resToastText(), 1);
                }
                Log.v(ACRA.LOG_TAG, "About to start ReportSenderWorker from #checkReportOnApplicationStart");
                startSendingReports(false, false);
            } else if (ACRA.getConfig().mode() == ReportingInteractionMode.NOTIFICATION) {
                notifySendReport(getLatestNonSilentReport(crashReportFiles2));
            } else {
                ACRA.getConfig().mode();
                ReportingInteractionMode reportingInteractionMode = ReportingInteractionMode.DIALOG;
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void deletePendingNonApprovedReports(boolean z) {
        deletePendingReports(false, true, z ? 1 : 0);
    }

    public void handleException(Throwable th, boolean z) {
        handleException(th, ACRA.getConfig().mode(), false, z);
    }

    public void handleException(Throwable th) {
        handleException(th, ACRA.getConfig().mode(), false, false);
    }

    /* JADX WARNING: Removed duplicated region for block: B:13:0x0027  */
    /* JADX WARNING: Removed duplicated region for block: B:25:0x004a  */
    /* JADX WARNING: Removed duplicated region for block: B:38:0x008f  */
    private void handleException(Throwable th, ReportingInteractionMode reportingInteractionMode, boolean z, boolean z2) {
        boolean z3;
        boolean z4;
        if (this.enabled) {
            if (reportingInteractionMode == null) {
                reportingInteractionMode = ACRA.getConfig().mode();
            } else if (reportingInteractionMode == ReportingInteractionMode.SILENT && ACRA.getConfig().mode() != ReportingInteractionMode.SILENT) {
                z3 = true;
                if (th == null) {
                    th = new Exception("Report requested by developer");
                }
                z4 = reportingInteractionMode != ReportingInteractionMode.TOAST || (ACRA.getConfig().resToastText() != 0 && (reportingInteractionMode == ReportingInteractionMode.NOTIFICATION || reportingInteractionMode == ReportingInteractionMode.DIALOG));
                if (z4) {
                    new Thread() {
                        public void run() {
                            Looper.prepare();
                            ToastSender.sendToast(ErrorReporter.this.mContext, ACRA.getConfig().resToastText(), 1);
                            Looper.loop();
                        }
                    }.start();
                }
                CrashReportData createCrashData = this.crashReportDataFactory.createCrashData(th, z, this.brokenThread);
                final String reportFileName = getReportFileName(createCrashData);
                saveCrashReportFile(reportFileName, createCrashData);
                SendWorker sendWorker = null;
                if (reportingInteractionMode != ReportingInteractionMode.SILENT || reportingInteractionMode == ReportingInteractionMode.TOAST || this.prefs.getBoolean(ACRA.PREF_ALWAYS_ACCEPT, false)) {
                    Log.d(ACRA.LOG_TAG, "About to start ReportSenderWorker from #handleException");
                    sendWorker = startSendingReports(z3, true);
                } else if (reportingInteractionMode == ReportingInteractionMode.NOTIFICATION) {
                    Log.d(ACRA.LOG_TAG, "Notification will be created on application start.");
                }
                final SendWorker sendWorker2 = sendWorker;
                if (z4) {
                    toastWaitEnded = false;
                    new Thread() {
                        public void run() {
                            Time time = new Time();
                            Time time2 = new Time();
                            time.setToNow();
                            long millis = time.toMillis(false);
                            for (long j = 0; j < 3000; j = time2.toMillis(false) - millis) {
                                try {
                                    Thread.sleep(3000);
                                } catch (InterruptedException e) {
                                    Log.d(ACRA.LOG_TAG, "Interrupted while waiting for Toast to end.", e);
                                }
                                time2.setToNow();
                            }
                            ErrorReporter.toastWaitEnded = true;
                        }
                    }.start();
                }
                final boolean z5 = reportingInteractionMode != ReportingInteractionMode.DIALOG && !this.prefs.getBoolean(ACRA.PREF_ALWAYS_ACCEPT, false);
                final boolean z6 = z2;
                AnonymousClass4 r4 = new Thread() {
                    public void run() {
                        Log.d(ACRA.LOG_TAG, "Waiting for Toast + worker...");
                        while (true) {
                            if (ErrorReporter.toastWaitEnded) {
                                SendWorker sendWorker = sendWorker2;
                                if (sendWorker == null || !sendWorker.isAlive()) {
                                }
                            }
                            try {
                                Thread.sleep(100);
                            } catch (InterruptedException e) {
                                Log.e(ACRA.LOG_TAG, "Error : ", e);
                            }
                        }
                        if (z5) {
                            Log.d(ACRA.LOG_TAG, "About to create DIALOG from #handleException");
                            ErrorReporter.this.notifyDialog(reportFileName);
                        }
                        String str = ACRA.LOG_TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("Wait for Toast + worker ended. Kill Application ? ");
                        sb.append(z6);
                        Log.d(str, sb.toString());
                        if (z6) {
                            ErrorReporter.this.endApplication();
                        }
                    }
                };
                r4.start();
            }
            z3 = false;
            if (th == null) {
            }
            if (reportingInteractionMode != ReportingInteractionMode.TOAST) {
            }
            if (z4) {
            }
            CrashReportData createCrashData2 = this.crashReportDataFactory.createCrashData(th, z, this.brokenThread);
            final String reportFileName2 = getReportFileName(createCrashData2);
            saveCrashReportFile(reportFileName2, createCrashData2);
            SendWorker sendWorker3 = null;
            if (reportingInteractionMode != ReportingInteractionMode.SILENT) {
            }
            Log.d(ACRA.LOG_TAG, "About to start ReportSenderWorker from #handleException");
            sendWorker3 = startSendingReports(z3, true);
            final SendWorker sendWorker22 = sendWorker3;
            if (z4) {
            }
            if (reportingInteractionMode != ReportingInteractionMode.DIALOG) {
            }
            final boolean z62 = z2;
            AnonymousClass4 r42 = new Thread() {
                public void run() {
                    Log.d(ACRA.LOG_TAG, "Waiting for Toast + worker...");
                    while (true) {
                        if (ErrorReporter.toastWaitEnded) {
                            SendWorker sendWorker = sendWorker22;
                            if (sendWorker == null || !sendWorker.isAlive()) {
                            }
                        }
                        try {
                            Thread.sleep(100);
                        } catch (InterruptedException e) {
                            Log.e(ACRA.LOG_TAG, "Error : ", e);
                        }
                    }
                    if (z5) {
                        Log.d(ACRA.LOG_TAG, "About to create DIALOG from #handleException");
                        ErrorReporter.this.notifyDialog(reportFileName2);
                    }
                    String str = ACRA.LOG_TAG;
                    StringBuilder sb = new StringBuilder();
                    sb.append("Wait for Toast + worker ended. Kill Application ? ");
                    sb.append(z62);
                    Log.d(str, sb.toString());
                    if (z62) {
                        ErrorReporter.this.endApplication();
                    }
                }
            };
            r42.start();
        }
    }

    /* access modifiers changed from: 0000 */
    public void notifyDialog(String str) {
        String str2 = ACRA.LOG_TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("Creating Dialog for ");
        sb.append(str);
        Log.d(str2, sb.toString());
        Intent intent = new Intent(this.mContext, CrashReportDialog.class);
        intent.putExtra("REPORT_FILE_NAME", str);
        intent.setFlags(268435456);
        this.mContext.startActivity(intent);
    }

    private void notifySendReport(String str) {
        ACRAConfiguration config = ACRA.getConfig();
        Notification notification = new Notification(config.resNotifIcon(), this.mContext.getText(config.resNotifTickerText()), System.currentTimeMillis());
        CharSequence text = this.mContext.getText(config.resNotifTitle());
        CharSequence text2 = this.mContext.getText(config.resNotifText());
        Intent intent = new Intent(this.mContext, CrashReportDialog.class);
        String str2 = ACRA.LOG_TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("Creating Notification for ");
        sb.append(str);
        Log.d(str2, sb.toString());
        intent.putExtra("REPORT_FILE_NAME", str);
        Application application = this.mContext;
        int i = mNotificationCounter;
        mNotificationCounter = i + 1;
        notification.setLatestEventInfo(this.mContext, text, text2, PendingIntent.getActivity(application, i, intent, 134217728));
        Intent intent2 = new Intent(this.mContext, CrashReportDialog.class);
        intent2.putExtra("FORCE_CANCEL", true);
        notification.deleteIntent = PendingIntent.getActivity(this.mContext, -1, intent2, 0);
        ((NotificationManager) this.mContext.getSystemService("notification")).notify(666, notification);
    }

    private String getReportFileName(CrashReportData crashReportData) {
        Time time = new Time();
        time.setToNow();
        long millis = time.toMillis(false);
        String property = crashReportData.getProperty(ReportField.IS_SILENT);
        StringBuilder sb = new StringBuilder();
        String str = "";
        sb.append(str);
        sb.append(millis);
        if (property != null) {
            str = ACRAConstants.SILENT_SUFFIX;
        }
        sb.append(str);
        sb.append(ACRAConstants.REPORTFILE_EXTENSION);
        return sb.toString();
    }

    private void saveCrashReportFile(String str, CrashReportData crashReportData) {
        try {
            String str2 = ACRA.LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Writing crash report file ");
            sb.append(str);
            sb.append(".");
            Log.d(str2, sb.toString());
            new CrashReportPersister(this.mContext).store(crashReportData, str);
        } catch (Exception e) {
            Log.e(ACRA.LOG_TAG, "An error occurred while writing the report file...", e);
        }
    }

    private String getLatestNonSilentReport(String[] strArr) {
        if (strArr == null || strArr.length <= 0) {
            return null;
        }
        for (int length = strArr.length - 1; length >= 0; length--) {
            if (!this.fileNameParser.isSilent(strArr[length])) {
                return strArr[length];
            }
        }
        return strArr[strArr.length - 1];
    }

    private void deletePendingReports(boolean z, boolean z2, int i) {
        String[] crashReportFiles = new CrashReportFinder(this.mContext).getCrashReportFiles();
        Arrays.sort(crashReportFiles);
        if (crashReportFiles != null) {
            for (int i2 = 0; i2 < crashReportFiles.length - i; i2++) {
                String str = crashReportFiles[i2];
                boolean isApproved = this.fileNameParser.isApproved(str);
                if ((isApproved && z) || (!isApproved && z2)) {
                    File file = new File(this.mContext.getFilesDir(), str);
                    ACRALog aCRALog = ACRA.log;
                    String str2 = ACRA.LOG_TAG;
                    StringBuilder sb = new StringBuilder();
                    sb.append("Deleting file ");
                    sb.append(str);
                    aCRALog.d(str2, sb.toString());
                    if (!file.delete()) {
                        String str3 = ACRA.LOG_TAG;
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("Could not delete report : ");
                        sb2.append(file);
                        Log.e(str3, sb2.toString());
                    }
                }
            }
        }
    }

    private boolean containsOnlySilentOrApprovedReports(String[] strArr) {
        for (String isApproved : strArr) {
            if (!this.fileNameParser.isApproved(isApproved)) {
                return false;
            }
        }
        return true;
    }

    public void setDefaultReportSenders() {
        ACRAConfiguration config = ACRA.getConfig();
        Application application = ACRA.getApplication();
        removeAllReportSenders();
        if (!"".equals(config.mailTo())) {
            String str = ACRA.LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append(application.getPackageName());
            sb.append(" reports will be sent by email (if accepted by user).");
            Log.w(str, sb.toString());
            setReportSender(new EmailIntentSender(application));
        } else if (!new PackageManagerWrapper(application).hasPermission("android.permission.INTERNET")) {
            String str2 = ACRA.LOG_TAG;
            StringBuilder sb2 = new StringBuilder();
            sb2.append(application.getPackageName());
            sb2.append(" should be granted permission ");
            sb2.append("android.permission.INTERNET");
            sb2.append(" if you want your crash reports to be sent. If you don't want to add this permission to your application you can also enable sending reports by email. If this is your will then provide your email address in @ReportsCrashes(mailTo=\"your.account@domain.com\"");
            Log.e(str2, sb2.toString());
        } else if (config.formUri() == null || "".equals(config.formUri())) {
            if (config.formKey() != null && !"".equals(config.formKey().trim())) {
                addReportSender(new GoogleFormSender());
            }
        } else {
            setReportSender(new HttpSender(ACRA.getConfig().httpMethod(), ACRA.getConfig().reportType(), null));
        }
    }
}