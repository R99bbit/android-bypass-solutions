package org.acra;

import android.content.Context;
import android.util.Log;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.acra.collector.CrashReportData;
import org.acra.sender.ReportSender;
import org.acra.sender.ReportSenderException;

final class SendWorker extends Thread {
    private final boolean approvePendingReports;
    private final Context context;
    private final CrashReportFileNameParser fileNameParser = new CrashReportFileNameParser();
    private final List<ReportSender> reportSenders;
    private final boolean sendOnlySilentReports;

    public SendWorker(Context context2, List<ReportSender> list, boolean z, boolean z2) {
        this.context = context2;
        this.reportSenders = list;
        this.sendOnlySilentReports = z;
        this.approvePendingReports = z2;
    }

    public void run() {
        if (this.approvePendingReports) {
            approvePendingReports();
        }
        checkAndSendReports(this.context, this.sendOnlySilentReports);
    }

    private void approvePendingReports() {
        String[] crashReportFiles;
        Log.d(ACRA.LOG_TAG, "Mark all pending reports as approved.");
        for (String str : new CrashReportFinder(this.context).getCrashReportFiles()) {
            if (!this.fileNameParser.isApproved(str)) {
                File file = new File(this.context.getFilesDir(), str);
                File file2 = new File(this.context.getFilesDir(), str.replace(ACRAConstants.REPORTFILE_EXTENSION, "-approved.stacktrace"));
                if (!file.renameTo(file2)) {
                    String str2 = ACRA.LOG_TAG;
                    StringBuilder sb = new StringBuilder();
                    sb.append("Could not rename approved report from ");
                    sb.append(file);
                    sb.append(" to ");
                    sb.append(file2);
                    Log.e(str2, sb.toString());
                }
            }
        }
    }

    private void checkAndSendReports(Context context2, boolean z) {
        Log.d(ACRA.LOG_TAG, "#checkAndSendReports - start");
        String[] crashReportFiles = new CrashReportFinder(context2).getCrashReportFiles();
        Arrays.sort(crashReportFiles);
        int i = 0;
        for (String str : crashReportFiles) {
            if (!z || this.fileNameParser.isSilent(str)) {
                if (i >= 5) {
                    break;
                }
                String str2 = ACRA.LOG_TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("Sending file ");
                sb.append(str);
                Log.i(str2, sb.toString());
                try {
                    sendCrashReport(new CrashReportPersister(context2).load(str));
                    deleteFile(context2, str);
                } catch (RuntimeException e) {
                    String str3 = ACRA.LOG_TAG;
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("Failed to send crash reports for ");
                    sb2.append(str);
                    Log.e(str3, sb2.toString(), e);
                    deleteFile(context2, str);
                } catch (IOException e2) {
                    String str4 = ACRA.LOG_TAG;
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("Failed to load crash report for ");
                    sb3.append(str);
                    Log.e(str4, sb3.toString(), e2);
                    deleteFile(context2, str);
                } catch (ReportSenderException e3) {
                    String str5 = ACRA.LOG_TAG;
                    StringBuilder sb4 = new StringBuilder();
                    sb4.append("Failed to send crash report for ");
                    sb4.append(str);
                    Log.e(str5, sb4.toString(), e3);
                }
                i++;
            }
        }
        Log.d(ACRA.LOG_TAG, "#checkAndSendReports - finish");
    }

    private void sendCrashReport(CrashReportData crashReportData) throws ReportSenderException {
        if (!ACRA.isDebuggable() || ACRA.getConfig().sendReportsInDevMode()) {
            boolean z = false;
            for (ReportSender next : this.reportSenders) {
                try {
                    next.send(crashReportData);
                    z = true;
                } catch (ReportSenderException e) {
                    if (z) {
                        String str = ACRA.LOG_TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("ReportSender of class ");
                        sb.append(next.getClass().getName());
                        sb.append(" failed but other senders completed their task. ACRA will not send this report again.");
                        Log.w(str, sb.toString());
                    } else {
                        throw e;
                    }
                }
            }
        }
    }

    private void deleteFile(Context context2, String str) {
        if (!context2.deleteFile(str)) {
            String str2 = ACRA.LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Could not delete error report : ");
            sb.append(str);
            Log.w(str2, sb.toString());
        }
    }
}