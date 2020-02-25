package org.acra.sender;

import android.content.Context;
import android.content.Intent;
import org.acra.ACRA;
import org.acra.ACRAConstants;
import org.acra.ReportField;
import org.acra.collector.CrashReportData;

public class EmailIntentSender implements ReportSender {
    private final Context mContext;

    public EmailIntentSender(Context context) {
        this.mContext = context;
    }

    public void send(CrashReportData crashReportData) throws ReportSenderException {
        StringBuilder sb = new StringBuilder();
        sb.append(this.mContext.getPackageName());
        sb.append(" Crash Report");
        String sb2 = sb.toString();
        String buildBody = buildBody(crashReportData);
        Intent intent = new Intent("android.intent.action.SEND");
        intent.addFlags(268435456);
        intent.setType("text/plain");
        intent.putExtra("android.intent.extra.SUBJECT", sb2);
        intent.putExtra("android.intent.extra.TEXT", buildBody);
        intent.putExtra("android.intent.extra.EMAIL", new String[]{ACRA.getConfig().mailTo()});
        this.mContext.startActivity(intent);
    }

    private String buildBody(CrashReportData crashReportData) {
        ReportField[] customReportContent = ACRA.getConfig().customReportContent();
        if (customReportContent.length == 0) {
            customReportContent = ACRAConstants.DEFAULT_MAIL_REPORT_FIELDS;
        }
        StringBuilder sb = new StringBuilder();
        for (ReportField reportField : customReportContent) {
            sb.append(reportField.toString());
            sb.append("=");
            sb.append((String) crashReportData.get(reportField));
            sb.append(10);
        }
        return sb.toString();
    }
}