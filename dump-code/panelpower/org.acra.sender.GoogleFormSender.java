package org.acra.sender;

import android.net.Uri;
import android.util.Log;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import org.acra.ACRA;
import org.acra.ACRAConstants;
import org.acra.ReportField;
import org.acra.collector.CrashReportData;
import org.acra.sender.HttpSender.Method;
import org.acra.sender.HttpSender.Type;
import org.acra.util.HttpRequest;

public class GoogleFormSender implements ReportSender {
    private final Uri mFormUri;

    /* renamed from: org.acra.sender.GoogleFormSender$1 reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$org$acra$ReportField = new int[ReportField.values().length];

        /* JADX WARNING: Can't wrap try/catch for region: R(6:0|1|2|3|4|6) */
        /* JADX WARNING: Code restructure failed: missing block: B:7:?, code lost:
            return;
         */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:3:0x0014 */
        static {
            $SwitchMap$org$acra$ReportField[ReportField.APP_VERSION_NAME.ordinal()] = 1;
            $SwitchMap$org$acra$ReportField[ReportField.ANDROID_VERSION.ordinal()] = 2;
        }
    }

    public GoogleFormSender() {
        this.mFormUri = null;
    }

    public GoogleFormSender(String str) {
        this.mFormUri = Uri.parse(String.format(ACRA.getConfig().googleFormUrlFormat(), new Object[]{str}));
    }

    public void send(CrashReportData crashReportData) throws ReportSenderException {
        Uri uri = this.mFormUri;
        if (uri == null) {
            uri = Uri.parse(String.format(ACRA.getConfig().googleFormUrlFormat(), new Object[]{ACRA.getConfig().formKey()}));
        }
        Map<String, String> remap = remap(crashReportData);
        remap.put("pageNumber", "0");
        remap.put("backupCache", "");
        remap.put("submit", "Envoyer");
        try {
            URL url = new URL(uri.toString());
            String str = ACRA.LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Sending report ");
            sb.append((String) crashReportData.get(ReportField.REPORT_ID));
            Log.d(str, sb.toString());
            String str2 = ACRA.LOG_TAG;
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Connect to ");
            sb2.append(url);
            Log.d(str2, sb2.toString());
            HttpRequest httpRequest = new HttpRequest();
            httpRequest.setConnectionTimeOut(ACRA.getConfig().connectionTimeout());
            httpRequest.setSocketTimeOut(ACRA.getConfig().socketTimeout());
            httpRequest.setMaxNrRetries(ACRA.getConfig().maxNumberOfRequestRetries());
            httpRequest.send(url, Method.POST, HttpRequest.getParamsAsFormString(remap), Type.FORM);
        } catch (IOException e) {
            throw new ReportSenderException("Error while sending report to Google Form.", e);
        }
    }

    private Map<String, String> remap(Map<ReportField, String> map) {
        ReportField[] customReportContent = ACRA.getConfig().customReportContent();
        if (customReportContent.length == 0) {
            customReportContent = ACRAConstants.DEFAULT_REPORT_FIELDS;
        }
        HashMap hashMap = new HashMap();
        int i = 0;
        for (ReportField reportField : customReportContent) {
            int i2 = AnonymousClass1.$SwitchMap$org$acra$ReportField[reportField.ordinal()];
            if (i2 == 1) {
                StringBuilder sb = new StringBuilder();
                sb.append("entry.");
                sb.append(i);
                sb.append(".single");
                String sb2 = sb.toString();
                StringBuilder sb3 = new StringBuilder();
                sb3.append("'");
                sb3.append(map.get(reportField));
                hashMap.put(sb2, sb3.toString());
            } else if (i2 != 2) {
                StringBuilder sb4 = new StringBuilder();
                sb4.append("entry.");
                sb4.append(i);
                sb4.append(".single");
                hashMap.put(sb4.toString(), map.get(reportField));
            } else {
                StringBuilder sb5 = new StringBuilder();
                sb5.append("entry.");
                sb5.append(i);
                sb5.append(".single");
                String sb6 = sb5.toString();
                StringBuilder sb7 = new StringBuilder();
                sb7.append("'");
                sb7.append(map.get(reportField));
                hashMap.put(sb6, sb7.toString());
            }
            i++;
        }
        return hashMap;
    }
}