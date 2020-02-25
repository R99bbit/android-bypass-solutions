package org.acra.sender;

import android.net.Uri;
import android.util.Log;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import org.acra.ACRA;
import org.acra.ACRAConfiguration;
import org.acra.ACRAConstants;
import org.acra.ReportField;
import org.acra.collector.CrashReportData;
import org.acra.util.HttpRequest;
import org.acra.util.JSONReportBuilder.JSONReportException;

public class HttpSender implements ReportSender {
    private final Uri mFormUri;
    private final Map<ReportField, String> mMapping;
    private final Method mMethod;
    private final Type mType;

    /* renamed from: org.acra.sender.HttpSender$1 reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$org$acra$sender$HttpSender$Method = new int[Method.values().length];
        static final /* synthetic */ int[] $SwitchMap$org$acra$sender$HttpSender$Type = new int[Type.values().length];

        /* JADX WARNING: Can't wrap try/catch for region: R(11:0|1|2|3|(2:5|6)|7|9|10|11|12|14) */
        /* JADX WARNING: Code restructure failed: missing block: B:15:?, code lost:
            return;
         */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:11:0x0032 */
        static {
            try {
                $SwitchMap$org$acra$sender$HttpSender$Method[Method.POST.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$org$acra$sender$HttpSender$Method[Method.PUT.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            $SwitchMap$org$acra$sender$HttpSender$Type[Type.JSON.ordinal()] = 1;
            $SwitchMap$org$acra$sender$HttpSender$Type[Type.FORM.ordinal()] = 2;
        }
    }

    public enum Method {
        POST,
        PUT
    }

    public enum Type {
        FORM {
            public String getContentType() {
                return "application/x-www-form-urlencoded";
            }
        },
        JSON {
            public String getContentType() {
                return "application/json";
            }
        };

        public abstract String getContentType();
    }

    public HttpSender(Method method, Type type, Map<ReportField, String> map) {
        this.mMethod = method;
        this.mFormUri = null;
        this.mMapping = map;
        this.mType = type;
    }

    public HttpSender(Method method, Type type, String str, Map<ReportField, String> map) {
        this.mMethod = method;
        this.mFormUri = Uri.parse(str);
        this.mMapping = map;
        this.mType = type;
    }

    public void send(CrashReportData crashReportData) throws ReportSenderException {
        String str;
        try {
            URL url = this.mFormUri == null ? new URL(ACRA.getConfig().formUri()) : new URL(this.mFormUri.toString());
            String str2 = ACRA.LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Connect to ");
            sb.append(url.toString());
            Log.d(str2, sb.toString());
            String str3 = null;
            String formUriBasicAuthLogin = ACRAConfiguration.isNull(ACRA.getConfig().formUriBasicAuthLogin()) ? null : ACRA.getConfig().formUriBasicAuthLogin();
            if (!ACRAConfiguration.isNull(ACRA.getConfig().formUriBasicAuthPassword())) {
                str3 = ACRA.getConfig().formUriBasicAuthPassword();
            }
            HttpRequest httpRequest = new HttpRequest();
            httpRequest.setConnectionTimeOut(ACRA.getConfig().connectionTimeout());
            httpRequest.setSocketTimeOut(ACRA.getConfig().socketTimeout());
            httpRequest.setMaxNrRetries(ACRA.getConfig().maxNumberOfRequestRetries());
            httpRequest.setLogin(formUriBasicAuthLogin);
            httpRequest.setPassword(str3);
            httpRequest.setHeaders(ACRA.getConfig().getHttpHeaders());
            if (AnonymousClass1.$SwitchMap$org$acra$sender$HttpSender$Type[this.mType.ordinal()] != 1) {
                str = HttpRequest.getParamsAsFormString(remap(crashReportData));
            } else {
                str = crashReportData.toJSON().toString();
            }
            int i = AnonymousClass1.$SwitchMap$org$acra$sender$HttpSender$Method[this.mMethod.ordinal()];
            if (i != 1) {
                if (i == 2) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append(url.toString());
                    sb2.append('/');
                    sb2.append(crashReportData.getProperty(ReportField.REPORT_ID));
                    url = new URL(sb2.toString());
                } else {
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("Unknown method: ");
                    sb3.append(this.mMethod.name());
                    throw new UnsupportedOperationException(sb3.toString());
                }
            }
            httpRequest.send(url, this.mMethod, str, this.mType);
        } catch (IOException e) {
            StringBuilder sb4 = new StringBuilder();
            sb4.append("Error while sending ");
            sb4.append(ACRA.getConfig().reportType());
            sb4.append(" report via Http ");
            sb4.append(this.mMethod.name());
            throw new ReportSenderException(sb4.toString(), e);
        } catch (JSONReportException e2) {
            StringBuilder sb5 = new StringBuilder();
            sb5.append("Error while sending ");
            sb5.append(ACRA.getConfig().reportType());
            sb5.append(" report via Http ");
            sb5.append(this.mMethod.name());
            throw new ReportSenderException(sb5.toString(), e2);
        }
    }

    private Map<String, String> remap(Map<ReportField, String> map) {
        ReportField[] customReportContent = ACRA.getConfig().customReportContent();
        if (customReportContent.length == 0) {
            customReportContent = ACRAConstants.DEFAULT_REPORT_FIELDS;
        }
        HashMap hashMap = new HashMap(map.size());
        for (ReportField reportField : customReportContent) {
            Map<ReportField, String> map2 = this.mMapping;
            if (map2 == null || map2.get(reportField) == null) {
                hashMap.put(reportField.toString(), map.get(reportField));
            } else {
                hashMap.put(this.mMapping.get(reportField), map.get(reportField));
            }
        }
        return hashMap;
    }
}