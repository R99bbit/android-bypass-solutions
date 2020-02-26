package org.acra;

import java.lang.annotation.Annotation;
import java.util.Map;
import org.acra.annotation.ReportsCrashes;
import org.acra.sender.HttpSender.Method;
import org.acra.sender.HttpSender.Type;

public class ACRAConfiguration implements ReportsCrashes {
    private String[] mAdditionalDropboxTags = null;
    private String[] mAdditionalSharedPreferences = null;
    private String mApplicationLogFile = null;
    private Integer mApplicationLogFileLines = null;
    private Integer mConnectionTimeout = null;
    private ReportField[] mCustomReportContent = null;
    private Boolean mDeleteOldUnsentReportsOnApplicationStart = null;
    private Boolean mDeleteUnapprovedReportsOnApplicationStart = null;
    private Boolean mDisableSSLCertValidation = null;
    private Integer mDropboxCollectionMinutes = null;
    private String[] mExcludeMatchingSettingsKeys = null;
    private String[] mExcludeMatchingSharedPreferencesKeys = null;
    private Boolean mForceCloseDialogAfterToast = null;
    private String mFormKey = null;
    private String mFormUri = null;
    private String mFormUriBasicAuthLogin = null;
    private String mFormUriBasicAuthPassword = null;
    private String mGoogleFormUrlFormat = null;
    private Map<String, String> mHttpHeaders;
    private Method mHttpMethod = null;
    private Boolean mIncludeDropboxSystemTags = null;
    private String[] mLogcatArguments = null;
    private Boolean mLogcatFilterByPid = null;
    private String mMailTo = null;
    private Integer mMaxNumberOfRequestRetries = null;
    private ReportingInteractionMode mMode = null;
    private Type mReportType = null;
    private ReportsCrashes mReportsCrashes = null;
    private Integer mResDialogCommentPrompt = null;
    private Integer mResDialogEmailPrompt = null;
    private Integer mResDialogIcon = null;
    private Integer mResDialogOkToast = null;
    private Integer mResDialogText = null;
    private Integer mResDialogTitle = null;
    private Integer mResNotifIcon = null;
    private Integer mResNotifText = null;
    private Integer mResNotifTickerText = null;
    private Integer mResNotifTitle = null;
    private Integer mResToastText = null;
    private Boolean mSendReportsInDevMode = null;
    private Integer mSharedPreferenceMode = null;
    private String mSharedPreferenceName = null;
    private Integer mSocketTimeout = null;

    public void setHttpHeaders(Map<String, String> map) {
        this.mHttpHeaders = map;
    }

    public Map<String, String> getHttpHeaders() {
        return this.mHttpHeaders;
    }

    public void setAdditionalDropboxTags(String[] strArr) {
        this.mAdditionalDropboxTags = strArr;
    }

    public void setAdditionalSharedPreferences(String[] strArr) {
        this.mAdditionalSharedPreferences = strArr;
    }

    public void setConnectionTimeout(Integer num) {
        this.mConnectionTimeout = num;
    }

    public void setCustomReportContent(ReportField[] reportFieldArr) {
        this.mCustomReportContent = reportFieldArr;
    }

    public void setDeleteUnapprovedReportsOnApplicationStart(Boolean bool) {
        this.mDeleteUnapprovedReportsOnApplicationStart = bool;
    }

    public void setDeleteOldUnsentReportsOnApplicationStart(Boolean bool) {
        this.mDeleteOldUnsentReportsOnApplicationStart = bool;
    }

    public void setDropboxCollectionMinutes(Integer num) {
        this.mDropboxCollectionMinutes = num;
    }

    public void setForceCloseDialogAfterToast(Boolean bool) {
        this.mForceCloseDialogAfterToast = bool;
    }

    public void setFormKey(String str) {
        this.mFormKey = str;
    }

    public void setFormUri(String str) {
        this.mFormUri = str;
    }

    public void setFormUriBasicAuthLogin(String str) {
        this.mFormUriBasicAuthLogin = str;
    }

    public void setFormUriBasicAuthPassword(String str) {
        this.mFormUriBasicAuthPassword = str;
    }

    public void setIncludeDropboxSystemTags(Boolean bool) {
        this.mIncludeDropboxSystemTags = bool;
    }

    public void setLogcatArguments(String[] strArr) {
        this.mLogcatArguments = strArr;
    }

    public void setMailTo(String str) {
        this.mMailTo = str;
    }

    public void setMaxNumberOfRequestRetries(Integer num) {
        this.mMaxNumberOfRequestRetries = num;
    }

    public void setMode(ReportingInteractionMode reportingInteractionMode) throws ACRAConfigurationException {
        this.mMode = reportingInteractionMode;
        ACRA.checkCrashResources();
    }

    public void setResDialogCommentPrompt(int i) {
        this.mResDialogCommentPrompt = Integer.valueOf(i);
    }

    public void setResDialogEmailPrompt(int i) {
        this.mResDialogEmailPrompt = Integer.valueOf(i);
    }

    public void setResDialogIcon(int i) {
        this.mResDialogIcon = Integer.valueOf(i);
    }

    public void setResDialogOkToast(int i) {
        this.mResDialogOkToast = Integer.valueOf(i);
    }

    public void setResDialogText(int i) {
        this.mResDialogText = Integer.valueOf(i);
    }

    public void setResDialogTitle(int i) {
        this.mResDialogTitle = Integer.valueOf(i);
    }

    public void setResNotifIcon(int i) {
        this.mResNotifIcon = Integer.valueOf(i);
    }

    public void setResNotifText(int i) {
        this.mResNotifText = Integer.valueOf(i);
    }

    public void setResNotifTickerText(int i) {
        this.mResNotifTickerText = Integer.valueOf(i);
    }

    public void setResNotifTitle(int i) {
        this.mResNotifTitle = Integer.valueOf(i);
    }

    public void setResToastText(int i) {
        this.mResToastText = Integer.valueOf(i);
    }

    public void setSharedPreferenceMode(Integer num) {
        this.mSharedPreferenceMode = num;
    }

    public void setSharedPreferenceName(String str) {
        this.mSharedPreferenceName = str;
    }

    public void setSocketTimeout(Integer num) {
        this.mSocketTimeout = num;
    }

    public void setLogcatFilterByPid(Boolean bool) {
        this.mLogcatFilterByPid = bool;
    }

    public void setSendReportsInDevMode(Boolean bool) {
        this.mSendReportsInDevMode = bool;
    }

    public void setExcludeMatchingSharedPreferencesKeys(String[] strArr) {
        this.mExcludeMatchingSharedPreferencesKeys = strArr;
    }

    public void setExcludeMatchingSettingsKeys(String[] strArr) {
        this.mExcludeMatchingSettingsKeys = strArr;
    }

    public void setApplicationLogFile(String str) {
        this.mApplicationLogFile = str;
    }

    public void setApplicationLogFileLines(int i) {
        this.mApplicationLogFileLines = Integer.valueOf(i);
    }

    public void setDisableSSLCertValidation(boolean z) {
        this.mDisableSSLCertValidation = Boolean.valueOf(z);
    }

    public void setHttpMethod(Method method) {
        this.mHttpMethod = method;
    }

    public void setReportType(Type type) {
        this.mReportType = type;
    }

    public ACRAConfiguration(ReportsCrashes reportsCrashes) {
        this.mReportsCrashes = reportsCrashes;
    }

    public String[] additionalDropBoxTags() {
        String[] strArr = this.mAdditionalDropboxTags;
        if (strArr != null) {
            return strArr;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.additionalDropBoxTags();
        }
        return new String[0];
    }

    public String[] additionalSharedPreferences() {
        String[] strArr = this.mAdditionalSharedPreferences;
        if (strArr != null) {
            return strArr;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.additionalSharedPreferences();
        }
        return new String[0];
    }

    public Class<? extends Annotation> annotationType() {
        return this.mReportsCrashes.annotationType();
    }

    public int connectionTimeout() {
        Integer num = this.mConnectionTimeout;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.connectionTimeout();
        }
        return 3000;
    }

    public ReportField[] customReportContent() {
        ReportField[] reportFieldArr = this.mCustomReportContent;
        if (reportFieldArr != null) {
            return reportFieldArr;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.customReportContent();
        }
        return new ReportField[0];
    }

    public boolean deleteUnapprovedReportsOnApplicationStart() {
        Boolean bool = this.mDeleteUnapprovedReportsOnApplicationStart;
        if (bool != null) {
            return bool.booleanValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.deleteUnapprovedReportsOnApplicationStart();
        }
        return true;
    }

    public boolean deleteOldUnsentReportsOnApplicationStart() {
        Boolean bool = this.mDeleteOldUnsentReportsOnApplicationStart;
        if (bool != null) {
            return bool.booleanValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.deleteOldUnsentReportsOnApplicationStart();
        }
        return true;
    }

    public int dropboxCollectionMinutes() {
        Integer num = this.mDropboxCollectionMinutes;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.dropboxCollectionMinutes();
        }
        return 5;
    }

    public boolean forceCloseDialogAfterToast() {
        Boolean bool = this.mForceCloseDialogAfterToast;
        if (bool != null) {
            return bool.booleanValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.forceCloseDialogAfterToast();
        }
        return false;
    }

    public String formKey() {
        String str = this.mFormKey;
        if (str != null) {
            return str;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.formKey() : "";
    }

    public String formUri() {
        String str = this.mFormUri;
        if (str != null) {
            return str;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.formUri() : "";
    }

    public String formUriBasicAuthLogin() {
        String str = this.mFormUriBasicAuthLogin;
        if (str != null) {
            return str;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.formUriBasicAuthLogin() : ACRAConstants.NULL_VALUE;
    }

    public String formUriBasicAuthPassword() {
        String str = this.mFormUriBasicAuthPassword;
        if (str != null) {
            return str;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.formUriBasicAuthPassword() : ACRAConstants.NULL_VALUE;
    }

    public boolean includeDropBoxSystemTags() {
        Boolean bool = this.mIncludeDropboxSystemTags;
        if (bool != null) {
            return bool.booleanValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.includeDropBoxSystemTags();
        }
        return false;
    }

    public String[] logcatArguments() {
        String[] strArr = this.mLogcatArguments;
        if (strArr != null) {
            return strArr;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.logcatArguments();
        }
        return new String[]{"-t", Integer.toString(100), "-v", "time"};
    }

    public String mailTo() {
        String str = this.mMailTo;
        if (str != null) {
            return str;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.mailTo() : "";
    }

    public int maxNumberOfRequestRetries() {
        Integer num = this.mMaxNumberOfRequestRetries;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.maxNumberOfRequestRetries();
        }
        return 3;
    }

    public ReportingInteractionMode mode() {
        ReportingInteractionMode reportingInteractionMode = this.mMode;
        if (reportingInteractionMode != null) {
            return reportingInteractionMode;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.mode();
        }
        return ReportingInteractionMode.SILENT;
    }

    public int resDialogCommentPrompt() {
        Integer num = this.mResDialogCommentPrompt;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.resDialogCommentPrompt();
        }
        return 0;
    }

    public int resDialogEmailPrompt() {
        Integer num = this.mResDialogEmailPrompt;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.resDialogEmailPrompt();
        }
        return 0;
    }

    public int resDialogIcon() {
        Integer num = this.mResDialogIcon;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.resDialogIcon() : ACRAConstants.DEFAULT_DIALOG_ICON;
    }

    public int resDialogOkToast() {
        Integer num = this.mResDialogOkToast;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.resDialogOkToast();
        }
        return 0;
    }

    public int resDialogText() {
        Integer num = this.mResDialogText;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.resDialogText();
        }
        return 0;
    }

    public int resDialogTitle() {
        Integer num = this.mResDialogTitle;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.resDialogTitle();
        }
        return 0;
    }

    public int resNotifIcon() {
        Integer num = this.mResNotifIcon;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.resNotifIcon() : ACRAConstants.DEFAULT_NOTIFICATION_ICON;
    }

    public int resNotifText() {
        Integer num = this.mResNotifText;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.resNotifText();
        }
        return 0;
    }

    public int resNotifTickerText() {
        Integer num = this.mResNotifTickerText;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.resNotifTickerText();
        }
        return 0;
    }

    public int resNotifTitle() {
        Integer num = this.mResNotifTitle;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.resNotifTitle();
        }
        return 0;
    }

    public int resToastText() {
        Integer num = this.mResToastText;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.resToastText();
        }
        return 0;
    }

    public int sharedPreferencesMode() {
        Integer num = this.mSharedPreferenceMode;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.sharedPreferencesMode();
        }
        return 0;
    }

    public String sharedPreferencesName() {
        String str = this.mSharedPreferenceName;
        if (str != null) {
            return str;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.sharedPreferencesName() : "";
    }

    public int socketTimeout() {
        Integer num = this.mSocketTimeout;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.socketTimeout() : ACRAConstants.DEFAULT_SOCKET_TIMEOUT;
    }

    public boolean logcatFilterByPid() {
        Boolean bool = this.mLogcatFilterByPid;
        if (bool != null) {
            return bool.booleanValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.logcatFilterByPid();
        }
        return false;
    }

    public boolean sendReportsInDevMode() {
        Boolean bool = this.mSendReportsInDevMode;
        if (bool != null) {
            return bool.booleanValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.sendReportsInDevMode();
        }
        return true;
    }

    public String[] excludeMatchingSharedPreferencesKeys() {
        String[] strArr = this.mExcludeMatchingSharedPreferencesKeys;
        if (strArr != null) {
            return strArr;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.excludeMatchingSharedPreferencesKeys();
        }
        return new String[0];
    }

    public String[] excludeMatchingSettingsKeys() {
        String[] strArr = this.mExcludeMatchingSettingsKeys;
        if (strArr != null) {
            return strArr;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.excludeMatchingSettingsKeys();
        }
        return new String[0];
    }

    public String applicationLogFile() {
        String str = this.mApplicationLogFile;
        if (str != null) {
            return str;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.applicationLogFile() : "";
    }

    public int applicationLogFileLines() {
        Integer num = this.mApplicationLogFileLines;
        if (num != null) {
            return num.intValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.applicationLogFileLines();
        }
        return 100;
    }

    public String googleFormUrlFormat() {
        String str = this.mGoogleFormUrlFormat;
        if (str != null) {
            return str;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        return reportsCrashes != null ? reportsCrashes.googleFormUrlFormat() : ACRAConstants.DEFAULT_GOOGLE_FORM_URL_FORMAT;
    }

    public boolean disableSSLCertValidation() {
        Boolean bool = this.mDisableSSLCertValidation;
        if (bool != null) {
            return bool.booleanValue();
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.disableSSLCertValidation();
        }
        return false;
    }

    public Method httpMethod() {
        Method method = this.mHttpMethod;
        if (method != null) {
            return method;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.httpMethod();
        }
        return Method.POST;
    }

    public Type reportType() {
        Type type = this.mReportType;
        if (type != null) {
            return type;
        }
        ReportsCrashes reportsCrashes = this.mReportsCrashes;
        if (reportsCrashes != null) {
            return reportsCrashes.reportType();
        }
        return Type.FORM;
    }

    public static boolean isNull(String str) {
        return str == null || ACRAConstants.NULL_VALUE.equals(str);
    }
}