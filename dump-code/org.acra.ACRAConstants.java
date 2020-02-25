package org.acra;

public final class ACRAConstants {
    static final String APPROVED_SUFFIX = "-approved";
    public static final String DEFAULT_APPLICATION_LOGFILE = "";
    public static final int DEFAULT_APPLICATION_LOGFILE_LINES = 100;
    public static final int DEFAULT_BUFFER_SIZE_IN_BYTES = 8192;
    public static final int DEFAULT_CONNECTION_TIMEOUT = 3000;
    public static final boolean DEFAULT_DELETE_OLD_UNSENT_REPORTS_ON_APPLICATION_START = true;
    public static final boolean DEFAULT_DELETE_UNAPPROVED_REPORTS_ON_APPLICATION_START = true;
    public static final int DEFAULT_DIALOG_ICON = 17301543;
    public static final boolean DEFAULT_DISABLE_SSL_CERT_VALIDATION = false;
    public static final int DEFAULT_DROPBOX_COLLECTION_MINUTES = 5;
    public static final boolean DEFAULT_FORCE_CLOSE_DIALOG_AFTER_TOAST = false;
    public static final String DEFAULT_GOOGLE_FORM_URL_FORMAT = "https://docs.google.com/spreadsheet/formResponse?formkey=%s&ifq";
    public static final boolean DEFAULT_INCLUDE_DROPBOX_SYSTEM_TAGS = false;
    public static final boolean DEFAULT_LOGCAT_FILTER_BY_PID = false;
    public static final int DEFAULT_LOGCAT_LINES = 100;
    public static final ReportField[] DEFAULT_MAIL_REPORT_FIELDS = {ReportField.USER_COMMENT, ReportField.ANDROID_VERSION, ReportField.APP_VERSION_NAME, ReportField.BRAND, ReportField.PHONE_MODEL, ReportField.CUSTOM_DATA, ReportField.STACK_TRACE};
    public static final int DEFAULT_MAX_NUMBER_OF_REQUEST_RETRIES = 3;
    public static final int DEFAULT_NOTIFICATION_ICON = 17301624;
    public static final ReportField[] DEFAULT_REPORT_FIELDS = {ReportField.REPORT_ID, ReportField.APP_VERSION_CODE, ReportField.APP_VERSION_NAME, ReportField.PACKAGE_NAME, ReportField.FILE_PATH, ReportField.PHONE_MODEL, ReportField.BRAND, ReportField.PRODUCT, ReportField.ANDROID_VERSION, ReportField.BUILD, ReportField.TOTAL_MEM_SIZE, ReportField.AVAILABLE_MEM_SIZE, ReportField.CUSTOM_DATA, ReportField.IS_SILENT, ReportField.STACK_TRACE, ReportField.INITIAL_CONFIGURATION, ReportField.CRASH_CONFIGURATION, ReportField.DISPLAY, ReportField.USER_COMMENT, ReportField.USER_EMAIL, ReportField.USER_APP_START_DATE, ReportField.USER_CRASH_DATE, ReportField.DUMPSYS_MEMINFO, ReportField.LOGCAT, ReportField.INSTALLATION_ID, ReportField.DEVICE_FEATURES, ReportField.ENVIRONMENT, ReportField.SHARED_PREFERENCES, ReportField.SETTINGS_SYSTEM, ReportField.SETTINGS_SECURE, ReportField.SETTINGS_GLOBAL};
    public static final int DEFAULT_RES_VALUE = 0;
    public static final boolean DEFAULT_SEND_REPORTS_IN_DEV_MODE = true;
    public static final int DEFAULT_SHARED_PREFERENCES_MODE = 0;
    public static final int DEFAULT_SOCKET_TIMEOUT = 5000;
    public static final String DEFAULT_STRING_VALUE = "";
    protected static final String EXTRA_FORCE_CANCEL = "FORCE_CANCEL";
    protected static final String EXTRA_REPORT_FILE_NAME = "REPORT_FILE_NAME";
    static final int MAX_SEND_REPORTS = 5;
    static final int NOTIF_CRASH_ID = 666;
    public static final String NULL_VALUE = "ACRA-NULL-STRING";
    public static final String REPORTFILE_EXTENSION = ".stacktrace";
    static final String SILENT_SUFFIX;
    static final int TOAST_WAIT_DURATION = 3000;

    static {
        StringBuilder sb = new StringBuilder();
        sb.append("-");
        sb.append(ReportField.IS_SILENT);
        SILENT_SUFFIX = sb.toString();
    }
}