package org.acra;

import android.app.Application;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.content.pm.PackageManager.NameNotFoundException;
import android.preference.PreferenceManager;
import org.acra.annotation.ReportsCrashes;
import org.acra.log.ACRALog;
import org.acra.log.AndroidLogDelegate;

public class ACRA {
    public static final boolean DEV_LOGGING = false;
    public static final String LOG_TAG = "ACRA";
    public static final String PREF_ALWAYS_ACCEPT = "acra.alwaysaccept";
    public static final String PREF_DISABLE_ACRA = "acra.disable";
    public static final String PREF_ENABLE_ACRA = "acra.enable";
    public static final String PREF_ENABLE_DEVICE_ID = "acra.deviceid.enable";
    public static final String PREF_ENABLE_SYSTEM_LOGS = "acra.syslog.enable";
    public static final String PREF_LAST_VERSION_NR = "acra.lastVersionNr";
    public static final String PREF_USER_EMAIL_ADDRESS = "acra.user.email";
    private static ACRAConfiguration configProxy;
    private static ErrorReporter errorReporterSingleton;
    public static ACRALog log = new AndroidLogDelegate();
    private static Application mApplication;
    private static OnSharedPreferenceChangeListener mPrefListener;
    private static ReportsCrashes mReportsCrashes;

    /* renamed from: org.acra.ACRA$2 reason: invalid class name */
    static /* synthetic */ class AnonymousClass2 {
        static final /* synthetic */ int[] $SwitchMap$org$acra$ReportingInteractionMode = new int[ReportingInteractionMode.values().length];

        /* JADX WARNING: Can't wrap try/catch for region: R(8:0|1|2|3|4|5|6|8) */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:3:0x0014 */
        /* JADX WARNING: Missing exception handler attribute for start block: B:5:0x001f */
        static {
            $SwitchMap$org$acra$ReportingInteractionMode[ReportingInteractionMode.TOAST.ordinal()] = 1;
            $SwitchMap$org$acra$ReportingInteractionMode[ReportingInteractionMode.NOTIFICATION.ordinal()] = 2;
            try {
                $SwitchMap$org$acra$ReportingInteractionMode[ReportingInteractionMode.DIALOG.ordinal()] = 3;
            } catch (NoSuchFieldError unused) {
            }
        }
    }

    public static void init(Application application) {
        if (mApplication != null) {
            log.w(LOG_TAG, (String) "ACRA#init called more than once. Won't do anything more.");
            return;
        }
        mApplication = application;
        mReportsCrashes = (ReportsCrashes) mApplication.getClass().getAnnotation(ReportsCrashes.class);
        if (mReportsCrashes == null) {
            ACRALog aCRALog = log;
            String str = LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("ACRA#init called but no ReportsCrashes annotation on Application ");
            sb.append(mApplication.getPackageName());
            aCRALog.e(str, sb.toString());
            return;
        }
        SharedPreferences aCRASharedPreferences = getACRASharedPreferences();
        try {
            checkCrashResources();
            ACRALog aCRALog2 = log;
            String str2 = LOG_TAG;
            StringBuilder sb2 = new StringBuilder();
            sb2.append("ACRA is enabled for ");
            sb2.append(mApplication.getPackageName());
            sb2.append(", intializing...");
            aCRALog2.d(str2, sb2.toString());
            ErrorReporter errorReporter = new ErrorReporter(mApplication, aCRASharedPreferences, !shouldDisableACRA(aCRASharedPreferences));
            errorReporter.setDefaultReportSenders();
            errorReporterSingleton = errorReporter;
        } catch (ACRAConfigurationException e) {
            log.w(LOG_TAG, "Error : ", e);
        }
        mPrefListener = new OnSharedPreferenceChangeListener() {
            public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String str) {
                if (ACRA.PREF_DISABLE_ACRA.equals(str) || ACRA.PREF_ENABLE_ACRA.equals(str)) {
                    ACRA.getErrorReporter().setEnabled(!ACRA.shouldDisableACRA(sharedPreferences));
                }
            }
        };
        aCRASharedPreferences.registerOnSharedPreferenceChangeListener(mPrefListener);
    }

    public static ErrorReporter getErrorReporter() {
        ErrorReporter errorReporter = errorReporterSingleton;
        if (errorReporter != null) {
            return errorReporter;
        }
        throw new IllegalStateException("Cannot access ErrorReporter before ACRA#init");
    }

    /* access modifiers changed from: private */
    public static boolean shouldDisableACRA(SharedPreferences sharedPreferences) {
        boolean z = true;
        try {
            if (sharedPreferences.getBoolean(PREF_ENABLE_ACRA, true)) {
                z = false;
            }
            return sharedPreferences.getBoolean(PREF_DISABLE_ACRA, z);
        } catch (Exception unused) {
            return false;
        }
    }

    static void checkCrashResources() throws ACRAConfigurationException {
        ACRAConfiguration config = getConfig();
        int i = AnonymousClass2.$SwitchMap$org$acra$ReportingInteractionMode[config.mode().ordinal()];
        if (i != 1) {
            if (i != 2) {
                if (i == 3 && config.resDialogText() == 0) {
                    throw new ACRAConfigurationException("DIALOG mode: you have to define at least the resDialogText parameters in your application @ReportsCrashes() annotation.");
                }
            } else if (config.resNotifTickerText() == 0 || config.resNotifTitle() == 0 || config.resNotifText() == 0 || config.resDialogText() == 0) {
                throw new ACRAConfigurationException("NOTIFICATION mode: you have to define at least the resNotifTickerText, resNotifTitle, resNotifText, resDialogText parameters in your application @ReportsCrashes() annotation.");
            }
        } else if (config.resToastText() == 0) {
            throw new ACRAConfigurationException("TOAST mode: you have to define the resToastText parameter in your application @ReportsCrashes() annotation.");
        }
    }

    public static SharedPreferences getACRASharedPreferences() {
        ACRAConfiguration config = getConfig();
        if (!"".equals(config.sharedPreferencesName())) {
            return mApplication.getSharedPreferences(config.sharedPreferencesName(), config.sharedPreferencesMode());
        }
        return PreferenceManager.getDefaultSharedPreferences(mApplication);
    }

    public static ACRAConfiguration getConfig() {
        if (configProxy == null) {
            if (mApplication == null) {
                log.w(LOG_TAG, (String) "Calling ACRA.getConfig() before ACRA.init() gives you an empty configuration instance. You might prefer calling ACRA.getNewDefaultConfig(Application) to get an instance with default values taken from a @ReportsCrashes annotation.");
            }
            configProxy = getNewDefaultConfig(mApplication);
        }
        return configProxy;
    }

    public static void setConfig(ACRAConfiguration aCRAConfiguration) {
        configProxy = aCRAConfiguration;
    }

    public static ACRAConfiguration getNewDefaultConfig(Application application) {
        if (application != null) {
            return new ACRAConfiguration((ReportsCrashes) application.getClass().getAnnotation(ReportsCrashes.class));
        }
        return new ACRAConfiguration(null);
    }

    static boolean isDebuggable() {
        try {
            if ((mApplication.getPackageManager().getApplicationInfo(mApplication.getPackageName(), 0).flags & 2) > 0) {
                return true;
            }
            return false;
        } catch (NameNotFoundException unused) {
            return false;
        }
    }

    static Application getApplication() {
        return mApplication;
    }

    public static void setLog(ACRALog aCRALog) {
        log = aCRALog;
    }
}