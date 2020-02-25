package org.acra.collector;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.os.Build.VERSION;
import android.os.Environment;
import android.text.format.Time;
import android.util.Log;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.acra.ACRA;
import org.acra.ACRAConfiguration;
import org.acra.ACRAConstants;
import org.acra.ReportField;
import org.acra.util.Installation;
import org.acra.util.PackageManagerWrapper;
import org.acra.util.ReportUtils;

public final class CrashReportDataFactory {
    private final Time appStartDate;
    private final Context context;
    private final Map<String, String> customParameters = new HashMap();
    private final String initialConfiguration;
    private final SharedPreferences prefs;

    public CrashReportDataFactory(Context context2, SharedPreferences sharedPreferences, Time time, String str) {
        this.context = context2;
        this.prefs = sharedPreferences;
        this.appStartDate = time;
        this.initialConfiguration = str;
    }

    public String putCustomData(String str, String str2) {
        return this.customParameters.put(str, str2);
    }

    public String removeCustomData(String str) {
        return this.customParameters.remove(str);
    }

    public String getCustomData(String str) {
        return this.customParameters.get(str);
    }

    public CrashReportData createCrashData(Throwable th, boolean z, Thread thread) {
        CrashReportData crashReportData = new CrashReportData();
        try {
            List<ReportField> reportFields = getReportFields();
            crashReportData.put(ReportField.STACK_TRACE, getStackTrace(th));
            crashReportData.put(ReportField.USER_APP_START_DATE, this.appStartDate.format3339(false));
            if (z) {
                crashReportData.put(ReportField.IS_SILENT, "true");
            }
            if (reportFields.contains(ReportField.REPORT_ID)) {
                crashReportData.put(ReportField.REPORT_ID, UUID.randomUUID().toString());
            }
            if (reportFields.contains(ReportField.INSTALLATION_ID)) {
                crashReportData.put(ReportField.INSTALLATION_ID, Installation.id(this.context));
            }
            if (reportFields.contains(ReportField.INITIAL_CONFIGURATION)) {
                crashReportData.put(ReportField.INITIAL_CONFIGURATION, this.initialConfiguration);
            }
            if (reportFields.contains(ReportField.CRASH_CONFIGURATION)) {
                crashReportData.put(ReportField.CRASH_CONFIGURATION, ConfigurationCollector.collectConfiguration(this.context));
            }
            if (!(th instanceof OutOfMemoryError) && reportFields.contains(ReportField.DUMPSYS_MEMINFO)) {
                crashReportData.put(ReportField.DUMPSYS_MEMINFO, DumpSysCollector.collectMemInfo());
            }
            if (reportFields.contains(ReportField.PACKAGE_NAME)) {
                crashReportData.put(ReportField.PACKAGE_NAME, this.context.getPackageName());
            }
            if (reportFields.contains(ReportField.BUILD)) {
                ReportField reportField = ReportField.BUILD;
                StringBuilder sb = new StringBuilder();
                sb.append(ReflectionCollector.collectConstants(Build.class));
                sb.append(ReflectionCollector.collectConstants(VERSION.class, "VERSION"));
                crashReportData.put(reportField, sb.toString());
            }
            if (reportFields.contains(ReportField.PHONE_MODEL)) {
                crashReportData.put(ReportField.PHONE_MODEL, Build.MODEL);
            }
            if (reportFields.contains(ReportField.ANDROID_VERSION)) {
                crashReportData.put(ReportField.ANDROID_VERSION, VERSION.RELEASE);
            }
            if (reportFields.contains(ReportField.BRAND)) {
                crashReportData.put(ReportField.BRAND, Build.BRAND);
            }
            if (reportFields.contains(ReportField.PRODUCT)) {
                crashReportData.put(ReportField.PRODUCT, Build.PRODUCT);
            }
            if (reportFields.contains(ReportField.TOTAL_MEM_SIZE)) {
                crashReportData.put(ReportField.TOTAL_MEM_SIZE, Long.toString(ReportUtils.getTotalInternalMemorySize()));
            }
            if (reportFields.contains(ReportField.AVAILABLE_MEM_SIZE)) {
                crashReportData.put(ReportField.AVAILABLE_MEM_SIZE, Long.toString(ReportUtils.getAvailableInternalMemorySize()));
            }
            if (reportFields.contains(ReportField.FILE_PATH)) {
                crashReportData.put(ReportField.FILE_PATH, ReportUtils.getApplicationFilePath(this.context));
            }
            if (reportFields.contains(ReportField.DISPLAY)) {
                crashReportData.put(ReportField.DISPLAY, DisplayManagerCollector.collectDisplays(this.context));
            }
            if (reportFields.contains(ReportField.USER_CRASH_DATE)) {
                Time time = new Time();
                time.setToNow();
                crashReportData.put(ReportField.USER_CRASH_DATE, time.format3339(false));
            }
            if (reportFields.contains(ReportField.CUSTOM_DATA)) {
                crashReportData.put(ReportField.CUSTOM_DATA, createCustomInfoString());
            }
            if (reportFields.contains(ReportField.USER_EMAIL)) {
                crashReportData.put(ReportField.USER_EMAIL, this.prefs.getString(ACRA.PREF_USER_EMAIL_ADDRESS, "N/A"));
            }
            if (reportFields.contains(ReportField.DEVICE_FEATURES)) {
                crashReportData.put(ReportField.DEVICE_FEATURES, DeviceFeaturesCollector.getFeatures(this.context));
            }
            if (reportFields.contains(ReportField.ENVIRONMENT)) {
                crashReportData.put(ReportField.ENVIRONMENT, ReflectionCollector.collectStaticGettersResults(Environment.class));
            }
            if (reportFields.contains(ReportField.SETTINGS_SYSTEM)) {
                crashReportData.put(ReportField.SETTINGS_SYSTEM, SettingsCollector.collectSystemSettings(this.context));
            }
            if (reportFields.contains(ReportField.SETTINGS_SECURE)) {
                crashReportData.put(ReportField.SETTINGS_SECURE, SettingsCollector.collectSecureSettings(this.context));
            }
            if (reportFields.contains(ReportField.SETTINGS_GLOBAL)) {
                crashReportData.put(ReportField.SETTINGS_GLOBAL, SettingsCollector.collectGlobalSettings(this.context));
            }
            if (reportFields.contains(ReportField.SHARED_PREFERENCES)) {
                crashReportData.put(ReportField.SHARED_PREFERENCES, SharedPreferencesCollector.collect(this.context));
            }
            PackageManagerWrapper packageManagerWrapper = new PackageManagerWrapper(this.context);
            PackageInfo packageInfo = packageManagerWrapper.getPackageInfo();
            if (packageInfo != null) {
                if (reportFields.contains(ReportField.APP_VERSION_CODE)) {
                    crashReportData.put(ReportField.APP_VERSION_CODE, Integer.toString(packageInfo.versionCode));
                }
                if (reportFields.contains(ReportField.APP_VERSION_NAME)) {
                    crashReportData.put(ReportField.APP_VERSION_NAME, packageInfo.versionName != null ? packageInfo.versionName : "not set");
                }
            } else {
                crashReportData.put(ReportField.APP_VERSION_NAME, "Package info unavailable");
            }
            if (reportFields.contains(ReportField.DEVICE_ID) && this.prefs.getBoolean(ACRA.PREF_ENABLE_DEVICE_ID, true) && packageManagerWrapper.hasPermission("android.permission.READ_PHONE_STATE")) {
                String deviceId = ReportUtils.getDeviceId(this.context);
                if (deviceId != null) {
                    crashReportData.put(ReportField.DEVICE_ID, deviceId);
                }
            }
            if ((!this.prefs.getBoolean(ACRA.PREF_ENABLE_SYSTEM_LOGS, true) || !packageManagerWrapper.hasPermission("android.permission.READ_LOGS")) && Compatibility.getAPILevel() < 16) {
                Log.i(ACRA.LOG_TAG, "READ_LOGS not allowed. ACRA will not include LogCat and DropBox data.");
            } else {
                Log.i(ACRA.LOG_TAG, "READ_LOGS granted! ACRA can include LogCat and DropBox data.");
                if (reportFields.contains(ReportField.LOGCAT)) {
                    crashReportData.put(ReportField.LOGCAT, LogCatCollector.collectLogCat(null));
                }
                if (reportFields.contains(ReportField.EVENTSLOG)) {
                    crashReportData.put(ReportField.EVENTSLOG, LogCatCollector.collectLogCat("events"));
                }
                if (reportFields.contains(ReportField.RADIOLOG)) {
                    crashReportData.put(ReportField.RADIOLOG, LogCatCollector.collectLogCat("radio"));
                }
                if (reportFields.contains(ReportField.DROPBOX)) {
                    crashReportData.put(ReportField.DROPBOX, DropBoxCollector.read(this.context, ACRA.getConfig().additionalDropBoxTags()));
                }
            }
            if (reportFields.contains(ReportField.APPLICATION_LOG)) {
                crashReportData.put(ReportField.APPLICATION_LOG, LogFileCollector.collectLogFile(this.context, ACRA.getConfig().applicationLogFile(), ACRA.getConfig().applicationLogFileLines()));
            }
            if (reportFields.contains(ReportField.MEDIA_CODEC_LIST)) {
                crashReportData.put(ReportField.MEDIA_CODEC_LIST, MediaCodecListCollector.collecMediaCodecList());
            }
            if (reportFields.contains(ReportField.THREAD_DETAILS)) {
                crashReportData.put(ReportField.THREAD_DETAILS, ThreadCollector.collect(thread));
            }
            if (reportFields.contains(ReportField.USER_IP)) {
                crashReportData.put(ReportField.USER_IP, ReportUtils.getLocalIpAddress());
            }
        } catch (RuntimeException e) {
            Log.e(ACRA.LOG_TAG, "Error while retrieving crash data", e);
        } catch (FileNotFoundException e2) {
            String str = ACRA.LOG_TAG;
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Error : application log file ");
            sb2.append(ACRA.getConfig().applicationLogFile());
            sb2.append(" not found.");
            Log.e(str, sb2.toString(), e2);
        } catch (IOException e3) {
            String str2 = ACRA.LOG_TAG;
            StringBuilder sb3 = new StringBuilder();
            sb3.append("Error while reading application log file ");
            sb3.append(ACRA.getConfig().applicationLogFile());
            sb3.append(".");
            Log.e(str2, sb3.toString(), e3);
        }
        return crashReportData;
    }

    private String createCustomInfoString() {
        StringBuilder sb = new StringBuilder();
        for (String next : this.customParameters.keySet()) {
            String str = this.customParameters.get(next);
            sb.append(next);
            sb.append(" = ");
            if (str != null) {
                str = str.replaceAll("\n", "\\\\n");
            }
            sb.append(str);
            sb.append("\n");
        }
        return sb.toString();
    }

    private String getStackTrace(Throwable th) {
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        while (th != null) {
            th.printStackTrace(printWriter);
            th = th.getCause();
        }
        String obj = stringWriter.toString();
        printWriter.close();
        return obj;
    }

    private List<ReportField> getReportFields() {
        ACRAConfiguration config = ACRA.getConfig();
        ReportField[] customReportContent = config.customReportContent();
        if (customReportContent.length != 0) {
            Log.d(ACRA.LOG_TAG, "Using custom Report Fields");
        } else if (config.mailTo() == null || "".equals(config.mailTo())) {
            Log.d(ACRA.LOG_TAG, "Using default Report Fields");
            customReportContent = ACRAConstants.DEFAULT_REPORT_FIELDS;
        } else {
            Log.d(ACRA.LOG_TAG, "Using default Mail Report Fields");
            customReportContent = ACRAConstants.DEFAULT_MAIL_REPORT_FIELDS;
        }
        return Arrays.asList(customReportContent);
    }
}