package org.acra;

public enum ReportField {
    REPORT_ID,
    APP_VERSION_CODE,
    APP_VERSION_NAME,
    PACKAGE_NAME,
    FILE_PATH,
    PHONE_MODEL,
    ANDROID_VERSION,
    BUILD {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    BRAND,
    PRODUCT,
    TOTAL_MEM_SIZE,
    AVAILABLE_MEM_SIZE,
    CUSTOM_DATA {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    STACK_TRACE,
    INITIAL_CONFIGURATION {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    CRASH_CONFIGURATION {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    DISPLAY {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    USER_COMMENT,
    USER_APP_START_DATE,
    USER_CRASH_DATE,
    DUMPSYS_MEMINFO,
    DROPBOX,
    LOGCAT,
    EVENTSLOG,
    RADIOLOG,
    IS_SILENT,
    DEVICE_ID,
    INSTALLATION_ID,
    USER_EMAIL,
    DEVICE_FEATURES {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    ENVIRONMENT {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    SETTINGS_SYSTEM {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    SETTINGS_SECURE {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    SETTINGS_GLOBAL {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    SHARED_PREFERENCES {
        public boolean containsKeyValuePairs() {
            return true;
        }
    },
    APPLICATION_LOG,
    MEDIA_CODEC_LIST,
    THREAD_DETAILS,
    USER_IP;

    public boolean containsKeyValuePairs() {
        return false;
    }
}