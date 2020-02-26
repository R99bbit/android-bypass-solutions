package org.acra;

import android.content.Context;
import android.util.Log;
import java.io.File;
import java.io.FilenameFilter;

final class CrashReportFinder {
    private final Context context;

    public CrashReportFinder(Context context2) {
        this.context = context2;
    }

    public String[] getCrashReportFiles() {
        Context context2 = this.context;
        if (context2 == null) {
            Log.e(ACRA.LOG_TAG, "Trying to get ACRA reports but ACRA is not initialized.");
            return new String[0];
        }
        File filesDir = context2.getFilesDir();
        if (filesDir == null) {
            Log.w(ACRA.LOG_TAG, "Application files directory does not exist! The application may not be installed correctly. Please try reinstalling.");
            return new String[0];
        }
        String str = ACRA.LOG_TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("Looking for error files in ");
        sb.append(filesDir.getAbsolutePath());
        Log.d(str, sb.toString());
        String[] list = filesDir.list(new FilenameFilter() {
            public boolean accept(File file, String str) {
                return str.endsWith(ACRAConstants.REPORTFILE_EXTENSION);
            }
        });
        if (list == null) {
            list = new String[0];
        }
        return list;
    }
}