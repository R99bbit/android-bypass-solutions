package com.nuvent.shareat.util;

import android.os.Environment;
import java.io.File;

public class ShareatLogger {
    private static String externalPath = (Environment.getExternalStorageDirectory().getAbsolutePath() + "/Shareat/");
    private static String mAllEvFile = "log_";
    static boolean mDebug = false;
    static boolean mPrintLog = false;

    public static void printLog(String event) {
        if (mDebug && mPrintLog) {
            System.out.println(event);
        }
    }

    public static void writeLog(String event) {
    }

    public static boolean createDirIfNotExists(String path) {
        File file = new File(path);
        if (file.exists() || file.mkdirs()) {
            return true;
        }
        return false;
    }
}