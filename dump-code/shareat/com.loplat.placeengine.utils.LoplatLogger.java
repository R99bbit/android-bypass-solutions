package com.loplat.placeengine.utils;

import android.os.Environment;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class LoplatLogger {
    private static String mAllEvFile = "log_";
    static boolean mDebug = false;
    static boolean mPrintLog = false;

    public static void printLog(String event) {
        if (mDebug && mPrintLog) {
            System.out.println(event);
        }
    }

    public static void writeLog(String event) {
        if (mDebug) {
            if (mPrintLog) {
                System.out.println(event);
            }
            SimpleDateFormat mSimpleDateFormat = new SimpleDateFormat("MM-dd HH:mm:ss", Locale.KOREA);
            SimpleDateFormat fileDateFormat = new SimpleDateFormat("MM-dd", Locale.KOREA);
            Date currentTime = new Date();
            String externalPath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/loplat/";
            String fullfilename = externalPath + mAllEvFile + fileDateFormat.format(currentTime) + ".txt";
            String mTime = mSimpleDateFormat.format(currentTime);
            try {
                createDirIfNotExists(externalPath);
                FileOutputStream mFos = new FileOutputStream(new File(fullfilename), true);
                try {
                    mFos.write((mTime + ", " + event + "\n").getBytes());
                    try {
                        mFos.close();
                    } catch (IOException | Exception e) {
                    }
                } catch (IOException | Exception e2) {
                }
            } catch (IOException e3) {
                e3.printStackTrace();
            }
        }
    }

    public static boolean createDirIfNotExists(String path) {
        File file = new File(path);
        if (file.exists() || file.mkdirs()) {
            return true;
        }
        return false;
    }
}