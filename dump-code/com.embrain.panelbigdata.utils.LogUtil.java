package com.embrain.panelbigdata.utils;

import android.os.Environment;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.text.SimpleDateFormat;

public class LogUtil {
    private static SimpleDateFormat FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.sss");
    private static final String TAG = "bigdata_Debug";
    private static boolean init = false;
    private static LogUtil mInstance;
    private static PrintStream mOutStream;

    private static LogUtil getInstance() {
        if (mInstance == null) {
            mInstance = new LogUtil();
        }
        return mInstance;
    }

    private LogUtil() {
        try {
            getWriter();
        } catch (Exception unused) {
        }
        init = true;
    }

    private PrintStream getWriter() throws FileNotFoundException {
        if (mOutStream == null) {
            mOutStream = new PrintStream(new FileOutputStream(getFile(), true));
        }
        return mOutStream;
    }

    private File getFile() {
        File file = new File(Environment.getExternalStorageDirectory(), "panel_log.txt");
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return file;
    }

    public static synchronized void write(String str) {
        synchronized (LogUtil.class) {
            if (!init) {
                getInstance();
            }
        }
    }
}