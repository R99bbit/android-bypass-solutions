package com.igaworks.adbrix.util;

import android.util.Log;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.Thread.UncaughtExceptionHandler;

public class ExceptionHandler implements UncaughtExceptionHandler {
    public void uncaughtException(Thread arg0, Throwable throw0) {
        StringWriter sw = new StringWriter();
        throw0.printStackTrace(new PrintWriter(sw));
        Log.e("Android Plugin Exception", sw.toString());
    }
}