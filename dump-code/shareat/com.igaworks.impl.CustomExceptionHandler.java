package com.igaworks.impl;

import android.util.Log;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.Thread.UncaughtExceptionHandler;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map.Entry;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class CustomExceptionHandler implements UncaughtExceptionHandler {
    private UncaughtExceptionHandler defaultUEH = Thread.getDefaultUncaughtExceptionHandler();

    public static long getThreadId() {
        return Thread.currentThread().getId();
    }

    public static String getThreadSignature() {
        Thread t = Thread.currentThread();
        long l = t.getId();
        String name = t.getName();
        long p = (long) t.getPriority();
        return new StringBuilder(String.valueOf(name)).append(":(id)").append(l).append(":(priority)").append(p).append(":(group)").append(t.getThreadGroup().getName()).toString();
    }

    public static void logThreadSignature() {
        Log.d("ThreadUtils", getThreadSignature());
    }

    public static void sleepForInSecs(int secs) {
        try {
            Thread.sleep((long) (secs * 1000));
        } catch (InterruptedException x) {
            throw new RuntimeException("interrupted", x);
        }
    }

    public void uncaughtException(Thread t, Throwable e) {
        try {
            List<String> pListWholeStackTrace = new ArrayList<>();
            for (Entry<Thread, StackTraceElement[]> entry : Thread.getAllStackTraces().entrySet()) {
                Thread key = entry.getKey();
                String stringStackTraceElement = "";
                int pCount = 0;
                StackTraceElement[] value = entry.getValue();
                int length = value.length;
                for (int i = 0; i < length; i++) {
                    StackTraceElement ste = value[i];
                    if (pCount == 0) {
                        stringStackTraceElement = ste.toString();
                    } else {
                        stringStackTraceElement = new StringBuilder(String.valueOf(stringStackTraceElement)).append("\n").append(ste.toString()).toString();
                    }
                    pCount++;
                }
                if (!stringStackTraceElement.equals("")) {
                    pListWholeStackTrace.add(("{\"" + key.getName() + "\",\"" + stringStackTraceElement + "\"}").toString());
                }
            }
            Writer result = new StringWriter();
            PrintWriter printWriter = new PrintWriter(result);
            e.printStackTrace(printWriter);
            String stacktrace = result.toString();
            printWriter.close();
            if (stacktrace.toLowerCase(Locale.US).indexOf("igaworks".toLowerCase()) != -1) {
                List<JSONObject> pListErr = new ArrayList<>();
                JSONObject pJObject = null;
                try {
                    String stringJSONObject = "{\"iga_error\":\"" + stacktrace + "\",\"exception_reason\":\"" + e.toString() + "\",\"retry_cnt\":\"" + 0 + "\"";
                    if (pListWholeStackTrace.size() > 0) {
                        JSONArray jarray = new JSONArray();
                        for (int i2 = 0; i2 < pListWholeStackTrace.size(); i2++) {
                            jarray.put(pListWholeStackTrace.get(i2));
                        }
                        stringJSONObject = new StringBuilder(String.valueOf(stringJSONObject)).append(",\"thread_information\":").append(jarray.toString()).toString();
                    }
                    pJObject = new JSONObject(new StringBuilder(String.valueOf(stringJSONObject)).append("}").toString());
                } catch (JSONException e1) {
                    e1.printStackTrace();
                }
                if (pJObject != null) {
                    pListErr.add(pJObject);
                    CommonFrameworkImpl.sendCrashReport(pListErr);
                } else {
                    return;
                }
            }
            this.defaultUEH.uncaughtException(t, e);
        } catch (Exception err) {
            err.printStackTrace();
        }
    }
}