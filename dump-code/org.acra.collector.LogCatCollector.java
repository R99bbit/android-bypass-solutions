package org.acra.collector;

import android.os.Process;
import android.util.Log;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import org.acra.ACRA;
import org.acra.util.BoundedLinkedList;

class LogCatCollector {
    private static final int DEFAULT_TAIL_COUNT = 100;

    LogCatCollector() {
    }

    public static String collectLogCat(String str) {
        String str2;
        int myPid = Process.myPid();
        if (!ACRA.getConfig().logcatFilterByPid() || myPid <= 0) {
            str2 = null;
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(Integer.toString(myPid));
            sb.append("):");
            str2 = sb.toString();
        }
        ArrayList arrayList = new ArrayList();
        arrayList.add("logcat");
        if (str != null) {
            arrayList.add("-b");
            arrayList.add(str);
        }
        ArrayList arrayList2 = new ArrayList(Arrays.asList(ACRA.getConfig().logcatArguments()));
        int indexOf = arrayList2.indexOf("-t");
        int i = -1;
        if (indexOf > -1 && indexOf < arrayList2.size()) {
            int i2 = indexOf + 1;
            int parseInt = Integer.parseInt((String) arrayList2.get(i2));
            if (Compatibility.getAPILevel() < 8) {
                arrayList2.remove(i2);
                arrayList2.remove(indexOf);
                arrayList2.add("-d");
            }
            i = parseInt;
        }
        if (i <= 0) {
            i = 100;
        }
        BoundedLinkedList boundedLinkedList = new BoundedLinkedList(i);
        arrayList.addAll(arrayList2);
        try {
            final Process exec = Runtime.getRuntime().exec((String[]) arrayList.toArray(new String[arrayList.size()]));
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()), 8192);
            Log.d(ACRA.LOG_TAG, "Retrieving logcat output...");
            new Thread(new Runnable() {
                public void run() {
                    try {
                        do {
                        } while (exec.getErrorStream().read(new byte[8192]) >= 0);
                    } catch (IOException unused) {
                    }
                }
            }).start();
            while (true) {
                String readLine = bufferedReader.readLine();
                if (readLine == null) {
                    break;
                } else if (str2 == null || readLine.contains(str2)) {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append(readLine);
                    sb2.append("\n");
                    boundedLinkedList.add(sb2.toString());
                }
            }
        } catch (IOException e) {
            Log.e(ACRA.LOG_TAG, "LogCatCollector.collectLogCat could not retrieve data.", e);
        }
        return boundedLinkedList.toString();
    }
}