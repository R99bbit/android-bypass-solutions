package org.acra.collector;

import android.content.Context;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import org.acra.util.BoundedLinkedList;

class LogFileCollector {
    private LogFileCollector() {
    }

    public static String collectLogFile(Context context, String str, int i) throws IOException {
        BufferedReader bufferedReader;
        BoundedLinkedList boundedLinkedList = new BoundedLinkedList(i);
        if (str.contains("/")) {
            bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(str)), 1024);
        } else {
            bufferedReader = new BufferedReader(new InputStreamReader(context.openFileInput(str)), 1024);
        }
        for (String readLine = bufferedReader.readLine(); readLine != null; readLine = bufferedReader.readLine()) {
            StringBuilder sb = new StringBuilder();
            sb.append(readLine);
            sb.append("\n");
            boundedLinkedList.add(sb.toString());
        }
        return boundedLinkedList.toString();
    }
}