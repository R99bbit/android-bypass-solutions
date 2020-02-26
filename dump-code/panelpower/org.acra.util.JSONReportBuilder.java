package org.acra.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Locale;
import org.acra.ACRA;
import org.acra.ReportField;
import org.acra.collector.CrashReportData;
import org.acra.log.ACRALog;
import org.json.JSONException;
import org.json.JSONObject;

public class JSONReportBuilder {

    public static class JSONReportException extends Exception {
        private static final long serialVersionUID = -694684023635442219L;

        public JSONReportException(String str, Throwable th) {
            super(str, th);
        }
    }

    public static JSONObject buildJSONReport(CrashReportData crashReportData) throws JSONReportException {
        JSONObject jSONObject = new JSONObject();
        for (ReportField reportField : crashReportData.keySet()) {
            try {
                if (reportField.containsKeyValuePairs()) {
                    JSONObject jSONObject2 = new JSONObject();
                    BufferedReader bufferedReader = new BufferedReader(new StringReader(crashReportData.getProperty(reportField)), 1024);
                    while (true) {
                        try {
                            String readLine = bufferedReader.readLine();
                            if (readLine == null) {
                                break;
                            }
                            addJSONFromProperty(jSONObject2, readLine);
                        } catch (IOException e) {
                            ACRALog aCRALog = ACRA.log;
                            String str = ACRA.LOG_TAG;
                            StringBuilder sb = new StringBuilder();
                            sb.append("Error while converting ");
                            sb.append(reportField.name());
                            sb.append(" to JSON.");
                            aCRALog.e(str, sb.toString(), e);
                        }
                    }
                    jSONObject.accumulate(reportField.name(), jSONObject2);
                } else {
                    jSONObject.accumulate(reportField.name(), guessType(crashReportData.getProperty(reportField)));
                }
            } catch (JSONException e2) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("Could not create JSON object for key ");
                sb2.append(reportField);
                throw new JSONReportException(sb2.toString(), e2);
            }
        }
        return jSONObject;
    }

    private static void addJSONFromProperty(JSONObject jSONObject, String str) throws JSONException {
        int indexOf = str.indexOf(61);
        if (indexOf > 0) {
            String trim = str.substring(0, indexOf).trim();
            Object guessType = guessType(str.substring(indexOf + 1).trim());
            if (guessType instanceof String) {
                guessType = ((String) guessType).replaceAll("\\\\n", "\n");
            }
            String[] split = trim.split("\\.");
            if (split.length > 1) {
                addJSONSubTree(jSONObject, split, guessType);
            } else {
                jSONObject.accumulate(trim, guessType);
            }
        } else {
            jSONObject.put(str.trim(), true);
        }
    }

    /* JADX WARNING: type inference failed for: r1v2, types: [java.lang.Number] */
    /* JADX WARNING: Multi-variable type inference failed */
    /* JADX WARNING: Unknown variable types count: 1 */
    private static Object guessType(String str) {
        if (str.equalsIgnoreCase("true")) {
            return Boolean.valueOf(true);
        }
        if (str.equalsIgnoreCase("false")) {
            return Boolean.valueOf(false);
        }
        if (str.matches("(?:^|\\s)([1-9](?:\\d*|(?:\\d{0,2})(?:,\\d{3})*)(?:\\.\\d*[1-9])?|0?\\.\\d*[1-9]|0)(?:\\s|$)")) {
            try {
                str = NumberFormat.getInstance(Locale.US).parse(str);
            } catch (ParseException unused) {
            }
        }
        return str;
    }

    private static void addJSONSubTree(JSONObject jSONObject, String[] strArr, Object obj) throws JSONException {
        JSONObject jSONObject2;
        for (int i = 0; i < strArr.length; i++) {
            String str = strArr[i];
            if (i < strArr.length - 1) {
                if (jSONObject.isNull(str)) {
                    jSONObject2 = new JSONObject();
                    jSONObject.accumulate(str, jSONObject2);
                } else {
                    jSONObject2 = jSONObject.getJSONObject(str);
                }
                jSONObject = jSONObject2;
            } else {
                jSONObject.accumulate(str, obj);
            }
        }
    }
}