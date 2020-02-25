package com.loplat.placeengine.utils;

import a.b.a.h.a;
import a.b.a.h.b;
import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;
import android.widget.Toast;
import com.embrain.panelpower.IConstValue.EventConst;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class LoplatLogger {
    public static final int A = 6;
    public static final int D = 2;
    public static boolean DEBUG = false;
    public static final int E = 5;
    public static final int I = 3;
    public static final int JSON = 7;
    public static final int JSON_INDENT = 4;
    public static final String LINE_SEPARATOR = System.getProperty("line.separator");
    public static final String NULL_TIPS = "Log with null object";
    public static final int V = 1;
    public static final int W = 4;

    /* renamed from: a reason: collision with root package name */
    public static boolean f59a = false;
    public static boolean b = false;

    public static void a(Object obj) {
        a(6, null, obj);
    }

    public static void clearLogFile() {
        a.a();
    }

    public static void d(Object obj) {
        a(2, null, obj);
    }

    public static void e(Object obj) {
        a(5, null, obj);
    }

    public static String getLogFilePath() {
        return a.b;
    }

    public static void i(Object obj) {
        a(3, null, obj);
    }

    public static void json(String str) {
        a(7, null, str);
    }

    public static void setConfigForUnitTest() {
        b = false;
        f59a = false;
    }

    public static void setEnableFileLog(Context context, boolean z) {
        PackageManager packageManager = context.getPackageManager();
        String packageName = context.getPackageName();
        if (!z || packageManager == null || packageManager.checkPermission("android.permission.WRITE_EXTERNAL_STORAGE", packageName) != -1) {
            f59a = z;
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Permission denied. please check Manifest.permission.");
        sb.append("WRITE_EXTERNAL_STORAGE");
        Toast.makeText(context, sb.toString(), 0).show();
    }

    public static void setEnablePrintLog(boolean z) {
        DEBUG = z;
        b = z;
    }

    public static void v(Object obj) {
        a(1, null, obj);
    }

    public static void w(Object obj) {
        a(4, null, obj);
    }

    public static void a(String str, Object... objArr) {
        a(6, str, objArr);
    }

    public static void d(String str, Object... objArr) {
        a(2, str, objArr);
    }

    public static void e(Throwable th) {
        a(5, null, Log.getStackTraceString(th));
    }

    public static void i(String str, Object... objArr) {
        a(3, str, objArr);
    }

    public static void v(String str, Object... objArr) {
        a(1, str, objArr);
    }

    public static void w(String str, Object... objArr) {
        a(4, str, objArr);
    }

    public static void a(int i, String str, Object... objArr) {
        if (DEBUG) {
            if (!b || !(i == 1 || i == 2 || i == 7)) {
                if (str == null) {
                    str = "Plengi";
                }
                String str2 = "null";
                int i2 = 0;
                if (objArr == null) {
                    str2 = NULL_TIPS;
                } else if (objArr.length > 1) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("\n");
                    for (int i3 = 0; i3 < objArr.length; i3++) {
                        Object obj = objArr[i3];
                        if (obj == null) {
                            sb.append("Param");
                            sb.append("[");
                            sb.append(i3);
                            sb.append("]");
                            sb.append(" = ");
                            sb.append(str2);
                            sb.append("\n");
                        } else {
                            sb.append("Param");
                            sb.append("[");
                            sb.append(i3);
                            sb.append("]");
                            sb.append(" = ");
                            sb.append(obj.toString());
                            sb.append("\n");
                        }
                    }
                    str2 = sb.toString();
                } else {
                    Object obj2 = objArr[0];
                    if (obj2 != null) {
                        str2 = obj2.toString();
                    }
                }
                String[] strArr = {str, str2};
                String str3 = strArr[0];
                String str4 = strArr[1];
                if (f59a && (i == 2 || i == 3 || i == 4 || i == 5 || i == 6 || i == 7)) {
                    File file = new File(a.f43a);
                    if (!file.exists()) {
                        file.mkdirs();
                    }
                    File file2 = new File(a.f43a, a.b());
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append(a.f43a);
                    sb2.append(a.b());
                    a.b = sb2.toString();
                    String format = new SimpleDateFormat("MM-dd HH:mm:ss", Locale.KOREA).format(new Date());
                    try {
                        FileOutputStream fileOutputStream = new FileOutputStream(file2, true);
                        OutputStreamWriter outputStreamWriter = new OutputStreamWriter(fileOutputStream, "UTF-8");
                        String str5 = null;
                        switch (i) {
                            case 1:
                                str5 = EventConst.EVENT_TP_CD_INVITE;
                                break;
                            case 2:
                                str5 = "D";
                                break;
                            case 3:
                                str5 = "I";
                                break;
                            case 4:
                                str5 = "W";
                                break;
                            case 5:
                                str5 = "E";
                                break;
                            case 6:
                                str5 = "A";
                                break;
                            case 7:
                                str5 = "J";
                                break;
                        }
                        if (i == 7) {
                            StringBuilder sb3 = new StringBuilder();
                            sb3.append(format);
                            sb3.append(", ");
                            sb3.append(str5);
                            sb3.append(":\n");
                            outputStreamWriter.write(sb3.toString());
                            StringBuilder sb4 = new StringBuilder();
                            sb4.append(b.a(str4));
                            sb4.append("\n");
                            outputStreamWriter.write(sb4.toString());
                        } else {
                            StringBuilder sb5 = new StringBuilder();
                            sb5.append(format);
                            sb5.append(", ");
                            sb5.append(str5);
                            sb5.append(": ");
                            sb5.append(str4);
                            sb5.append("\n");
                            outputStreamWriter.write(sb5.toString());
                        }
                        outputStreamWriter.flush();
                        fileOutputStream.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                switch (i) {
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                        int length = str4.length();
                        int i4 = length / 4000;
                        if (i4 <= 0) {
                            a.b.a.g.a.a(i, str3, str4);
                            break;
                        } else {
                            int i5 = 0;
                            while (i2 < i4) {
                                int i6 = i5 + 4000;
                                a.b.a.g.a.a(i, str3, str4.substring(i5, i6));
                                i2++;
                                i5 = i6;
                            }
                            a.b.a.g.a.a(i, str3, str4.substring(i5, length));
                            break;
                        }
                    case 7:
                        b.a(str3, str4);
                        break;
                }
            }
        }
    }

    public static void e(String str, Object... objArr) {
        a(5, str, objArr);
    }
}