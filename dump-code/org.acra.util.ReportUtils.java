package org.acra.util;

import android.content.Context;
import android.os.Environment;
import android.os.StatFs;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.util.SparseArray;
import java.io.File;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import org.acra.ACRA;

public final class ReportUtils {
    public static long getAvailableInternalMemorySize() {
        StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
        return ((long) statFs.getAvailableBlocks()) * ((long) statFs.getBlockSize());
    }

    public static long getTotalInternalMemorySize() {
        StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
        return ((long) statFs.getBlockCount()) * ((long) statFs.getBlockSize());
    }

    public static String getDeviceId(Context context) {
        try {
            return ((TelephonyManager) context.getSystemService("phone")).getDeviceId();
        } catch (RuntimeException e) {
            String str = ACRA.LOG_TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Couldn't retrieve DeviceId for : ");
            sb.append(context.getPackageName());
            Log.w(str, sb.toString(), e);
            return null;
        }
    }

    public static String getApplicationFilePath(Context context) {
        File filesDir = context.getFilesDir();
        if (filesDir != null) {
            return filesDir.getAbsolutePath();
        }
        String str = ACRA.LOG_TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("Couldn't retrieve ApplicationFilePath for : ");
        sb.append(context.getPackageName());
        Log.w(str, sb.toString());
        return "Couldn't retrieve ApplicationFilePath";
    }

    public static String sparseArrayToString(SparseArray<?> sparseArray) {
        StringBuilder sb = new StringBuilder();
        if (sparseArray == null) {
            return "null";
        }
        sb.append('{');
        for (int i = 0; i < sparseArray.size(); i++) {
            sb.append(sparseArray.keyAt(i));
            sb.append(" => ");
            if (sparseArray.valueAt(i) == null) {
                sb.append("null");
            } else {
                sb.append(sparseArray.valueAt(i).toString());
            }
            if (i < sparseArray.size() - 1) {
                sb.append(", ");
            }
        }
        sb.append('}');
        return sb.toString();
    }

    public static String getLocalIpAddress() {
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            boolean z = true;
            while (networkInterfaces.hasMoreElements()) {
                Enumeration<InetAddress> inetAddresses = networkInterfaces.nextElement().getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress nextElement = inetAddresses.nextElement();
                    if (!nextElement.isLoopbackAddress()) {
                        if (!z) {
                            sb.append(10);
                        }
                        sb.append(nextElement.getHostAddress().toString());
                        z = false;
                    }
                }
            }
        } catch (SocketException e) {
            ACRA.log.w(ACRA.LOG_TAG, e.toString());
        }
        return sb.toString();
    }
}