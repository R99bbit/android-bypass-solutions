package org.acra.util;

import android.content.Context;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.UUID;
import org.acra.ACRA;

public class Installation {
    private static final String INSTALLATION = "ACRA-INSTALLATION";
    private static String sID;

    public static synchronized String id(Context context) {
        String str;
        synchronized (Installation.class) {
            if (sID == null) {
                File file = new File(context.getFilesDir(), INSTALLATION);
                try {
                    if (!file.exists()) {
                        writeInstallationFile(file);
                    }
                    sID = readInstallationFile(file);
                } catch (IOException e) {
                    String str2 = ACRA.LOG_TAG;
                    StringBuilder sb = new StringBuilder();
                    sb.append("Couldn't retrieve InstallationId for ");
                    sb.append(context.getPackageName());
                    Log.w(str2, sb.toString(), e);
                    return "Couldn't retrieve InstallationId";
                } catch (RuntimeException e2) {
                    String str3 = ACRA.LOG_TAG;
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("Couldn't retrieve InstallationId for ");
                    sb2.append(context.getPackageName());
                    Log.w(str3, sb2.toString(), e2);
                    return "Couldn't retrieve InstallationId";
                }
            }
            str = sID;
        }
        return str;
    }

    /* JADX INFO: finally extract failed */
    private static String readInstallationFile(File file) throws IOException {
        RandomAccessFile randomAccessFile = new RandomAccessFile(file, "r");
        byte[] bArr = new byte[((int) randomAccessFile.length())];
        try {
            randomAccessFile.readFully(bArr);
            randomAccessFile.close();
            return new String(bArr);
        } catch (Throwable th) {
            randomAccessFile.close();
            throw th;
        }
    }

    private static void writeInstallationFile(File file) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        try {
            fileOutputStream.write(UUID.randomUUID().toString().getBytes());
        } finally {
            fileOutputStream.close();
        }
    }
}