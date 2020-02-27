package com.igaworks.util.image;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

public abstract class IOUtils {
    public static String read(InputStream is) throws IOException {
        InputStreamReader reader = null;
        try {
            InputStreamReader reader2 = new InputStreamReader(is);
            try {
                StringBuilder builder = new StringBuilder();
                char[] readDate = new char[1024];
                while (true) {
                    int len = reader2.read(readDate);
                    if (len == -1) {
                        String sb = builder.toString();
                        close(reader2);
                        return sb;
                    }
                    builder.append(readDate, 0, len);
                }
            } catch (Throwable th) {
                th = th;
                reader = reader2;
            }
        } catch (Throwable th2) {
            th = th2;
            close(reader);
            throw th;
        }
    }

    public static void copy(InputStream is, OutputStream out) throws IOException {
        byte[] buff = new byte[4096];
        while (true) {
            int len = is.read(buff);
            if (len != -1) {
                out.write(buff, 0, len);
            } else {
                return;
            }
        }
    }

    public static void copy(File source, OutputStream os) throws IOException {
        BufferedInputStream is = null;
        try {
            BufferedInputStream is2 = new BufferedInputStream(new FileInputStream(source));
            try {
                copy((InputStream) is2, os);
                close(is2);
            } catch (Throwable th) {
                th = th;
                is = is2;
                close(is);
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            close(is);
            throw th;
        }
    }

    public static void copy(InputStream is, File target) throws IOException {
        OutputStream os = null;
        try {
            OutputStream os2 = new BufferedOutputStream(new FileOutputStream(target));
            try {
                copy(is, os2);
                close(os2);
            } catch (Throwable th) {
                th = th;
                os = os2;
                close(os);
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            close(os);
            throw th;
        }
    }

    public static void copy(String str, OutputStream os) throws IOException {
        os.write(str.getBytes());
    }

    public static void close(Closeable stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException e) {
            }
        }
    }
}