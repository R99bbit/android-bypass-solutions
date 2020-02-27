package com.getkeepsafe.relinker;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build.VERSION;
import com.getkeepsafe.relinker.ReLinker.LibraryInstaller;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ApkLibraryInstaller implements LibraryInstaller {
    private static final int COPY_BUFFER_SIZE = 4096;
    private static final int MAX_TRIES = 5;

    private static class ZipFileInZipEntry {
        public ZipEntry zipEntry;
        public ZipFile zipFile;

        public ZipFileInZipEntry(ZipFile zipFile2, ZipEntry zipEntry2) {
            this.zipFile = zipFile2;
            this.zipEntry = zipEntry2;
        }
    }

    private String[] sourceDirectories(Context context) {
        ApplicationInfo appInfo = context.getApplicationInfo();
        if (VERSION.SDK_INT < 21 || appInfo.splitSourceDirs == null || appInfo.splitSourceDirs.length == 0) {
            return new String[]{appInfo.sourceDir};
        }
        String[] apks = new String[(appInfo.splitSourceDirs.length + 1)];
        apks[0] = appInfo.sourceDir;
        System.arraycopy(appInfo.splitSourceDirs, 0, apks, 1, appInfo.splitSourceDirs.length);
        return apks;
    }

    private ZipFileInZipEntry findAPKWithLibrary(Context context, String[] abis, String mappedLibraryName, ReLinkerInstance instance) {
        ZipFile zipFile;
        String[] sourceDirectories = sourceDirectories(context);
        int length = sourceDirectories.length;
        int i = 0;
        ZipFile zipFile2 = null;
        while (i < length) {
            String sourceDir = sourceDirectories[i];
            int tries = 0;
            while (true) {
                int tries2 = tries;
                tries = tries2 + 1;
                if (tries2 >= 5) {
                    zipFile = zipFile2;
                    break;
                }
                try {
                    zipFile = new ZipFile(new File(sourceDir), 1);
                    break;
                } catch (IOException e) {
                }
            }
            if (zipFile != null) {
                int tries3 = 0;
                while (true) {
                    int tries4 = tries3;
                    tries3 = tries4 + 1;
                    if (tries4 < 5) {
                        int length2 = abis.length;
                        for (int i2 = 0; i2 < length2; i2++) {
                            String jniNameInApk = "lib" + File.separatorChar + abis[i2] + File.separatorChar + mappedLibraryName;
                            instance.log("Looking for %s in APK %s...", jniNameInApk, sourceDir);
                            ZipEntry libraryEntry = zipFile.getEntry(jniNameInApk);
                            if (libraryEntry != null) {
                                return new ZipFileInZipEntry(zipFile, libraryEntry);
                            }
                        }
                    } else {
                        try {
                            zipFile.close();
                            break;
                        } catch (IOException e2) {
                        }
                    }
                }
            }
            i++;
            zipFile2 = zipFile;
        }
        ZipFile zipFile3 = zipFile2;
        return null;
    }

    public void installLibrary(Context context, String[] abis, String mappedLibraryName, File destination, ReLinkerInstance instance) {
        int tries;
        int tries2;
        InputStream inputStream;
        FileOutputStream fileOut;
        ZipFileInZipEntry found = null;
        try {
            found = findAPKWithLibrary(context, abis, mappedLibraryName, instance);
            if (found == null) {
                MissingLibraryException missingLibraryException = new MissingLibraryException(mappedLibraryName);
                throw missingLibraryException;
            }
            tries = 0;
            while (true) {
                tries2 = tries + 1;
                if (tries < 5) {
                    r1 = "Found %s! Extracting...";
                    instance.log("Found %s! Extracting...", mappedLibraryName);
                    try {
                        if (destination.exists() || destination.createNewFile()) {
                            inputStream = null;
                            fileOut = null;
                            inputStream = found.zipFile.getInputStream(found.zipEntry);
                            FileOutputStream fileOut2 = new FileOutputStream(destination);
                            try {
                                long written = copy(inputStream, fileOut2);
                                fileOut2.getFD().sync();
                                if (written != destination.length()) {
                                    closeSilently(inputStream);
                                    closeSilently(fileOut2);
                                    tries = tries2;
                                } else {
                                    closeSilently(inputStream);
                                    closeSilently(fileOut2);
                                    destination.setReadable(true, false);
                                    destination.setExecutable(true, false);
                                    destination.setWritable(true);
                                    if (found != null) {
                                        try {
                                            if (found.zipFile != null) {
                                                found.zipFile.close();
                                                return;
                                            }
                                            return;
                                        } catch (IOException e) {
                                            return;
                                        }
                                    } else {
                                        return;
                                    }
                                }
                            } catch (FileNotFoundException e2) {
                                fileOut = fileOut2;
                                closeSilently(inputStream);
                                closeSilently(fileOut);
                                tries = tries2;
                            } catch (IOException e3) {
                                fileOut = fileOut2;
                                closeSilently(inputStream);
                                closeSilently(fileOut);
                                tries = tries2;
                            } catch (Throwable th) {
                                th = th;
                                fileOut = fileOut2;
                                closeSilently(inputStream);
                                closeSilently(fileOut);
                                throw th;
                            }
                        } else {
                            tries = tries2;
                        }
                    } catch (IOException e4) {
                        tries = tries2;
                    }
                } else {
                    instance.log((String) "FATAL! Couldn't extract the library from the APK!");
                    if (found != null) {
                        try {
                            if (found.zipFile != null) {
                                found.zipFile.close();
                                return;
                            }
                            return;
                        } catch (IOException e5) {
                            return;
                        }
                    } else {
                        return;
                    }
                }
            }
        } catch (FileNotFoundException e6) {
            closeSilently(inputStream);
            closeSilently(fileOut);
            tries = tries2;
        } catch (IOException e7) {
            closeSilently(inputStream);
            closeSilently(fileOut);
            tries = tries2;
        } catch (Throwable th2) {
            if (found != null) {
                try {
                    if (found.zipFile != null) {
                        found.zipFile.close();
                    }
                } catch (IOException e8) {
                }
            }
            throw th2;
        }
    }

    private long copy(InputStream in, OutputStream out) throws IOException {
        long copied = 0;
        byte[] buf = new byte[4096];
        while (true) {
            int read = in.read(buf);
            if (read == -1) {
                out.flush();
                return copied;
            }
            out.write(buf, 0, read);
            copied += (long) read;
        }
    }

    private void closeSilently(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
            }
        }
    }
}