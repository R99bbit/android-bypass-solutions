package com.ning.http.client.resumable;

import com.ning.http.client.resumable.ResumableAsyncHandler.ResumableProcessor;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PropertiesBasedResumableProcessor implements ResumableProcessor {
    private static final File TMP = new File(System.getProperty("java.io.tmpdir"), "ahc");
    private static final Logger log = LoggerFactory.getLogger(PropertiesBasedResumableProcessor.class);
    private static final String storeName = "ResumableAsyncHandler.properties";
    private final ConcurrentHashMap<String, Long> properties = new ConcurrentHashMap<>();

    public void put(String url, long transferredBytes) {
        this.properties.put(url, Long.valueOf(transferredBytes));
    }

    public void remove(String uri) {
        if (uri != null) {
            this.properties.remove(uri);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:12:0x004b A[SYNTHETIC, Splitter:B:12:0x004b] */
    /* JADX WARNING: Removed duplicated region for block: B:23:0x0086 A[SYNTHETIC, Splitter:B:23:0x0086] */
    /* JADX WARNING: Removed duplicated region for block: B:53:? A[RETURN, SYNTHETIC] */
    public void save(Map<String, Long> map) {
        log.debug((String) "Saving current download state {}", (Object) this.properties.toString());
        FileOutputStream os = null;
        if (TMP.exists() || TMP.mkdirs()) {
            try {
                File f = new File(TMP, storeName);
                if (!f.exists() && !f.createNewFile()) {
                    throw new IllegalStateException("Unable to create temp file: " + f.getAbsolutePath());
                } else if (!f.canWrite()) {
                    throw new IllegalStateException();
                } else {
                    FileOutputStream os2 = new FileOutputStream(f);
                    try {
                        for (Entry<String, Long> e : this.properties.entrySet()) {
                            os2.write(append(e).getBytes("UTF-8"));
                        }
                        os2.flush();
                        if (os2 != null) {
                            try {
                                os2.close();
                                FileOutputStream fileOutputStream = os2;
                            } catch (IOException e2) {
                                FileOutputStream fileOutputStream2 = os2;
                            }
                        }
                    } catch (Throwable th) {
                        th = th;
                        os = os2;
                        if (os != null) {
                        }
                        throw th;
                    }
                }
            } catch (Throwable th2) {
                e = th2;
                log.warn(e.getMessage(), e);
                if (os == null) {
                    try {
                        os.close();
                    } catch (IOException e3) {
                    }
                }
            }
        } else {
            throw new IllegalStateException("Unable to create directory: " + TMP.getAbsolutePath());
        }
    }

    private static String append(Entry<String, Long> e) {
        return new StringBuilder(e.getKey()).append("=").append(e.getValue()).append("\n").toString();
    }

    /* JADX WARNING: Removed duplicated region for block: B:14:0x0048  */
    /* JADX WARNING: Removed duplicated region for block: B:25:0x006f  */
    /* JADX WARNING: Removed duplicated region for block: B:28:0x0076  */
    /* JADX WARNING: Unknown top exception splitter block from list: {B:22:0x0064=Splitter:B:22:0x0064, B:11:0x003b=Splitter:B:11:0x003b} */
    public Map<String, Long> load() {
        Scanner scan = null;
        try {
            Scanner scan2 = new Scanner(new File(TMP, storeName), "UTF-8");
            try {
                scan2.useDelimiter("[=\n]");
                while (scan2.hasNext()) {
                    this.properties.put(scan2.next().trim(), Long.valueOf(scan2.next().trim()));
                }
                log.debug((String) "Loading previous download state {}", (Object) this.properties.toString());
                if (scan2 != null) {
                    scan2.close();
                    Scanner scanner = scan2;
                }
            } catch (FileNotFoundException e) {
                scan = scan2;
                try {
                    log.debug((String) "Missing {}", (Object) storeName);
                    if (scan != null) {
                        scan.close();
                    }
                    return this.properties;
                } catch (Throwable th) {
                    th = th;
                    if (scan != null) {
                        scan.close();
                    }
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
                scan = scan2;
                if (scan != null) {
                }
                throw th;
            }
        } catch (FileNotFoundException e2) {
            log.debug((String) "Missing {}", (Object) storeName);
            if (scan != null) {
            }
            return this.properties;
        } catch (Throwable th3) {
            ex = th3;
            log.warn(ex.getMessage(), ex);
            if (scan != null) {
            }
            return this.properties;
        }
        return this.properties;
    }
}