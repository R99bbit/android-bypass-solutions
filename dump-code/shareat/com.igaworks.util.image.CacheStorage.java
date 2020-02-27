package com.igaworks.util.image;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class CacheStorage {
    private static final String TAG = "CacheStorage";
    /* access modifiers changed from: private */
    public File cacheDir;
    private Map<String, CacheFile> cacheFileMap;
    private AtomicLong currentBytesSize = new AtomicLong();
    private long maxBytesSize;
    private Lock readLock = this.rwl.readLock();
    private ReadWriteLock rwl = new ReentrantReadWriteLock();
    /* access modifiers changed from: private */
    public Lock writeLock = this.rwl.writeLock();

    private static class CacheFile {
        public File file;
        public long size;

        public CacheFile(File file2) {
            this.file = file2;
            this.size = file2.length();
        }
    }

    private class Initializer implements Runnable {
        private Initializer() {
        }

        /* synthetic */ Initializer(CacheStorage cacheStorage, Initializer initializer) {
            this();
        }

        public void run() {
            CacheStorage.this.writeLock.lock();
            try {
                for (File file : CacheStorage.this.cacheDir.listFiles()) {
                    CacheStorage.this.putFileToCacheMap(file);
                }
            } catch (Exception e) {
            } finally {
                CacheStorage.this.writeLock.unlock();
            }
        }
    }

    public CacheStorage(File cacheDir2, long maxBytesSize2) {
        try {
            this.cacheDir = cacheDir2;
            this.maxBytesSize = maxBytesSize2;
            this.cacheFileMap = Collections.synchronizedMap(new LinkedHashMap(1024));
            createCacheDirIfNotExists();
            initializing();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createCacheDirIfNotExists() {
        if (!this.cacheDir.exists()) {
            this.cacheDir.mkdirs();
        }
    }

    private void initializing() {
        new Thread(new Initializer(this, null)).start();
    }

    public File get(String filename) {
        File file = null;
        this.readLock.lock();
        try {
            CacheFile cachdFile = this.cacheFileMap.get(filename);
            if (cachdFile != null) {
                if (cachdFile.file.exists()) {
                    moveHitEntryToFirst(filename, cachdFile);
                    file = cachdFile.file;
                    this.readLock.unlock();
                } else {
                    removeCacheFileFromMap(filename, cachdFile);
                    this.readLock.unlock();
                }
            }
            return file;
        } finally {
            this.readLock.unlock();
        }
    }

    private void moveHitEntryToFirst(String filename, CacheFile cachedFile) {
        this.cacheFileMap.remove(filename);
        this.cacheFileMap.put(filename, cachedFile);
    }

    private void removeCacheFileFromMap(String filename, CacheFile cachedFile) {
        this.currentBytesSize.addAndGet(-cachedFile.size);
        this.cacheFileMap.remove(filename);
    }

    public void write(String filename, ByteProvider provider) throws IOException {
        this.writeLock.lock();
        try {
            createCacheDirIfNotExists();
            File file = createFile(filename);
            copyProviderToFile(provider, file);
            putToCachMapAndCheckMaxThresold(file);
        } finally {
            this.writeLock.unlock();
        }
    }

    private File createFile(String filename) {
        return new File(this.cacheDir, filename);
    }

    private void copyProviderToFile(ByteProvider provider, File file) throws FileNotFoundException, IOException {
        BufferedOutputStream os = null;
        try {
            BufferedOutputStream os2 = new BufferedOutputStream(new FileOutputStream(file));
            try {
                provider.writeTo(os2);
                IOUtils.close(os2);
            } catch (Throwable th) {
                th = th;
                os = os2;
                IOUtils.close(os);
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            IOUtils.close(os);
            throw th;
        }
    }

    private void putToCachMapAndCheckMaxThresold(File file) {
        putFileToCacheMap(file);
        checkMaxThresoldAndDeleteOldestWhenOverflow();
    }

    /* access modifiers changed from: private */
    public void putFileToCacheMap(File file) {
        this.cacheFileMap.put(file.getName(), new CacheFile(file));
        this.currentBytesSize.addAndGet(file.length());
    }

    private void checkMaxThresoldAndDeleteOldestWhenOverflow() {
        if (isOverflow()) {
            for (Entry<String, CacheFile> entry : getDeletingCandidates()) {
                delete(entry.getKey());
            }
        }
    }

    private boolean isOverflow() {
        if (this.maxBytesSize > 0 && this.currentBytesSize.get() > this.maxBytesSize) {
            return true;
        }
        return false;
    }

    private List<Entry<String, CacheFile>> getDeletingCandidates() {
        List<Entry<String, CacheFile>> deletingCandidates = new ArrayList<>();
        long cadidateFileSizes = 0;
        try {
            for (Entry<String, CacheFile> entry : this.cacheFileMap.entrySet()) {
                deletingCandidates.add(entry);
                cadidateFileSizes += entry.getValue().file.length();
                if (this.currentBytesSize.get() - cadidateFileSizes < this.maxBytesSize) {
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return deletingCandidates;
    }

    public void move(String filename, File sourceFile) {
        this.writeLock.lock();
        try {
            createCacheDirIfNotExists();
            File file = createFile(filename);
            sourceFile.renameTo(file);
            putToCachMapAndCheckMaxThresold(file);
        } finally {
            this.writeLock.unlock();
        }
    }

    public void delete(String filename) {
        this.writeLock.lock();
        try {
            CacheFile cacheFile = this.cacheFileMap.get(filename);
            if (cacheFile != null) {
                removeCacheFileFromMap(filename, cacheFile);
                cacheFile.file.delete();
                this.writeLock.unlock();
            }
        } finally {
            this.writeLock.unlock();
        }
    }

    public void deleteAll() {
        this.writeLock.lock();
        try {
            for (String key : new ArrayList<>(this.cacheFileMap.keySet())) {
                delete(key);
            }
        } finally {
            this.writeLock.unlock();
        }
    }
}