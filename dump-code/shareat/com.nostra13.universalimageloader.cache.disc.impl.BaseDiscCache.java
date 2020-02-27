package com.nostra13.universalimageloader.cache.disc.impl;

import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import com.nostra13.universalimageloader.cache.disc.DiskCache;
import com.nostra13.universalimageloader.cache.disc.naming.FileNameGenerator;
import com.nostra13.universalimageloader.core.DefaultConfigurationFactory;
import com.nostra13.universalimageloader.utils.IoUtils;
import com.nostra13.universalimageloader.utils.IoUtils.CopyListener;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public abstract class BaseDiscCache implements DiskCache {
    public static final int DEFAULT_BUFFER_SIZE = 32768;
    public static final CompressFormat DEFAULT_COMPRESS_FORMAT = CompressFormat.PNG;
    public static final int DEFAULT_COMPRESS_QUALITY = 100;
    private static final String ERROR_ARG_NULL = " argument must be not null";
    private static final String TEMP_IMAGE_POSTFIX = ".tmp";
    protected int bufferSize;
    protected final File cacheDir;
    protected CompressFormat compressFormat;
    protected int compressQuality;
    protected final FileNameGenerator fileNameGenerator;
    protected final File reserveCacheDir;

    public BaseDiscCache(File cacheDir2) {
        this(cacheDir2, null);
    }

    public BaseDiscCache(File cacheDir2, File reserveCacheDir2) {
        this(cacheDir2, reserveCacheDir2, DefaultConfigurationFactory.createFileNameGenerator());
    }

    public BaseDiscCache(File cacheDir2, File reserveCacheDir2, FileNameGenerator fileNameGenerator2) {
        this.bufferSize = 32768;
        this.compressFormat = DEFAULT_COMPRESS_FORMAT;
        this.compressQuality = 100;
        if (cacheDir2 == null) {
            throw new IllegalArgumentException("cacheDir argument must be not null");
        } else if (fileNameGenerator2 == null) {
            throw new IllegalArgumentException("fileNameGenerator argument must be not null");
        } else {
            this.cacheDir = cacheDir2;
            this.reserveCacheDir = reserveCacheDir2;
            this.fileNameGenerator = fileNameGenerator2;
        }
    }

    public File getDirectory() {
        return this.cacheDir;
    }

    public File get(String imageUri) {
        return getFile(imageUri);
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=java.io.InputStream, code=java.io.OutputStream, for r8v0, types: [java.io.Closeable, java.io.InputStream] */
    public boolean save(String imageUri, OutputStream os, CopyListener listener) throws IOException {
        OutputStream os2;
        File imageFile = getFile(imageUri);
        File tmpFile = new File(imageFile.getAbsolutePath() + ".tmp");
        boolean loaded = false;
        try {
            os2 = new BufferedOutputStream(new FileOutputStream(tmpFile), this.bufferSize);
            boolean loaded2 = IoUtils.copyStream(os2, os2, listener, this.bufferSize);
            if (loaded2 && !tmpFile.renameTo(imageFile)) {
                loaded2 = false;
            }
            if (!loaded2) {
                tmpFile.delete();
            }
            return loaded2;
        } catch (Throwable th) {
            if (loaded && !tmpFile.renameTo(imageFile)) {
                loaded = false;
            }
            if (!loaded) {
                tmpFile.delete();
            }
            throw th;
        } finally {
            IoUtils.closeSilently(os2);
        }
    }

    public boolean save(String imageUri, Bitmap bitmap) throws IOException {
        File imageFile = getFile(imageUri);
        File tmpFile = new File(imageFile.getAbsolutePath() + ".tmp");
        OutputStream os = new BufferedOutputStream(new FileOutputStream(tmpFile), this.bufferSize);
        boolean savedSuccessfully = false;
        try {
            savedSuccessfully = bitmap.compress(this.compressFormat, this.compressQuality, os);
            bitmap.recycle();
            return savedSuccessfully;
        } finally {
            IoUtils.closeSilently(os);
            if (savedSuccessfully && !tmpFile.renameTo(imageFile)) {
                savedSuccessfully = false;
            }
            if (!savedSuccessfully) {
                tmpFile.delete();
            }
        }
    }

    public boolean remove(String imageUri) {
        return getFile(imageUri).delete();
    }

    public void close() {
    }

    public void clear() {
        File[] files = this.cacheDir.listFiles();
        if (files != null) {
            for (File f : files) {
                f.delete();
            }
        }
    }

    /* access modifiers changed from: protected */
    public File getFile(String imageUri) {
        String fileName = this.fileNameGenerator.generate(imageUri);
        File dir = this.cacheDir;
        if (!this.cacheDir.exists() && !this.cacheDir.mkdirs() && this.reserveCacheDir != null && (this.reserveCacheDir.exists() || this.reserveCacheDir.mkdirs())) {
            dir = this.reserveCacheDir;
        }
        return new File(dir, fileName);
    }

    public void setBufferSize(int bufferSize2) {
        this.bufferSize = bufferSize2;
    }

    public void setCompressFormat(CompressFormat compressFormat2) {
        this.compressFormat = compressFormat2;
    }

    public void setCompressQuality(int compressQuality2) {
        this.compressQuality = compressQuality2;
    }
}