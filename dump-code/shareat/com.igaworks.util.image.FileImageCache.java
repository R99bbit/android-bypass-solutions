package com.igaworks.util.image;

import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.graphics.BitmapFactory;
import android.graphics.BitmapFactory.Options;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

public class FileImageCache implements ImageCache {
    private static final String TAG = "FileImageCache";
    private FileCache fileCache;

    public FileImageCache(String cacheName) {
        this.fileCache = FileCacheFactory.getInstance().get(cacheName);
    }

    public void addBitmap(String key, final Bitmap bitmap) {
        try {
            this.fileCache.put(key, (ByteProvider) new ByteProvider() {
                public void writeTo(OutputStream os) {
                    bitmap.compress(CompressFormat.PNG, 100, os);
                }
            });
        } catch (IOException e) {
        }
    }

    public void addBitmap(String key, File bitmapFile) {
        try {
            this.fileCache.put(key, bitmapFile, true);
        } catch (IOException e) {
        }
    }

    public Bitmap getBitmap(String key) {
        try {
            FileEntry cachedFile = this.fileCache.get(key);
            if (cachedFile == null) {
                return null;
            }
            Options options = new Options();
            options.inJustDecodeBounds = true;
            options.inDither = true;
            BitmapFactory.decodeFile(cachedFile.getFile().getAbsolutePath(), options);
            options.inJustDecodeBounds = false;
            return BitmapFactory.decodeFile(cachedFile.getFile().getAbsolutePath(), options);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void clear() {
        this.fileCache.clear();
    }
}