package com.igaworks.util.image;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import java.io.File;

public class MemoryImageCache implements ImageCache {
    private IgawLruCache<String, Bitmap> lruCache;

    public MemoryImageCache(int maxCount) {
        this.lruCache = new IgawLruCache<>(maxCount);
    }

    public void addBitmap(String key, Bitmap bitmap) {
        if (bitmap != null) {
            try {
                this.lruCache.put(key, bitmap);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void addBitmap(String key, File bitmapFile) {
        if (bitmapFile != null) {
            try {
                if (bitmapFile.exists() && key != null && this.lruCache.get(key) == null) {
                    Bitmap bitmap = BitmapFactory.decodeFile(bitmapFile.getAbsolutePath());
                    if (bitmap != null) {
                        this.lruCache.put(key, bitmap);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public Bitmap getBitmap(String key) {
        if (key == null) {
            return null;
        }
        return (Bitmap) this.lruCache.get(key);
    }

    public void clear() {
        this.lruCache.evictAll();
    }
}