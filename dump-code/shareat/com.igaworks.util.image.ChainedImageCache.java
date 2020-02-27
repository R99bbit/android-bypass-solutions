package com.igaworks.util.image;

import android.graphics.Bitmap;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ChainedImageCache implements ImageCache {
    private List<ImageCache> chain;

    public ChainedImageCache(List<ImageCache> chain2) {
        this.chain = chain2;
    }

    public void addBitmap(String key, Bitmap bitmap) {
        for (ImageCache cache : this.chain) {
            cache.addBitmap(key, bitmap);
        }
    }

    public void addBitmap(String key, File bitmapFile) {
        for (ImageCache cache : this.chain) {
            cache.addBitmap(key, bitmapFile);
        }
    }

    public final Bitmap getBitmap(String key) {
        Bitmap bitmap = null;
        try {
            List<ImageCache> previousCaches = new ArrayList<>();
            for (ImageCache cache : this.chain) {
                bitmap = cache.getBitmap(key);
                if (bitmap != null && !bitmap.isRecycled()) {
                    break;
                }
                previousCaches.add(cache);
            }
            if (bitmap == null) {
                return null;
            }
            if (!previousCaches.isEmpty()) {
                for (ImageCache cache2 : previousCaches) {
                    cache2.addBitmap(key, bitmap);
                }
            }
            return bitmap;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public final void clear() {
        for (ImageCache cache : this.chain) {
            cache.clear();
        }
    }
}