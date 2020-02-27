package com.igaworks.util;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.BitmapFactory;
import android.graphics.BitmapFactory.Options;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.WeakHashMap;

public class CommonResourceManager {
    private static WeakHashMap<String, Bitmap> mImageCache = new WeakHashMap<>();

    public static void clearImageCache() {
        try {
            if (mImageCache != null) {
                Object[] keyList = mImageCache.keySet().toArray();
                for (Object obj : keyList) {
                    String key = (String) obj;
                    if (mImageCache.get(key) != null) {
                        mImageCache.remove(key);
                    }
                }
                mImageCache.clear();
            }
        } catch (Exception e) {
            if (mImageCache != null) {
                mImageCache.clear();
            }
        }
    }

    public static Bitmap getBitmapResource(Context context, String resourcePath) {
        Bitmap bitmap = null;
        try {
            if (mImageCache == null || !mImageCache.containsKey(resourcePath)) {
                InputStream is = context.getClassLoader().getResourceAsStream(resourcePath);
                Options option = new Options();
                option.inPreferredConfig = Config.RGB_565;
                option.inSampleSize = 1;
                bitmap = BitmapFactory.decodeStream(is);
                if (is != null) {
                    try {
                        is.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                if (bitmap != null) {
                    if (mImageCache == null) {
                        mImageCache = new WeakHashMap<>();
                    }
                    mImageCache.put(resourcePath, bitmap);
                }
                return bitmap;
            }
            bitmap = mImageCache.get(resourcePath);
            return bitmap;
        } catch (OutOfMemoryError out) {
            out.printStackTrace();
            try {
                Iterator<String> it = mImageCache.keySet().iterator();
                if (it != null && it.hasNext()) {
                    String path = it.next();
                    Bitmap temp = mImageCache.get(path);
                    if (temp != null) {
                        temp.recycle();
                        mImageCache.remove(path);
                    }
                }
                mImageCache.clear();
                System.gc();
                return null;
            } catch (Exception e2) {
                System.gc();
                return null;
            }
        } catch (Exception e3) {
        }
    }
}