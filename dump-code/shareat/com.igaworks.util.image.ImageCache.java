package com.igaworks.util.image;

import android.graphics.Bitmap;
import java.io.File;

public interface ImageCache {
    void addBitmap(String str, Bitmap bitmap);

    void addBitmap(String str, File file);

    void clear();

    Bitmap getBitmap(String str);
}