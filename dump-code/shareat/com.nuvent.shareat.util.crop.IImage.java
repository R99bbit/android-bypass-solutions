package com.nuvent.shareat.util.crop;

import android.graphics.Bitmap;
import android.net.Uri;
import java.io.InputStream;

public interface IImage {
    public static final int MINI_THUMB_MAX_NUM_PIXELS = 16384;
    public static final int MINI_THUMB_TARGET_SIZE = 96;
    public static final boolean NO_NATIVE = false;
    public static final boolean NO_ROTATE = false;
    public static final boolean ROTATE_AS_NEEDED = true;
    public static final int THUMBNAIL_MAX_NUM_PIXELS = 196608;
    public static final int THUMBNAIL_TARGET_SIZE = 320;
    public static final int UNCONSTRAINED = -1;
    public static final boolean USE_NATIVE = true;

    Bitmap fullSizeBitmap(int i, int i2);

    Bitmap fullSizeBitmap(int i, int i2, boolean z, boolean z2);

    InputStream fullSizeImageData();

    Uri fullSizeImageUri();

    IImageList getContainer();

    String getDataPath();

    long getDateTaken();

    int getDegreesRotated();

    int getHeight();

    String getMimeType();

    String getTitle();

    int getWidth();

    boolean isDrm();

    boolean isReadonly();

    Bitmap miniThumbBitmap();

    boolean rotateImageBy(int i);

    Bitmap thumbBitmap(boolean z);
}