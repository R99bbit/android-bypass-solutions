package com.nuvent.shareat.util.crop;

import android.content.ContentResolver;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory.Options;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import com.nuvent.shareat.util.crop.camera.BitmapManager;
import com.nuvent.shareat.util.crop.camera.Util;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

class UriImage implements IImage {
    private static final String TAG = "UriImage";
    private final IImageList mContainer;
    private final ContentResolver mContentResolver;
    private final Uri mUri;

    UriImage(IImageList container, ContentResolver cr, Uri uri) {
        this.mContainer = container;
        this.mContentResolver = cr;
        this.mUri = uri;
    }

    public int getDegreesRotated() {
        return 0;
    }

    public String getDataPath() {
        return this.mUri.getPath();
    }

    private InputStream getInputStream() {
        try {
            if (this.mUri.getScheme().equals("file")) {
                return new FileInputStream(this.mUri.getPath());
            }
            return this.mContentResolver.openInputStream(this.mUri);
        } catch (FileNotFoundException e) {
            return null;
        }
    }

    private ParcelFileDescriptor getPFD() {
        try {
            if (this.mUri.getScheme().equals("file")) {
                return ParcelFileDescriptor.open(new File(this.mUri.getPath()), 268435456);
            }
            return this.mContentResolver.openFileDescriptor(this.mUri, "r");
        } catch (FileNotFoundException e) {
            return null;
        }
    }

    public Bitmap fullSizeBitmap(int minSideLength, int maxNumberOfPixels) {
        return fullSizeBitmap(minSideLength, maxNumberOfPixels, true, false);
    }

    public Bitmap fullSizeBitmap(int minSideLength, int maxNumberOfPixels, boolean rotateAsNeeded) {
        return fullSizeBitmap(minSideLength, maxNumberOfPixels, rotateAsNeeded, false);
    }

    public Bitmap fullSizeBitmap(int minSideLength, int maxNumberOfPixels, boolean rotateAsNeeded, boolean useNative) {
        try {
            return Util.makeBitmap(minSideLength, maxNumberOfPixels, getPFD(), useNative);
        } catch (Exception ex) {
            Log.e(TAG, "got exception decoding bitmap ", ex);
            return null;
        }
    }

    public Uri fullSizeImageUri() {
        return this.mUri;
    }

    public InputStream fullSizeImageData() {
        return getInputStream();
    }

    public Bitmap miniThumbBitmap() {
        return thumbBitmap(true);
    }

    public String getTitle() {
        return this.mUri.toString();
    }

    public Bitmap thumbBitmap(boolean rotateAsNeeded) {
        return fullSizeBitmap(IImage.THUMBNAIL_TARGET_SIZE, IImage.THUMBNAIL_MAX_NUM_PIXELS, rotateAsNeeded);
    }

    private Options snifBitmapOptions() {
        ParcelFileDescriptor input = getPFD();
        if (input == null) {
            return null;
        }
        try {
            Options options = new Options();
            options.inJustDecodeBounds = true;
            BitmapManager.instance().decodeFileDescriptor(input.getFileDescriptor(), options);
            return options;
        } finally {
            Util.closeSilently(input);
        }
    }

    public String getMimeType() {
        Options options = snifBitmapOptions();
        return (options == null || options.outMimeType == null) ? "" : options.outMimeType;
    }

    public int getHeight() {
        Options options = snifBitmapOptions();
        if (options != null) {
            return options.outHeight;
        }
        return 0;
    }

    public int getWidth() {
        Options options = snifBitmapOptions();
        if (options != null) {
            return options.outWidth;
        }
        return 0;
    }

    public IImageList getContainer() {
        return this.mContainer;
    }

    public long getDateTaken() {
        return 0;
    }

    public boolean isReadonly() {
        return true;
    }

    public boolean isDrm() {
        return false;
    }

    public boolean rotateImageBy(int degrees) {
        return false;
    }
}