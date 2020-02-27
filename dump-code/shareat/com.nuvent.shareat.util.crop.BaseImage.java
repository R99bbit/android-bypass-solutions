package com.nuvent.shareat.util.crop;

import android.content.ContentResolver;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory.Options;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import com.nuvent.shareat.util.crop.camera.BitmapManager;
import com.nuvent.shareat.util.crop.camera.Util;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public abstract class BaseImage implements IImage {
    private static final String TAG = "BaseImage";
    private static final int UNKNOWN_LENGTH = -1;
    protected BaseImageList mContainer;
    protected ContentResolver mContentResolver;
    protected String mDataPath;
    private final long mDateTaken;
    private int mHeight = -1;
    protected long mId;
    protected final int mIndex;
    protected String mMimeType;
    private String mTitle;
    protected Uri mUri;
    private int mWidth = -1;

    protected BaseImage(BaseImageList container, ContentResolver cr, long id, int index, Uri uri, String dataPath, String mimeType, long dateTaken, String title) {
        this.mContainer = container;
        this.mContentResolver = cr;
        this.mId = id;
        this.mIndex = index;
        this.mUri = uri;
        this.mDataPath = dataPath;
        this.mMimeType = mimeType;
        this.mDateTaken = dateTaken;
        this.mTitle = title;
    }

    public String getDataPath() {
        return this.mDataPath;
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof Image)) {
            return false;
        }
        return this.mUri.equals(((Image) other).mUri);
    }

    public int hashCode() {
        return this.mUri.hashCode();
    }

    public Bitmap fullSizeBitmap(int minSideLength, int maxNumberOfPixels) {
        return fullSizeBitmap(minSideLength, maxNumberOfPixels, true, false);
    }

    public Bitmap fullSizeBitmap(int minSideLength, int maxNumberOfPixels, boolean rotateAsNeeded, boolean useNative) {
        Uri url = this.mContainer.contentUri(this.mId);
        if (url == null) {
            return null;
        }
        Bitmap b = Util.makeBitmap(minSideLength, maxNumberOfPixels, url, this.mContentResolver, useNative);
        if (b == null || !rotateAsNeeded) {
            return b;
        }
        return Util.rotate(b, getDegreesRotated());
    }

    public InputStream fullSizeImageData() {
        try {
            return this.mContentResolver.openInputStream(this.mUri);
        } catch (IOException e) {
            return null;
        }
    }

    public Uri fullSizeImageUri() {
        return this.mUri;
    }

    public IImageList getContainer() {
        return this.mContainer;
    }

    public long getDateTaken() {
        return this.mDateTaken;
    }

    public int getDegreesRotated() {
        return 0;
    }

    public String getMimeType() {
        return this.mMimeType;
    }

    public String getTitle() {
        return this.mTitle;
    }

    private void setupDimension() {
        ParcelFileDescriptor input = null;
        try {
            input = this.mContentResolver.openFileDescriptor(this.mUri, "r");
            Options options = new Options();
            options.inJustDecodeBounds = true;
            BitmapManager.instance().decodeFileDescriptor(input.getFileDescriptor(), options);
            this.mWidth = options.outWidth;
            this.mHeight = options.outHeight;
        } catch (FileNotFoundException e) {
            this.mWidth = 0;
            this.mHeight = 0;
        } finally {
            Util.closeSilently(input);
        }
    }

    public int getWidth() {
        if (this.mWidth == -1) {
            setupDimension();
        }
        return this.mWidth;
    }

    public int getHeight() {
        if (this.mHeight == -1) {
            setupDimension();
        }
        return this.mHeight;
    }

    public Bitmap miniThumbBitmap() {
        try {
            Bitmap b = BitmapManager.instance().getThumbnail(this.mContentResolver, this.mId, 3, null, false);
            if (b != null) {
                b = Util.rotate(b, getDegreesRotated());
            }
            return b;
        } catch (Throwable ex) {
            Log.e(TAG, "miniThumbBitmap got exception", ex);
            return null;
        }
    }

    /* access modifiers changed from: protected */
    public void onRemove() {
    }

    public String toString() {
        return this.mUri.toString();
    }
}