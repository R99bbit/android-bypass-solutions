package com.nuvent.shareat.util.crop;

import android.content.ContentResolver;
import android.net.Uri;
import java.util.HashMap;

public class SingleImageList implements IImageList {
    private static final String TAG = "BaseImageList";
    private IImage mSingleImage;
    private Uri mUri;

    public SingleImageList(ContentResolver resolver, Uri uri) {
        this.mUri = uri;
        this.mSingleImage = new UriImage(this, resolver, uri);
    }

    public HashMap<String, String> getBucketIds() {
        throw new UnsupportedOperationException();
    }

    public int getCount() {
        return 1;
    }

    public boolean isEmpty() {
        return false;
    }

    public int getImageIndex(IImage image) {
        return image == this.mSingleImage ? 0 : -1;
    }

    public IImage getImageAt(int i) {
        if (i == 0) {
            return this.mSingleImage;
        }
        return null;
    }

    public boolean removeImage(IImage image) {
        return false;
    }

    public boolean removeImageAt(int index) {
        return false;
    }

    public IImage getImageForUri(Uri uri) {
        if (uri.equals(this.mUri)) {
            return this.mSingleImage;
        }
        return null;
    }

    public void close() {
        this.mSingleImage = null;
        this.mUri = null;
    }
}