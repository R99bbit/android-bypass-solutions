package com.nuvent.shareat.util.crop;

import android.content.ContentResolver;
import android.content.ContentUris;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;
import com.nuvent.shareat.util.crop.camera.Util;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class BaseImageList implements IImageList {
    private static final int CACHE_CAPACITY = 512;
    private static final String TAG = "BaseImageList";
    private static final Pattern sPathWithId = Pattern.compile("(.*)/\\d+");
    protected Uri mBaseUri;
    protected String mBucketId;
    private final LruCache<Integer, BaseImage> mCache = new LruCache<>(512);
    protected ContentResolver mContentResolver;
    protected Cursor mCursor;
    protected boolean mCursorDeactivated = false;
    protected int mSort;

    /* access modifiers changed from: protected */
    public abstract Cursor createCursor();

    /* access modifiers changed from: protected */
    public abstract long getImageId(Cursor cursor);

    /* access modifiers changed from: protected */
    public abstract BaseImage loadImageFromCursor(Cursor cursor);

    public BaseImageList(ContentResolver resolver, Uri uri, int sort, String bucketId) {
        this.mSort = sort;
        this.mBaseUri = uri;
        this.mBucketId = bucketId;
        this.mContentResolver = resolver;
        this.mCursor = createCursor();
        if (this.mCursor == null) {
            Log.w(TAG, "createCursor returns null.");
        }
        this.mCache.clear();
    }

    public void close() {
        try {
            invalidateCursor();
        } catch (IllegalStateException e) {
            Log.e(TAG, "Caught exception while deactivating cursor.", e);
        }
        this.mContentResolver = null;
        if (this.mCursor != null) {
            this.mCursor.close();
            this.mCursor = null;
        }
    }

    public Uri contentUri(long id) {
        try {
            if (ContentUris.parseId(this.mBaseUri) != id) {
                Log.e(TAG, "id mismatch");
            }
            return this.mBaseUri;
        } catch (NumberFormatException e) {
            return ContentUris.withAppendedId(this.mBaseUri, id);
        }
    }

    public int getCount() {
        int count;
        Cursor cursor = getCursor();
        if (cursor == null) {
            return 0;
        }
        synchronized (this) {
            count = cursor.getCount();
        }
        return count;
    }

    public boolean isEmpty() {
        return getCount() == 0;
    }

    private Cursor getCursor() {
        Cursor cursor;
        synchronized (this) {
            if (this.mCursor == null) {
                cursor = null;
            } else {
                if (this.mCursorDeactivated) {
                    this.mCursor.requery();
                    this.mCursorDeactivated = false;
                }
                cursor = this.mCursor;
            }
        }
        return cursor;
    }

    public IImage getImageAt(int i) {
        BaseImage result = (BaseImage) this.mCache.get(Integer.valueOf(i));
        if (result == null) {
            Cursor cursor = getCursor();
            if (cursor == null) {
                return null;
            }
            synchronized (this) {
                if (cursor.moveToPosition(i)) {
                    result = loadImageFromCursor(cursor);
                } else {
                    result = null;
                }
                this.mCache.put(Integer.valueOf(i), result);
            }
        }
        return result;
    }

    public boolean removeImage(IImage image) {
        if (this.mContentResolver.delete(image.fullSizeImageUri(), null, null) <= 0) {
            return false;
        }
        ((BaseImage) image).onRemove();
        invalidateCursor();
        invalidateCache();
        return true;
    }

    public boolean removeImageAt(int i) {
        return removeImage(getImageAt(i));
    }

    /* access modifiers changed from: protected */
    public void invalidateCursor() {
        if (this.mCursor != null) {
            this.mCursor.deactivate();
            this.mCursorDeactivated = true;
        }
    }

    /* access modifiers changed from: protected */
    public void invalidateCache() {
        this.mCache.clear();
    }

    private static String getPathWithoutId(Uri uri) {
        String path = uri.getPath();
        Matcher matcher = sPathWithId.matcher(path);
        return matcher.matches() ? matcher.group(1) : path;
    }

    private boolean isChildImageUri(Uri uri) {
        Uri base = this.mBaseUri;
        return Util.equals(base.getScheme(), uri.getScheme()) && Util.equals(base.getHost(), uri.getHost()) && Util.equals(base.getAuthority(), uri.getAuthority()) && Util.equals(base.getPath(), getPathWithoutId(uri));
    }

    public IImage getImageForUri(Uri uri) {
        BaseImage image = null;
        if (isChildImageUri(uri)) {
            try {
                long matchId = ContentUris.parseId(uri);
                Cursor cursor = getCursor();
                if (cursor != null) {
                    synchronized (this) {
                        cursor.moveToPosition(-1);
                        int i = 0;
                        while (true) {
                            if (!cursor.moveToNext()) {
                                break;
                            } else if (getImageId(cursor) == matchId) {
                                image = (BaseImage) this.mCache.get(Integer.valueOf(i));
                                if (image == null) {
                                    image = loadImageFromCursor(cursor);
                                    this.mCache.put(Integer.valueOf(i), image);
                                }
                            } else {
                                i++;
                            }
                        }
                    }
                }
            } catch (NumberFormatException ex) {
                Log.i(TAG, "fail to get id in: " + uri, ex);
            }
        }
        return image;
    }

    public int getImageIndex(IImage image) {
        return ((BaseImage) image).mIndex;
    }

    /* access modifiers changed from: protected */
    public String sortOrder() {
        String ascending = this.mSort == 1 ? " ASC" : " DESC";
        return "case ifnull(datetaken,0) when 0 then date_modified*1000 else datetaken end" + ascending + ", _id" + ascending;
    }
}