package com.nuvent.shareat.util.crop;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.BitmapFactory.Options;
import android.media.ExifInterface;
import android.net.Uri;
import android.util.Log;
import com.naver.maps.map.NaverMap;
import com.nuvent.shareat.util.crop.camera.BitmapManager;
import com.nuvent.shareat.util.crop.camera.Util;
import java.io.IOException;

public class Image extends BaseImage implements IImage {
    private static final String TAG = "BaseImage";
    private static final String[] THUMB_PROJECTION = {"_id"};
    private ExifInterface mExif;
    private int mRotation;

    public Image(BaseImageList container, ContentResolver cr, long id, int index, Uri uri, String dataPath, String mimeType, long dateTaken, String title, int rotation) {
        super(container, cr, id, index, uri, dataPath, mimeType, dateTaken, title);
        this.mRotation = rotation;
    }

    public int getDegreesRotated() {
        return this.mRotation;
    }

    /* access modifiers changed from: protected */
    public void setDegreesRotated(int degrees) {
        if (this.mRotation != degrees) {
            this.mRotation = degrees;
            ContentValues values = new ContentValues();
            values.put("orientation", Integer.valueOf(this.mRotation));
            this.mContentResolver.update(this.mUri, values, null, null);
        }
    }

    public boolean isReadonly() {
        String mimeType = getMimeType();
        return !"image/jpeg".equals(mimeType) && !"image/png".equals(mimeType);
    }

    public boolean isDrm() {
        return false;
    }

    public void replaceExifTag(String tag, String value) {
        if (this.mExif == null) {
            loadExifData();
        }
        this.mExif.setAttribute(tag, value);
    }

    private void loadExifData() {
        try {
            this.mExif = new ExifInterface(this.mDataPath);
        } catch (IOException ex) {
            Log.e(TAG, "cannot read exif", ex);
        }
    }

    private void saveExifData() throws IOException {
        if (this.mExif != null) {
            this.mExif.saveAttributes();
        }
    }

    private void setExifRotation(int degrees) {
        try {
            int degrees2 = degrees % NaverMap.MAXIMUM_BEARING;
            if (degrees2 < 0) {
                degrees2 += NaverMap.MAXIMUM_BEARING;
            }
            int orientation = 1;
            switch (degrees2) {
                case 0:
                    orientation = 1;
                    break;
                case 90:
                    orientation = 6;
                    break;
                case 180:
                    orientation = 3;
                    break;
                case 270:
                    orientation = 8;
                    break;
            }
            replaceExifTag("Orientation", Integer.toString(orientation));
            saveExifData();
        } catch (Exception ex) {
            Log.e(TAG, "unable to save exif data with new orientation " + fullSizeImageUri(), ex);
        }
    }

    public boolean rotateImageBy(int degrees) {
        int newDegrees = (getDegreesRotated() + degrees) % NaverMap.MAXIMUM_BEARING;
        setExifRotation(newDegrees);
        setDegreesRotated(newDegrees);
        return true;
    }

    public Bitmap thumbBitmap(boolean rotateAsNeeded) {
        Options options = new Options();
        options.inDither = false;
        options.inPreferredConfig = Config.ARGB_8888;
        Bitmap bitmap = BitmapManager.instance().getThumbnail(this.mContentResolver, this.mId, 1, options, false);
        if (bitmap == null || !rotateAsNeeded) {
            return bitmap;
        }
        return Util.rotate(bitmap, getDegreesRotated());
    }
}