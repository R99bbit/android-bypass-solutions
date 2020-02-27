package com.nuvent.shareat.util.crop.camera;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.location.Location;
import android.media.ExifInterface;
import android.net.Uri;
import android.os.Environment;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.provider.MediaStore;
import android.provider.MediaStore.Images.Media;
import android.provider.MediaStore.Images.Thumbnails;
import android.util.Log;
import com.naver.maps.map.NaverMapSdk;
import com.nuvent.shareat.util.crop.BaseImageList;
import com.nuvent.shareat.util.crop.IImage;
import com.nuvent.shareat.util.crop.IImageList;
import com.nuvent.shareat.util.crop.ImageList;
import com.nuvent.shareat.util.crop.ImageListUber;
import com.nuvent.shareat.util.crop.SingleImageList;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

public class ImageManager {
    public static final String CAMERA_IMAGE_BUCKET_ID = getBucketId(CAMERA_IMAGE_BUCKET_NAME);
    public static final String CAMERA_IMAGE_BUCKET_NAME = (Environment.getExternalStorageDirectory().toString() + "/DCIM/Camera");
    public static final int INCLUDE_IMAGES = 1;
    public static final int INCLUDE_VIDEOS = 2;
    public static final int SORT_ASCENDING = 1;
    public static final int SORT_DESCENDING = 2;
    private static final Uri STORAGE_URI = Media.EXTERNAL_CONTENT_URI;
    private static final String TAG = "ImageManager";
    private static final Uri THUMB_URI = Thumbnails.EXTERNAL_CONTENT_URI;
    private static final Uri VIDEO_STORAGE_URI = Uri.parse("content://media/external/video/media");

    public enum DataLocation {
        NONE,
        INTERNAL,
        EXTERNAL,
        ALL
    }

    private static class EmptyImageList implements IImageList {
        private EmptyImageList() {
        }

        public void close() {
        }

        public HashMap<String, String> getBucketIds() {
            return new HashMap<>();
        }

        public int getCount() {
            return 0;
        }

        public boolean isEmpty() {
            return true;
        }

        public IImage getImageAt(int i) {
            return null;
        }

        public IImage getImageForUri(Uri uri) {
            return null;
        }

        public boolean removeImage(IImage image) {
            return false;
        }

        public boolean removeImageAt(int i) {
            return false;
        }

        public int getImageIndex(IImage image) {
            throw new UnsupportedOperationException();
        }
    }

    public static class ImageListParam implements Parcelable {
        public static final Creator CREATOR = new Creator() {
            public ImageListParam createFromParcel(Parcel in) {
                return new ImageListParam(in);
            }

            public ImageListParam[] newArray(int size) {
                return new ImageListParam[size];
            }
        };
        public String mBucketId;
        public int mInclusion;
        public boolean mIsEmptyImageList;
        public DataLocation mLocation;
        public Uri mSingleImageUri;
        public int mSort;

        public ImageListParam() {
        }

        public void writeToParcel(Parcel out, int flags) {
            out.writeInt(this.mLocation.ordinal());
            out.writeInt(this.mInclusion);
            out.writeInt(this.mSort);
            out.writeString(this.mBucketId);
            out.writeParcelable(this.mSingleImageUri, flags);
            out.writeInt(this.mIsEmptyImageList ? 1 : 0);
        }

        private ImageListParam(Parcel in) {
            this.mLocation = DataLocation.values()[in.readInt()];
            this.mInclusion = in.readInt();
            this.mSort = in.readInt();
            this.mBucketId = in.readString();
            this.mSingleImageUri = (Uri) in.readParcelable(null);
            this.mIsEmptyImageList = in.readInt() != 0;
        }

        public String toString() {
            return String.format("ImageListParam{loc=%s,inc=%d,sort=%d,bucket=%s,empty=%b,single=%s}", new Object[]{this.mLocation, Integer.valueOf(this.mInclusion), Integer.valueOf(this.mSort), this.mBucketId, Boolean.valueOf(this.mIsEmptyImageList), this.mSingleImageUri});
        }

        public int describeContents() {
            return 0;
        }
    }

    public static String getBucketId(String path) {
        return String.valueOf(path.toLowerCase().hashCode());
    }

    public static void ensureOSXCompatibleFolder() {
        File nnnAAAAA = new File(Environment.getExternalStorageDirectory().toString() + "/DCIM/100ANDRO");
        if (!nnnAAAAA.exists() && !nnnAAAAA.mkdir()) {
            Log.e(TAG, "create NNNAAAAA file: " + nnnAAAAA.getPath() + " failed");
        }
    }

    public static boolean isImageMimeType(String mimeType) {
        return mimeType.startsWith("image/");
    }

    public static boolean isImage(IImage image) {
        return isImageMimeType(image.getMimeType());
    }

    public static Uri addImage(ContentResolver cr, String title, long dateTaken, Location location, String directory, String filename, Bitmap source, byte[] jpegData, int[] degree) {
        OutputStream outputStream = null;
        String filePath = directory + "/" + filename;
        try {
            File dir = new File(directory);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            OutputStream outputStream2 = new FileOutputStream(new File(directory, filename));
            if (source != null) {
                try {
                    source.compress(CompressFormat.JPEG, 75, outputStream2);
                    degree[0] = 0;
                } catch (FileNotFoundException e) {
                    ex = e;
                    outputStream = outputStream2;
                } catch (IOException e2) {
                    ex = e2;
                    outputStream = outputStream2;
                    Log.w(TAG, ex);
                    Util.closeSilently((Closeable) outputStream);
                    return null;
                } catch (Throwable th) {
                    th = th;
                    outputStream = outputStream2;
                    Util.closeSilently((Closeable) outputStream);
                    throw th;
                }
            } else {
                outputStream2.write(jpegData);
                degree[0] = getExifOrientation(filePath);
            }
            Util.closeSilently((Closeable) outputStream2);
            ContentValues values = new ContentValues(7);
            values.put("title", title);
            values.put("_display_name", filename);
            values.put("datetaken", Long.valueOf(dateTaken));
            values.put("mime_type", "image/jpeg");
            values.put("orientation", Integer.valueOf(degree[0]));
            values.put("_data", filePath);
            if (location != null) {
                values.put("latitude", Double.valueOf(location.getLatitude()));
                values.put("longitude", Double.valueOf(location.getLongitude()));
            }
            FileOutputStream fileOutputStream = outputStream2;
            return cr.insert(STORAGE_URI, values);
        } catch (FileNotFoundException e3) {
            ex = e3;
            try {
                Log.w(TAG, ex);
                Util.closeSilently((Closeable) outputStream);
                return null;
            } catch (Throwable th2) {
                th = th2;
                Util.closeSilently((Closeable) outputStream);
                throw th;
            }
        } catch (IOException e4) {
            ex = e4;
            Log.w(TAG, ex);
            Util.closeSilently((Closeable) outputStream);
            return null;
        }
    }

    public static int getExifOrientation(String filepath) {
        ExifInterface exif = null;
        try {
            exif = new ExifInterface(filepath);
        } catch (IOException ex) {
            Log.e(TAG, "cannot read exif", ex);
        }
        if (exif == null) {
            return 0;
        }
        int orientation = exif.getAttributeInt("Orientation", -1);
        if (orientation == -1) {
            return 0;
        }
        switch (orientation) {
            case 3:
                return 180;
            case 6:
                return 90;
            case 8:
                return 270;
            default:
                return 0;
        }
    }

    public static IImageList makeImageList(ContentResolver cr, ImageListParam param) {
        DataLocation location = param.mLocation;
        int inclusion = param.mInclusion;
        int sort = param.mSort;
        String bucketId = param.mBucketId;
        Uri singleImageUri = param.mSingleImageUri;
        if (param.mIsEmptyImageList || cr == null) {
            return new EmptyImageList();
        }
        if (singleImageUri != null) {
            return new SingleImageList(cr, singleImageUri);
        }
        boolean haveSdCard = hasStorage(false);
        ArrayList<BaseImageList> l = new ArrayList<>();
        if (!(!haveSdCard || location == DataLocation.INTERNAL || (inclusion & 1) == 0)) {
            l.add(new ImageList(cr, STORAGE_URI, sort, bucketId));
        }
        if ((location == DataLocation.INTERNAL || location == DataLocation.ALL) && (inclusion & 1) != 0) {
            l.add(new ImageList(cr, Media.INTERNAL_CONTENT_URI, sort, bucketId));
        }
        Iterator<BaseImageList> it = l.iterator();
        while (it.hasNext()) {
            BaseImageList sublist = it.next();
            if (sublist.isEmpty()) {
                sublist.close();
                it.remove();
            }
        }
        if (l.size() == 1) {
            return l.get(0);
        }
        return new ImageListUber((IImageList[]) l.toArray(new IImageList[l.size()]), sort);
    }

    public static IImageList makeImageList(ContentResolver cr, Uri uri, int sort) {
        String uriString = uri != null ? uri.toString() : "";
        if (uriString.startsWith("content://media/external/video")) {
            return makeImageList(cr, DataLocation.EXTERNAL, 2, sort, null);
        }
        if (isSingleImageMode(uriString)) {
            return makeSingleImageList(cr, uri);
        }
        return makeImageList(cr, DataLocation.ALL, 1, sort, uri.getQueryParameter("bucketId"));
    }

    static boolean isSingleImageMode(String uriString) {
        return !uriString.startsWith(Media.EXTERNAL_CONTENT_URI.toString()) && !uriString.startsWith(Media.INTERNAL_CONTENT_URI.toString());
    }

    public static ImageListParam getImageListParam(DataLocation location, int inclusion, int sort, String bucketId) {
        ImageListParam param = new ImageListParam();
        param.mLocation = location;
        param.mInclusion = inclusion;
        param.mSort = sort;
        param.mBucketId = bucketId;
        return param;
    }

    public static ImageListParam getSingleImageListParam(Uri uri) {
        ImageListParam param = new ImageListParam();
        param.mSingleImageUri = uri;
        return param;
    }

    public static ImageListParam getEmptyImageListParam() {
        ImageListParam param = new ImageListParam();
        param.mIsEmptyImageList = true;
        return param;
    }

    public static IImageList makeImageList(ContentResolver cr, DataLocation location, int inclusion, int sort, String bucketId) {
        return makeImageList(cr, getImageListParam(location, inclusion, sort, bucketId));
    }

    public static IImageList makeEmptyImageList() {
        return makeImageList(null, getEmptyImageListParam());
    }

    public static IImageList makeSingleImageList(ContentResolver cr, Uri uri) {
        return makeImageList(cr, getSingleImageListParam(uri));
    }

    private static boolean checkFsWritable() {
        String directoryName = Environment.getExternalStorageDirectory().toString() + "/DCIM";
        File directory = new File(directoryName);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            return false;
        }
        File f = new File(directoryName, ".probe");
        try {
            if (f.exists()) {
                f.delete();
            }
            if (!f.createNewFile()) {
                return false;
            }
            f.delete();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public static boolean hasStorage() {
        return hasStorage(true);
    }

    public static boolean hasStorage(boolean requireWriteAccess) {
        String state = Environment.getExternalStorageState();
        if ("mounted".equals(state)) {
            if (requireWriteAccess) {
                return checkFsWritable();
            }
            return true;
        } else if (requireWriteAccess || !"mounted_ro".equals(state)) {
            return false;
        } else {
            return true;
        }
    }

    private static Cursor query(ContentResolver resolver, Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        Cursor cursor = null;
        if (resolver == null) {
            return cursor;
        }
        try {
            return resolver.query(uri, projection, selection, selectionArgs, sortOrder);
        } catch (UnsupportedOperationException e) {
            return cursor;
        }
    }

    public static boolean isMediaScannerScanning(ContentResolver cr) {
        boolean result = false;
        Cursor cursor = query(cr, MediaStore.getMediaScannerUri(), new String[]{"volume"}, null, null, null);
        if (cursor != null) {
            if (cursor.getCount() == 1) {
                cursor.moveToFirst();
                result = NaverMapSdk.METADATA_VALUE_CACHE_LOCATION_EXTERNAL.equals(cursor.getString(0));
            }
            cursor.close();
        }
        return result;
    }
}