package com.nuvent.shareat.util.crop;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.provider.MediaStore.Images.Media;
import com.facebook.internal.ServerProtocol;
import java.util.HashMap;

public class ImageList extends BaseImageList implements IImageList {
    private static final String[] ACCEPTABLE_IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif"};
    static final String[] IMAGE_PROJECTION = {"_id", "_data", "datetaken", "mini_thumb_magic", "orientation", "title", "mime_type", "date_modified"};
    private static final int INDEX_DATA_PATH = 1;
    private static final int INDEX_DATE_MODIFIED = 7;
    private static final int INDEX_DATE_TAKEN = 2;
    private static final int INDEX_ID = 0;
    private static final int INDEX_MIME_TYPE = 6;
    private static final int INDEX_MINI_THUMB_MAGIC = 3;
    private static final int INDEX_ORIENTATION = 4;
    private static final int INDEX_TITLE = 5;
    private static final String TAG = "ImageList";
    private static final String WHERE_CLAUSE = "(mime_type in (?, ?, ?))";
    private static final String WHERE_CLAUSE_WITH_BUCKET_ID = "(mime_type in (?, ?, ?)) AND bucket_id = ?";

    public HashMap<String, String> getBucketIds() {
        Uri uri = this.mBaseUri.buildUpon().appendQueryParameter("distinct", ServerProtocol.DIALOG_RETURN_SCOPES_TRUE).build();
        Cursor cursor = Media.query(this.mContentResolver, uri, new String[]{"bucket_display_name", "bucket_id"}, whereClause(), whereClauseArgs(), null);
        try {
            HashMap<String, String> hash = new HashMap<>();
            while (cursor.moveToNext()) {
                hash.put(cursor.getString(1), cursor.getString(0));
            }
            return hash;
        } finally {
            cursor.close();
        }
    }

    public ImageList(ContentResolver resolver, Uri imageUri, int sort, String bucketId) {
        super(resolver, imageUri, sort, bucketId);
    }

    /* access modifiers changed from: protected */
    public String whereClause() {
        return this.mBucketId == null ? WHERE_CLAUSE : WHERE_CLAUSE_WITH_BUCKET_ID;
    }

    /* access modifiers changed from: protected */
    public String[] whereClauseArgs() {
        if (this.mBucketId == null) {
            return ACCEPTABLE_IMAGE_TYPES;
        }
        int count = ACCEPTABLE_IMAGE_TYPES.length;
        String[] result = new String[(count + 1)];
        System.arraycopy(ACCEPTABLE_IMAGE_TYPES, 0, result, 0, count);
        result[count] = this.mBucketId;
        return result;
    }

    /* access modifiers changed from: protected */
    public Cursor createCursor() {
        return Media.query(this.mContentResolver, this.mBaseUri, IMAGE_PROJECTION, whereClause(), whereClauseArgs(), sortOrder());
    }

    /* access modifiers changed from: protected */
    public long getImageId(Cursor cursor) {
        return cursor.getLong(0);
    }

    /* access modifiers changed from: protected */
    public BaseImage loadImageFromCursor(Cursor cursor) {
        long id = cursor.getLong(0);
        String dataPath = cursor.getString(1);
        long dateTaken = cursor.getLong(2);
        if (dateTaken == 0) {
            dateTaken = cursor.getLong(7) * 1000;
        }
        long j = cursor.getLong(3);
        int orientation = cursor.getInt(4);
        String title = cursor.getString(5);
        String mimeType = cursor.getString(6);
        if (title == null || title.length() == 0) {
            title = dataPath;
        }
        return new Image(this, this.mContentResolver, id, cursor.getPosition(), contentUri(id), dataPath, mimeType, dateTaken, title, orientation);
    }
}