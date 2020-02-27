package net.xenix.util;

import android.content.Context;
import android.database.Cursor;
import android.database.CursorIndexOutOfBoundsException;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.graphics.Bitmap.Config;
import android.graphics.BitmapFactory;
import android.graphics.BitmapFactory.Options;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Path.Direction;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.media.ExifInterface;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Environment;
import android.provider.MediaStore.Images.Media;
import android.view.View;
import android.widget.ImageView;
import com.nostra13.universalimageloader.cache.disc.naming.Md5FileNameGenerator;
import com.nostra13.universalimageloader.cache.memory.impl.WeakMemoryCache;
import com.nostra13.universalimageloader.core.DisplayImageOptions;
import com.nostra13.universalimageloader.core.ImageLoader;
import com.nostra13.universalimageloader.core.ImageLoaderConfiguration.Builder;
import com.nostra13.universalimageloader.core.assist.ImageScaleType;
import com.nostra13.universalimageloader.core.assist.QueueProcessingType;
import com.nostra13.universalimageloader.core.display.FadeInBitmapDisplayer;
import com.nostra13.universalimageloader.core.listener.ImageLoadingListener;
import com.nostra13.universalimageloader.core.listener.SimpleImageLoadingListener;
import com.nostra13.universalimageloader.utils.L;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class ImageDisplay {
    public static final int GALLERY_INTENT_CALLED = 102;
    public static final int GALLERY_KITKAT_INTENT_CALLED = 101;
    public static final int MAX_IMAGE_SIZE = 1920;
    public static final String SHARE_FILE_NAME = "/shareat_crop.png";
    public static final String TEMP_SHARE_FILE_NAME = "/_shareat_crop.png";
    public static final int THUMBNAIL_IMAGE_SIZE = 640;
    private static ImageDisplay instance = new ImageDisplay();
    public static ImageLoadingListener mAimateFirstListener = new AnimateFirstDisplayListener();
    private DisplayImageOptions mDisplayImageOptions;
    private DisplayImageOptions mDisplayImageOptionsThumbnail;

    public static class AnimateFirstDisplayListener extends SimpleImageLoadingListener {
        private final List<String> displayedImages = Collections.synchronizedList(new LinkedList());

        public void onLoadingComplete(String imageUri, View view, Bitmap loadedImage) {
            if (loadedImage != null) {
                ImageView imageView = (ImageView) view;
                if (!this.displayedImages.contains(imageUri)) {
                    FadeInBitmapDisplayer.animate(imageView, 1000);
                    this.displayedImages.add(imageUri);
                }
            }
        }
    }

    public static synchronized ImageDisplay getInstance() {
        ImageDisplay imageDisplay;
        synchronized (ImageDisplay.class) {
            try {
                imageDisplay = instance;
            }
        }
        return imageDisplay;
    }

    public void initImageLoader(Context context) {
        ImageLoader.getInstance().init(new Builder(context).threadPriority(4).taskExecutor(AsyncTask.THREAD_POOL_EXECUTOR).taskExecutorForCachedImages(AsyncTask.THREAD_POOL_EXECUTOR).threadPoolSize(3).memoryCache(new WeakMemoryCache()).denyCacheImageMultipleSizesInMemory().diskCacheFileNameGenerator(new Md5FileNameGenerator()).diskCacheSize(1048576000).diskCacheFileCount(1000).tasksProcessingOrder(QueueProcessingType.LIFO).build());
        L.writeLogs(false);
        setDisplayOption();
    }

    public static void cacheClear() {
        ImageLoader.getInstance().clearDiskCache();
        ImageLoader.getInstance().clearMemoryCache();
    }

    public void displayImageLoad(String imageUrl, ImageView imageView, int resourceId) {
        ImageLoader.getInstance().displayImage(imageUrl, imageView, new DisplayImageOptions.Builder().showImageOnLoading(resourceId).showImageOnFail(resourceId).showImageForEmptyUri(resourceId).cacheInMemory(true).cacheOnDisk(true).bitmapConfig(Config.ARGB_8888).imageScaleType(ImageScaleType.IN_SAMPLE_INT).considerExifParams(true).build(), mAimateFirstListener);
    }

    public void displayImageLoad(String imageUrl, ImageView imageView, ImageLoadingListener listener) {
        ImageLoader.getInstance().displayImage(imageUrl, imageView, this.mDisplayImageOptions, listener);
    }

    public void displayImageLoad(String imageUrl, ImageView imageView, int resourceId, ImageLoadingListener listener) {
        ImageLoader.getInstance().displayImage(imageUrl, imageView, new DisplayImageOptions.Builder().showImageOnLoading(resourceId).showImageOnFail(resourceId).showImageForEmptyUri(resourceId).cacheInMemory(true).cacheOnDisk(true).bitmapConfig(Config.ARGB_8888).imageScaleType(ImageScaleType.IN_SAMPLE_INT).considerExifParams(true).build(), listener);
    }

    public void displayImageLoad(String imageUrl, ImageView imageView) {
        ImageLoader.getInstance().displayImage(setImageUrl(imageUrl), imageView, this.mDisplayImageOptions, mAimateFirstListener);
    }

    public void displayImageLoadEx(String imageUrl, ImageView imageView, int resourceId) {
        DisplayImageOptions options = new DisplayImageOptions.Builder().showImageOnLoading(resourceId).showImageOnFail(resourceId).cacheInMemory(true).cacheOnDisk(true).bitmapConfig(Config.RGB_565).imageScaleType(ImageScaleType.IN_SAMPLE_INT).considerExifParams(true).build();
        ImageLoader.getInstance().displayImage(setImageUrl(imageUrl), imageView, options, mAimateFirstListener);
    }

    public void displayImageLoadRound(String imageUrl, ImageView imageView, int roundSize) {
        displayImageLoadRound(imageUrl, imageView, roundSize, (int) R.drawable.profile_user_none);
    }

    public void displayImageLoadListRound(String imageUrl, ImageView imageView, int roundSize) {
        displayImageLoadRound(imageUrl, imageView, roundSize, (int) R.drawable.list_user_none);
    }

    public void displayImageLoadListRound(String imageUrl, ImageView imageView, int roundSize, int resource) {
        displayImageLoadRound(imageUrl, imageView, roundSize, resource);
    }

    public void displayImageLoadRoundStore(String imageUrl, ImageView imageView, int roundSize) {
        displayImageLoadRound(imageUrl, imageView, roundSize, (int) R.drawable.n_friend_visit_interest_img);
    }

    public void displayImageLoadCard(String imageUrl, ImageView imageView) {
        displayImageLoad(imageUrl, imageView);
    }

    public void displayImageLoadThumb(String imageUrl, ImageView imageView, int roundSize) {
        ImageLoader.getInstance().displayImage(imageUrl, imageView, new DisplayImageOptions.Builder().cacheInMemory(true).cacheOnDisk(true).bitmapConfig(Config.ARGB_8888).imageScaleType(ImageScaleType.IN_SAMPLE_INT).considerExifParams(true).displayer(new RoundedAlphaBitmapDisplayer(roundSize / 2, 0, 300)).build(), mAimateFirstListener);
    }

    public void displayImageLoadRound(String imageUrl, ImageView imageView, int roundSize, int resourceId) {
        ImageLoader.getInstance().displayImage(imageUrl, imageView, new DisplayImageOptions.Builder().showImageOnLoading(resourceId).showImageOnFail(resourceId).showImageForEmptyUri(resourceId).cacheInMemory(true).cacheOnDisk(true).bitmapConfig(Config.ARGB_8888).imageScaleType(ImageScaleType.IN_SAMPLE_INT).considerExifParams(true).displayer(new RoundedAlphaBitmapDisplayer(roundSize / 2, 0, 300)).build(), mAimateFirstListener);
    }

    public void displayImageLoadRound(String imageUrl, ImageView imageView, int roundSize, ImageLoadingListener listener) {
        ImageLoader.getInstance().displayImage(imageUrl, imageView, new DisplayImageOptions.Builder().showImageOnLoading((int) R.drawable.profile_photo).showImageOnFail((int) R.drawable.profile_photo).showImageForEmptyUri((int) R.drawable.profile_photo).cacheInMemory(true).cacheOnDisk(true).bitmapConfig(Config.ARGB_8888).imageScaleType(ImageScaleType.IN_SAMPLE_INT).considerExifParams(true).displayer(new RoundedAlphaBitmapDisplayer(roundSize / 2, 0, 300)).build(), listener);
    }

    public String setImageUrl(String url) {
        if (url == null) {
            return "";
        }
        if (url.contains("|")) {
            url = url.substring(0, url.indexOf("|"));
        }
        return url;
    }

    /* JADX WARNING: Removed duplicated region for block: B:34:0x0061 A[SYNTHETIC, Splitter:B:34:0x0061] */
    public static String saveBitmapToPNG(Bitmap source, String path) {
        File dir;
        String str;
        if (path == null || path.length() <= 0) {
            dir = Environment.getExternalStorageDirectory();
        } else {
            dir = new File(Environment.getExternalStorageDirectory(), path);
            if (!dir.exists()) {
                dir.mkdirs();
            }
        }
        File pngFile = new File(dir, SHARE_FILE_NAME);
        if (pngFile.exists()) {
            pngFile.delete();
        }
        FileOutputStream fos = null;
        try {
            FileOutputStream fos2 = new FileOutputStream(pngFile);
            try {
                source.compress(CompressFormat.PNG, 100, fos2);
                str = pngFile.getAbsolutePath();
                if (fos2 != null) {
                    try {
                        fos2.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                FileOutputStream fileOutputStream = fos2;
            } catch (FileNotFoundException e2) {
                e = e2;
                fos = fos2;
            } catch (Throwable th) {
                th = th;
                fos = fos2;
                if (fos != null) {
                    try {
                        fos.close();
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    }
                }
                throw th;
            }
        } catch (FileNotFoundException e4) {
            e = e4;
            try {
                e.printStackTrace();
                str = null;
                if (fos != null) {
                    try {
                        fos.close();
                    } catch (IOException e5) {
                        e5.printStackTrace();
                    }
                }
                return str;
            } catch (Throwable th2) {
                th = th2;
                if (fos != null) {
                }
                throw th;
            }
        }
        return str;
    }

    public int[] getImageSize(String filePath) {
        Options options = new Options();
        options.inJustDecodeBounds = true;
        BitmapFactory.decodeFile(filePath, options);
        return new int[]{options.outWidth, options.outHeight};
    }

    public Bitmap getBitmapResizeScale(int resize, String filePath) {
        Options options = new Options();
        options.inJustDecodeBounds = true;
        BitmapFactory.decodeFile(filePath, options);
        int scale = 0;
        if (options.outWidth > resize) {
            scale = (int) Math.pow(2.0d, (double) ((int) Math.round(Math.log(((double) resize) / ((double) Math.max(options.outHeight, options.outWidth))) / Math.log(0.5d))));
        }
        options.inJustDecodeBounds = false;
        options.inSampleSize = scale;
        return rotateBitmap(BitmapFactory.decodeFile(filePath, options), filePath);
    }

    public Bitmap getBitmapResizeScale(String filePath) {
        Options options = new Options();
        options.inJustDecodeBounds = true;
        BitmapFactory.decodeFile(filePath, options);
        int scale = 0;
        if (options.outWidth > 1920) {
            scale = (int) Math.pow(2.0d, (double) ((int) Math.round(Math.log(1920.0d / ((double) Math.max(options.outHeight, options.outWidth))) / Math.log(0.5d))));
        }
        options.inJustDecodeBounds = false;
        options.inSampleSize = scale;
        return rotateBitmap(BitmapFactory.decodeFile(filePath, options), filePath);
    }

    public Bitmap getBitmap(String filePath) {
        return rotateBitmap(BitmapFactory.decodeFile(filePath), filePath);
    }

    /* JADX WARNING: Removed duplicated region for block: B:33:0x00e7 A[SYNTHETIC, Splitter:B:33:0x00e7] */
    /* JADX WARNING: Removed duplicated region for block: B:36:0x00ec  */
    /* JADX WARNING: Removed duplicated region for block: B:54:0x0113 A[SYNTHETIC, Splitter:B:54:0x0113] */
    /* JADX WARNING: Removed duplicated region for block: B:57:0x0118  */
    /* JADX WARNING: Removed duplicated region for block: B:62:0x0124 A[SYNTHETIC, Splitter:B:62:0x0124] */
    /* JADX WARNING: Removed duplicated region for block: B:65:0x0129  */
    /* JADX WARNING: Removed duplicated region for block: B:75:? A[RETURN, SYNTHETIC] */
    /* JADX WARNING: Removed duplicated region for block: B:78:? A[RETURN, SYNTHETIC] */
    /* JADX WARNING: Unknown top exception splitter block from list: {B:29:0x00e0=Splitter:B:29:0x00e0, B:50:0x010c=Splitter:B:50:0x010c} */
    public String getResizeBitmap(int size, String path) {
        String extension = path.substring(path.lastIndexOf("."), path.length());
        String tempPath = Environment.getExternalStorageDirectory().getAbsolutePath() + File.separator + ".temp";
        File tempDir = new File(tempPath);
        if (!tempDir.exists()) {
            tempDir.mkdirs();
        }
        String tempPath2 = tempPath + File.separator + System.currentTimeMillis() + extension;
        Bitmap bitmap = getBitmap(path);
        float width = (float) bitmap.getWidth();
        float height = (float) bitmap.getHeight();
        if (width > ((float) size)) {
            width = (float) size;
            height *= (((float) size) / (width / 100.0f)) / 100.0f;
        }
        Bitmap dstBitmap = Bitmap.createScaledBitmap(bitmap, (int) width, (int) height, true);
        FileOutputStream fos = null;
        try {
            FileOutputStream fos2 = new FileOutputStream(tempPath2);
            try {
                if (extension.equalsIgnoreCase(".JPG") || extension.equalsIgnoreCase(".JPEG")) {
                    dstBitmap.compress(CompressFormat.JPEG, 100, fos2);
                } else if (extension.equalsIgnoreCase(".PNG")) {
                    dstBitmap.compress(CompressFormat.PNG, 100, fos2);
                } else {
                    if (fos2 != null) {
                        try {
                            fos2.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    if (dstBitmap != null) {
                        dstBitmap.recycle();
                    }
                    FileOutputStream fileOutputStream = fos2;
                    return path;
                }
                if (fos2 != null) {
                    try {
                        fos2.close();
                    } catch (IOException e2) {
                        e2.printStackTrace();
                    }
                }
                if (dstBitmap != null) {
                    dstBitmap.recycle();
                }
                FileOutputStream fileOutputStream2 = fos2;
                return tempPath2;
            } catch (FileNotFoundException e3) {
                e1 = e3;
                fos = fos2;
                try {
                    e1.printStackTrace();
                    if (fos != null) {
                    }
                    if (dstBitmap != null) {
                    }
                } catch (Throwable th) {
                    th = th;
                    if (fos != null) {
                        try {
                            fos.close();
                        } catch (IOException e4) {
                            e4.printStackTrace();
                        }
                    }
                    if (dstBitmap != null) {
                        dstBitmap.recycle();
                    }
                    throw th;
                }
            } catch (Exception e5) {
                e1 = e5;
                fos = fos2;
                e1.printStackTrace();
                if (fos != null) {
                }
                if (dstBitmap != null) {
                }
            } catch (Throwable th2) {
                th = th2;
                fos = fos2;
                if (fos != null) {
                }
                if (dstBitmap != null) {
                }
                throw th;
            }
        } catch (FileNotFoundException e6) {
            e1 = e6;
            e1.printStackTrace();
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e7) {
                    e7.printStackTrace();
                }
            }
            if (dstBitmap != null) {
                return null;
            }
            dstBitmap.recycle();
            return null;
        } catch (Exception e8) {
            e1 = e8;
            e1.printStackTrace();
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e9) {
                    e9.printStackTrace();
                }
            }
            if (dstBitmap != null) {
                return null;
            }
            dstBitmap.recycle();
            return null;
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:32:0x00ac A[SYNTHETIC, Splitter:B:32:0x00ac] */
    /* JADX WARNING: Removed duplicated region for block: B:35:0x00b1  */
    /* JADX WARNING: Removed duplicated region for block: B:52:0x00d6 A[SYNTHETIC, Splitter:B:52:0x00d6] */
    /* JADX WARNING: Removed duplicated region for block: B:55:0x00db  */
    /* JADX WARNING: Removed duplicated region for block: B:61:0x00e8 A[SYNTHETIC, Splitter:B:61:0x00e8] */
    /* JADX WARNING: Removed duplicated region for block: B:64:0x00ed  */
    /* JADX WARNING: Unknown top exception splitter block from list: {B:49:0x00d1=Splitter:B:49:0x00d1, B:29:0x00a7=Splitter:B:29:0x00a7} */
    public String getResizeBitmap(String path) {
        String extension = path.substring(path.lastIndexOf("."), path.length());
        String tempPath = Environment.getExternalStorageDirectory().getAbsolutePath() + File.separator + ".temp";
        File tempDir = new File(tempPath);
        if (!tempDir.exists()) {
            tempDir.mkdirs();
        }
        String tempPath2 = tempPath + File.separator + System.currentTimeMillis() + extension;
        Bitmap dstBitmap = getBitmapResizeScale(MAX_IMAGE_SIZE, path);
        if (dstBitmap == null) {
            return null;
        }
        FileOutputStream fos = null;
        try {
            FileOutputStream fos2 = new FileOutputStream(tempPath2);
            try {
                if (extension.equalsIgnoreCase(".JPG") || extension.equalsIgnoreCase(".JPEG")) {
                    dstBitmap.compress(CompressFormat.JPEG, 100, fos2);
                } else if (extension.equalsIgnoreCase(".PNG")) {
                    dstBitmap.compress(CompressFormat.PNG, 100, fos2);
                } else {
                    if (fos2 != null) {
                        try {
                            fos2.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    if (dstBitmap == null) {
                        return path;
                    }
                    dstBitmap.recycle();
                    return path;
                }
                if (fos2 != null) {
                    try {
                        fos2.close();
                    } catch (IOException e2) {
                        e2.printStackTrace();
                    }
                }
                if (dstBitmap != null) {
                    dstBitmap.recycle();
                }
                return tempPath2;
            } catch (FileNotFoundException e3) {
                e1 = e3;
                fos = fos2;
                try {
                    e1.printStackTrace();
                    if (fos != null) {
                    }
                    if (dstBitmap != null) {
                    }
                    return null;
                } catch (Throwable th) {
                    th = th;
                    if (fos != null) {
                        try {
                            fos.close();
                        } catch (IOException e4) {
                            e4.printStackTrace();
                        }
                    }
                    if (dstBitmap != null) {
                        dstBitmap.recycle();
                    }
                    throw th;
                }
            } catch (Exception e5) {
                e1 = e5;
                fos = fos2;
                e1.printStackTrace();
                if (fos != null) {
                }
                if (dstBitmap != null) {
                }
                return null;
            } catch (Throwable th2) {
                th = th2;
                fos = fos2;
                if (fos != null) {
                }
                if (dstBitmap != null) {
                }
                throw th;
            }
        } catch (FileNotFoundException e6) {
            e1 = e6;
            e1.printStackTrace();
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e7) {
                    e7.printStackTrace();
                }
            }
            if (dstBitmap != null) {
                dstBitmap.recycle();
            }
            return null;
        } catch (Exception e8) {
            e1 = e8;
            e1.printStackTrace();
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e9) {
                    e9.printStackTrace();
                }
            }
            if (dstBitmap != null) {
                dstBitmap.recycle();
            }
            return null;
        }
    }

    public static Bitmap rotateBitmap(Bitmap bitmap, String path) {
        try {
            int orientation = new ExifInterface(path).getAttributeInt("Orientation", 1);
            Matrix matrix = new Matrix();
            if (orientation == 6) {
                matrix.postRotate(90.0f);
            } else if (orientation == 3) {
                matrix.postRotate(180.0f);
            } else if (orientation == 8) {
                matrix.postRotate(270.0f);
            }
            return Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(), bitmap.getHeight(), matrix, true);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void setDisplayOption() {
        this.mDisplayImageOptions = new DisplayImageOptions.Builder().cacheInMemory(true).cacheOnDisk(true).bitmapConfig(Config.RGB_565).imageScaleType(ImageScaleType.IN_SAMPLE_INT).considerExifParams(true).build();
        this.mDisplayImageOptionsThumbnail = new DisplayImageOptions.Builder().cacheInMemory(true).cacheOnDisk(true).bitmapConfig(Config.ARGB_8888).imageScaleType(ImageScaleType.IN_SAMPLE_INT).considerExifParams(true).displayer(new FadeInBitmapDisplayer(500)).build();
    }

    public Bitmap cropCircle(Bitmap bitmap) {
        Bitmap output = Bitmap.createBitmap(bitmap.getWidth(), bitmap.getHeight(), Config.ARGB_8888);
        Canvas canvas = new Canvas(output);
        Paint paint = new Paint();
        Rect rect = new Rect(0, 0, bitmap.getWidth(), bitmap.getHeight());
        paint.setAntiAlias(true);
        canvas.drawARGB(0, 0, 0, 0);
        int size = bitmap.getWidth() / 2;
        canvas.drawCircle((float) size, (float) size, (float) size, paint);
        paint.setXfermode(new PorterDuffXfermode(Mode.SRC_IN));
        canvas.drawBitmap(bitmap, rect, rect, paint);
        return output;
    }

    public Bitmap getRoundedShape(Bitmap scaleBitmapImage) {
        int size;
        if (scaleBitmapImage.getWidth() >= scaleBitmapImage.getHeight()) {
            size = scaleBitmapImage.getHeight();
        } else {
            size = scaleBitmapImage.getWidth();
        }
        Bitmap targetBitmap = Bitmap.createBitmap(size, size, Config.ARGB_8888);
        Canvas canvas = new Canvas(targetBitmap);
        Path path = new Path();
        path.addCircle((float) (size / 2), (float) (size / 2), (float) (size / 2), Direction.CCW);
        canvas.clipPath(path);
        Bitmap sourceBitmap = scaleBitmapImage;
        canvas.drawBitmap(sourceBitmap, new Rect(0, 0, sourceBitmap.getWidth(), sourceBitmap.getHeight()), new Rect(0, 0, size, size), null);
        return targetBitmap;
    }

    public String getImagePath(Context context, int requestCode, Uri uri) {
        String path = "";
        if (requestCode == 102) {
            Cursor cursor = context.getContentResolver().query(uri, new String[]{"_id", "_data"}, null, null, null);
            if (cursor == null) {
                return "";
            }
            cursor.moveToFirst();
            try {
                path = cursor.getString(cursor.getColumnIndex("_data"));
            } catch (CursorIndexOutOfBoundsException e) {
                e.printStackTrace();
            }
            cursor.close();
            return path;
        } else if (requestCode != 101) {
            return path;
        } else {
            Cursor cursor2 = context.getContentResolver().query(uri, null, null, null, null);
            cursor2.moveToFirst();
            String document_id = cursor2.getString(0);
            String document_id2 = document_id.substring(document_id.lastIndexOf(":") + 1);
            cursor2.close();
            Cursor cursor3 = context.getContentResolver().query(Media.EXTERNAL_CONTENT_URI, null, "_id = ? ", new String[]{document_id2}, null);
            if (cursor3 == null) {
                return "";
            }
            cursor3.moveToFirst();
            try {
                path = cursor3.getString(cursor3.getColumnIndex("_data"));
            } catch (CursorIndexOutOfBoundsException e2) {
                e2.printStackTrace();
            }
            cursor3.close();
            return path;
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:20:0x0083 A[SYNTHETIC, Splitter:B:20:0x0083] */
    /* JADX WARNING: Removed duplicated region for block: B:23:0x0088  */
    /* JADX WARNING: Removed duplicated region for block: B:31:0x0098 A[SYNTHETIC, Splitter:B:31:0x0098] */
    /* JADX WARNING: Removed duplicated region for block: B:34:0x009d  */
    /* JADX WARNING: Removed duplicated region for block: B:40:0x00aa A[SYNTHETIC, Splitter:B:40:0x00aa] */
    /* JADX WARNING: Removed duplicated region for block: B:43:0x00af  */
    /* JADX WARNING: Unknown top exception splitter block from list: {B:28:0x0093=Splitter:B:28:0x0093, B:17:0x007e=Splitter:B:17:0x007e} */
    public String getScreenCapturePath(View view) {
        String tempPath = Environment.getExternalStorageDirectory().getAbsolutePath() + File.separator + ".temp";
        File tempDir = new File(tempPath);
        if (!tempDir.exists()) {
            tempDir.mkdirs();
        }
        String tempPath2 = tempPath + File.separator + System.currentTimeMillis() + ".png";
        view.setDrawingCacheEnabled(true);
        Bitmap dstBitmap = view.getDrawingCache();
        OutputStream outStream = null;
        try {
            OutputStream outStream2 = new FileOutputStream(tempPath2);
            try {
                dstBitmap.compress(CompressFormat.PNG, 100, outStream2);
                if (outStream2 != null) {
                    try {
                        outStream2.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                if (dstBitmap != null) {
                    dstBitmap.recycle();
                }
                view.setDrawingCacheEnabled(false);
                OutputStream outputStream = outStream2;
                return tempPath2;
            } catch (FileNotFoundException e2) {
                e1 = e2;
                outStream = outStream2;
                try {
                    e1.printStackTrace();
                    if (outStream != null) {
                        try {
                            outStream.close();
                        } catch (IOException e3) {
                            e3.printStackTrace();
                        }
                    }
                    if (dstBitmap != null) {
                        dstBitmap.recycle();
                    }
                    return null;
                } catch (Throwable th) {
                    th = th;
                    if (outStream != null) {
                    }
                    if (dstBitmap != null) {
                    }
                    throw th;
                }
            } catch (Exception e4) {
                e1 = e4;
                outStream = outStream2;
                e1.printStackTrace();
                if (outStream != null) {
                    try {
                        outStream.close();
                    } catch (IOException e5) {
                        e5.printStackTrace();
                    }
                }
                if (dstBitmap != null) {
                    dstBitmap.recycle();
                }
                return null;
            } catch (Throwable th2) {
                th = th2;
                outStream = outStream2;
                if (outStream != null) {
                    try {
                        outStream.close();
                    } catch (IOException e6) {
                        e6.printStackTrace();
                    }
                }
                if (dstBitmap != null) {
                    dstBitmap.recycle();
                }
                throw th;
            }
        } catch (FileNotFoundException e7) {
            e1 = e7;
            e1.printStackTrace();
            if (outStream != null) {
            }
            if (dstBitmap != null) {
            }
            return null;
        } catch (Exception e8) {
            e1 = e8;
            e1.printStackTrace();
            if (outStream != null) {
            }
            if (dstBitmap != null) {
            }
            return null;
        }
    }

    public String setPickImageView(final Context context, String path, final ImageView imageView) {
        if (path == null || path.isEmpty()) {
            ((BaseActivity) context).showDialog(context.getResources().getString(R.string.COMMON_INVALID_FILE));
            return null;
        }
        final String resizePath = getInstance().getResizeBitmap(path);
        if (resizePath == null || resizePath.isEmpty()) {
            ((BaseActivity) context).showDialog(context.getResources().getString(R.string.COMMON_INVALID_FILE));
            return null;
        }
        ((BaseActivity) context).runOnUiThread(new Runnable() {
            public void run() {
                ImageDisplay.getInstance().displayImageLoadRound("file:/" + resizePath, imageView, context.getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_25OPX));
            }
        });
        return resizePath;
    }
}