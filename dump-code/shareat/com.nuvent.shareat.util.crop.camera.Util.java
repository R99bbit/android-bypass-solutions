package com.nuvent.shareat.util.crop.camera;

import android.app.ProgressDialog;
import android.content.ContentResolver;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.BitmapFactory.Options;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Handler;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import com.nuvent.shareat.activity.crop.MonitoredActivity;
import com.nuvent.shareat.activity.crop.MonitoredActivity.LifeCycleAdapter;
import com.nuvent.shareat.util.crop.IImage;
import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.IOException;

public class Util {
    public static final int DIRECTION_DOWN = 3;
    public static final int DIRECTION_LEFT = 0;
    public static final int DIRECTION_RIGHT = 1;
    public static final int DIRECTION_UP = 2;
    public static final boolean NO_RECYCLE_INPUT = false;
    public static final boolean RECYCLE_INPUT = true;
    private static final String TAG = "Util";
    private static OnClickListener sNullOnClickListener;

    private static class BackgroundJob extends LifeCycleAdapter implements Runnable {
        /* access modifiers changed from: private */
        public final MonitoredActivity mActivity;
        private final Runnable mCleanupRunner = new Runnable() {
            public void run() {
                BackgroundJob.this.mActivity.removeLifeCycleListener(BackgroundJob.this);
                if (BackgroundJob.this.mDialog.getWindow() != null) {
                    BackgroundJob.this.mDialog.dismiss();
                }
            }
        };
        /* access modifiers changed from: private */
        public final ProgressDialog mDialog;
        private final Handler mHandler;
        private final Runnable mJob;

        public BackgroundJob(MonitoredActivity activity, Runnable job, ProgressDialog dialog, Handler handler) {
            this.mActivity = activity;
            this.mDialog = dialog;
            this.mJob = job;
            this.mActivity.addLifeCycleListener(this);
            this.mHandler = handler;
        }

        public void run() {
            try {
                this.mJob.run();
            } finally {
                this.mHandler.post(this.mCleanupRunner);
            }
        }

        public void onActivityDestroyed(MonitoredActivity activity) {
            this.mCleanupRunner.run();
            this.mHandler.removeCallbacks(this.mCleanupRunner);
        }

        public void onActivityStopped(MonitoredActivity activity) {
            this.mDialog.hide();
        }

        public void onActivityStarted(MonitoredActivity activity) {
            this.mDialog.show();
        }
    }

    private Util() {
    }

    public static Bitmap rotate(Bitmap b, int degrees) {
        if (degrees == 0 || b == null) {
            return b;
        }
        Matrix m = new Matrix();
        m.setRotate((float) degrees, ((float) b.getWidth()) / 2.0f, ((float) b.getHeight()) / 2.0f);
        try {
            Bitmap b2 = Bitmap.createBitmap(b, 0, 0, b.getWidth(), b.getHeight(), m, true);
            if (b == b2) {
                return b;
            }
            b.recycle();
            return b2;
        } catch (OutOfMemoryError e) {
            return b;
        }
    }

    public static int computeSampleSize(Options options, int minSideLength, int maxNumOfPixels) {
        int initialSize = computeInitialSampleSize(options, minSideLength, maxNumOfPixels);
        if (initialSize > 8) {
            return ((initialSize + 7) / 8) * 8;
        }
        int roundedSize = 1;
        while (roundedSize < initialSize) {
            roundedSize <<= 1;
        }
        return roundedSize;
    }

    private static int computeInitialSampleSize(Options options, int minSideLength, int maxNumOfPixels) {
        int lowerBound;
        int upperBound;
        double w = (double) options.outWidth;
        double h = (double) options.outHeight;
        if (maxNumOfPixels == -1) {
            lowerBound = 1;
        } else {
            lowerBound = (int) Math.ceil(Math.sqrt((w * h) / ((double) maxNumOfPixels)));
        }
        if (minSideLength == -1) {
            upperBound = 128;
        } else {
            upperBound = (int) Math.min(Math.floor(w / ((double) minSideLength)), Math.floor(h / ((double) minSideLength)));
        }
        if (upperBound < lowerBound) {
            return lowerBound;
        }
        if (maxNumOfPixels == -1 && minSideLength == -1) {
            return 1;
        }
        if (minSideLength != -1) {
            return upperBound;
        }
        return lowerBound;
    }

    public static Bitmap transform(Matrix scaler, Bitmap source, int targetWidth, int targetHeight, boolean scaleUp, boolean recycle) {
        Bitmap b1;
        Bitmap b2;
        int deltaX = source.getWidth() - targetWidth;
        int deltaY = source.getHeight() - targetHeight;
        if (scaleUp || (deltaX >= 0 && deltaY >= 0)) {
            float bitmapWidthF = (float) source.getWidth();
            float bitmapHeightF = (float) source.getHeight();
            if (bitmapWidthF / bitmapHeightF > ((float) targetWidth) / ((float) targetHeight)) {
                float scale = ((float) targetHeight) / bitmapHeightF;
                if (scale < 0.9f || scale > 1.0f) {
                    scaler.setScale(scale, scale);
                } else {
                    scaler = null;
                }
            } else {
                float scale2 = ((float) targetWidth) / bitmapWidthF;
                if (scale2 < 0.9f || scale2 > 1.0f) {
                    scaler.setScale(scale2, scale2);
                } else {
                    scaler = null;
                }
            }
            if (scaler != null) {
                b1 = Bitmap.createBitmap(source, 0, 0, source.getWidth(), source.getHeight(), scaler, true);
            } else {
                b1 = source;
            }
            if (recycle && b1 != source) {
                source.recycle();
            }
            b2 = Bitmap.createBitmap(b1, Math.max(0, b1.getWidth() - targetWidth) / 2, Math.max(0, b1.getHeight() - targetHeight) / 2, targetWidth, targetHeight);
            if (b2 != b1 && (recycle || b1 != source)) {
                b1.recycle();
            }
        } else {
            b2 = Bitmap.createBitmap(targetWidth, targetHeight, Config.ARGB_8888);
            Canvas c = new Canvas(b2);
            int deltaXHalf = Math.max(0, deltaX / 2);
            int deltaYHalf = Math.max(0, deltaY / 2);
            int i = deltaXHalf;
            int i2 = deltaYHalf;
            Rect rect = new Rect(i, i2, Math.min(targetWidth, source.getWidth()) + deltaXHalf, Math.min(targetHeight, source.getHeight()) + deltaYHalf);
            int dstX = (targetWidth - rect.width()) / 2;
            int dstY = (targetHeight - rect.height()) / 2;
            Rect rect2 = new Rect(dstX, dstY, targetWidth - dstX, targetHeight - dstY);
            c.drawBitmap(source, rect, rect2, null);
            if (recycle) {
                source.recycle();
            }
        }
        return b2;
    }

    public static <T> int indexOf(T[] array, T s) {
        for (int i = 0; i < array.length; i++) {
            if (array[i].equals(s)) {
                return i;
            }
        }
        return -1;
    }

    public static void closeSilently(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable th) {
            }
        }
    }

    public static void closeSilently(ParcelFileDescriptor c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable th) {
            }
        }
    }

    public static Bitmap makeBitmap(int minSideLength, int maxNumOfPixels, Uri uri, ContentResolver cr, boolean useNative) {
        ParcelFileDescriptor input = null;
        try {
            input = cr.openFileDescriptor(uri, "r");
            Options options = null;
            if (useNative) {
                options = createNativeAllocOptions();
            }
            return makeBitmap(minSideLength, maxNumOfPixels, uri, cr, input, options);
        } catch (IOException e) {
            return null;
        } finally {
            closeSilently(input);
        }
    }

    public static Bitmap makeBitmap(int minSideLength, int maxNumOfPixels, ParcelFileDescriptor pfd, boolean useNative) {
        Options options = null;
        if (useNative) {
            options = createNativeAllocOptions();
        }
        return makeBitmap(minSideLength, maxNumOfPixels, null, null, pfd, options);
    }

    public static Bitmap makeBitmap(int minSideLength, int maxNumOfPixels, Uri uri, ContentResolver cr, ParcelFileDescriptor pfd, Options options) {
        Bitmap bitmap = null;
        if (pfd == null) {
            try {
                pfd = makeInputStream(uri, cr);
            } catch (OutOfMemoryError ex) {
                Log.e(TAG, "Got oom exception ", ex);
                closeSilently(pfd);
            } catch (Throwable th) {
                closeSilently(pfd);
                throw th;
            }
        }
        if (pfd == null) {
            closeSilently(pfd);
        } else {
            if (options == null) {
                options = new Options();
            }
            FileDescriptor fd = pfd.getFileDescriptor();
            options.inJustDecodeBounds = true;
            BitmapManager.instance().decodeFileDescriptor(fd, options);
            if (options.mCancel || options.outWidth == -1 || options.outHeight == -1) {
                closeSilently(pfd);
            } else {
                options.inSampleSize = computeSampleSize(options, minSideLength, maxNumOfPixels);
                options.inJustDecodeBounds = false;
                options.inDither = false;
                options.inPreferredConfig = Config.ARGB_8888;
                bitmap = BitmapManager.instance().decodeFileDescriptor(fd, options);
                closeSilently(pfd);
            }
        }
        return bitmap;
    }

    private static ParcelFileDescriptor makeInputStream(Uri uri, ContentResolver cr) {
        try {
            return cr.openFileDescriptor(uri, "r");
        } catch (IOException e) {
            return null;
        }
    }

    public static synchronized OnClickListener getNullOnClickListener() {
        OnClickListener onClickListener;
        synchronized (Util.class) {
            if (sNullOnClickListener == null) {
                sNullOnClickListener = new OnClickListener() {
                    public void onClick(View v) {
                    }
                };
            }
            onClickListener = sNullOnClickListener;
        }
        return onClickListener;
    }

    public static void Assert(boolean cond) {
        if (!cond) {
            throw new AssertionError();
        }
    }

    public static boolean equals(String a, String b) {
        return a == b || a.equals(b);
    }

    public static void startBackgroundJob(MonitoredActivity activity, String title, String message, Runnable job, Handler handler) {
        new Thread(new BackgroundJob(activity, job, ProgressDialog.show(activity, title, message, true, false), handler)).start();
    }

    public static Intent createSetAsIntent(IImage image) {
        Uri u = image.fullSizeImageUri();
        Intent intent = new Intent("android.intent.action.ATTACH_DATA");
        intent.setDataAndType(u, image.getMimeType());
        intent.putExtra("mimeType", image.getMimeType());
        return intent;
    }

    public static Options createNativeAllocOptions() {
        return new Options();
    }
}