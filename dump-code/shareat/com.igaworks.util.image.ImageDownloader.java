package com.igaworks.util.image;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.widget.FrameLayout;
import android.widget.ImageView;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import java.io.File;
import java.util.concurrent.Callable;

public class ImageDownloader {
    public static final int MAX_IMAGE_CACHE = 100;
    private ImageCache imageCache;

    public ImageDownloader(Context context, String imageCacheName) {
        try {
            FileCacheFactory.initialize(context);
            if (!FileCacheFactory.getInstance().has(imageCacheName)) {
                FileCacheFactory.getInstance().create(imageCacheName, 100);
            }
            if (!ImageCacheFactory.getInstance().has(imageCacheName)) {
                ImageCacheFactory.getInstance().createTwoLevelCache(imageCacheName, 100);
            }
            this.imageCache = ImageCacheFactory.getInstance().get(imageCacheName);
        } catch (Exception e) {
            if (e != null) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, e.toString(), 0);
            }
        }
    }

    public void download(String url, ImageView imageView, Drawable noImageDrawable, FrameLayout progressCircle, ImageDownloadAsyncCallback callback) {
        try {
            Bitmap bitmap = this.imageCache.getBitmap(url);
            if (bitmap == null) {
                forceDownload(url, imageView, noImageDrawable, progressCircle, callback);
                return;
            }
            callback.onResultCustom(bitmap);
            cancelPotentialDownload(url, imageView);
            if (imageView != null) {
                imageView.setImageBitmap(bitmap);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void forceDownload(String url, ImageView imageView, Drawable noImageDrawable, FrameLayout progressCircle, ImageDownloadAsyncCallback callback) {
        try {
            if (cancelPotentialDownload(url, imageView)) {
                if (!(imageView == null || noImageDrawable == null)) {
                    imageView.setImageDrawable(noImageDrawable);
                }
                runAsyncImageDownloading(url, imageView, progressCircle, callback);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean cancelPotentialDownload(String url, ImageView imageView) {
        if (imageView == null) {
            return true;
        }
        try {
            ImageDownloadAsyncCallback asyncCallback = (ImageDownloadAsyncCallback) imageView.getTag();
            if (asyncCallback == null) {
                return true;
            }
            if (asyncCallback.isSameUrl(url)) {
                return false;
            }
            asyncCallback.cancel(true);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private void runAsyncImageDownloading(String url, ImageView imageView, FrameLayout progressCircle, final ImageDownloadAsyncCallback callback) {
        try {
            File tempFile = createTemporaryFile(url);
            if (tempFile != null) {
                final Callable<File> callable = new FileDownloadCallable<>(url, tempFile);
                if (imageView != null) {
                    imageView.setTag(callback);
                }
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    public void run() {
                        try {
                            AsyncExecutor<File> ae = new AsyncExecutor<>();
                            ae.setCallable(callable);
                            ae.setCallback(callback);
                            ae.execute(new Void[0]);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private File createTemporaryFile(String url) {
        try {
            File mFile1 = new File(new StringBuilder(String.valueOf(Environment.getExternalStorageDirectory().getAbsolutePath())).append(FileCacheImpl.IGAW_CACHE_PATH).toString());
            if (!mFile1.exists()) {
                mFile1.mkdirs();
            }
            return new File(mFile1, FileCacheImpl.computeHashedName(url));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}