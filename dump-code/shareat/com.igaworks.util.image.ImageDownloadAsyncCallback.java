package com.igaworks.util.image;

import android.graphics.Bitmap;
import android.widget.FrameLayout;
import android.widget.ImageView;
import java.io.File;
import java.lang.ref.WeakReference;

public abstract class ImageDownloadAsyncCallback implements AsyncCallback<File>, AsyncExecutorAware<File> {
    private AsyncExecutor<File> asyncExecutor;
    private ImageCache imageCache;
    private WeakReference<ImageView> imageViewReference;
    private FrameLayout progressCircle;
    private String url;

    public abstract void onResultCustom(Bitmap bitmap);

    public ImageDownloadAsyncCallback(String url2, ImageView imageView, ImageCache imageCache2, FrameLayout progressCircle2) {
        this.url = url2;
        this.imageViewReference = new WeakReference<>(imageView);
        this.imageCache = imageCache2;
        this.progressCircle = progressCircle2;
    }

    public void setAsyncExecutor(AsyncExecutor<File> asyncExecutor2) {
        this.asyncExecutor = asyncExecutor2;
    }

    public boolean isSameUrl(String url2) {
        return this.url.equals(url2);
    }

    public void onResult(File bitmapFile) {
        try {
            Bitmap bitmap = addBitmapToCache(bitmapFile);
            onResultCustom(bitmap);
            applyBitmapToImageView(bitmap);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Bitmap addBitmapToCache(File bitmap) {
        this.imageCache.addBitmap(this.url, bitmap);
        return this.imageCache.getBitmap(this.url);
    }

    private void applyBitmapToImageView(Bitmap bitmap) {
        ImageView imageView = (ImageView) this.imageViewReference.get();
        if (imageView != null && isSameCallback(imageView)) {
            imageView.setImageBitmap(bitmap);
            imageView.setTag(null);
        }
    }

    private boolean isSameCallback(ImageView imageView) {
        return this == imageView.getTag();
    }

    public void cancel(boolean b) {
        this.asyncExecutor.cancel(true);
    }

    public void exceptionOccured(Exception e) {
    }

    public void cancelled() {
    }
}