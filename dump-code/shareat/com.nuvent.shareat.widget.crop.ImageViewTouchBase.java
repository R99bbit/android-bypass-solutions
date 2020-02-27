package com.nuvent.shareat.widget.crop;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import com.nuvent.shareat.util.crop.camera.RotateBitmap;

abstract class ImageViewTouchBase extends ImageView {
    static final float SCALE_RATE = 1.25f;
    private static final String TAG = "ImageViewTouchBase";
    protected Matrix mBaseMatrix = new Matrix();
    protected final RotateBitmap mBitmapDisplayed = new RotateBitmap(null);
    private final Matrix mDisplayMatrix = new Matrix();
    protected Handler mHandler = new Handler();
    private final float[] mMatrixValues = new float[9];
    float mMaxZoom;
    private Runnable mOnLayoutRunnable = null;
    private Recycler mRecycler;
    protected Matrix mSuppMatrix = new Matrix();
    int mThisHeight = -1;
    int mThisWidth = -1;

    public interface Recycler {
        void recycle(Bitmap bitmap);
    }

    public void setRecycler(Recycler r) {
        this.mRecycler = r;
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        this.mThisWidth = right - left;
        this.mThisHeight = bottom - top;
        Runnable r = this.mOnLayoutRunnable;
        if (r != null) {
            this.mOnLayoutRunnable = null;
            r.run();
        }
        if (this.mBitmapDisplayed.getBitmap() != null) {
            getProperBaseMatrix(this.mBitmapDisplayed, this.mBaseMatrix);
            setImageMatrix(getImageViewMatrix());
        }
    }

    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode != 4 || event.getRepeatCount() != 0) {
            return super.onKeyDown(keyCode, event);
        }
        event.startTracking();
        return true;
    }

    public boolean onKeyUp(int keyCode, KeyEvent event) {
        if (keyCode != 4 || !event.isTracking() || event.isCanceled() || getScale() <= 1.0f) {
            return super.onKeyUp(keyCode, event);
        }
        zoomTo(1.0f);
        return true;
    }

    public void setImageBitmap(Bitmap bitmap) {
        setImageBitmap(bitmap, 0);
    }

    private void setImageBitmap(Bitmap bitmap, int rotation) {
        super.setImageBitmap(bitmap);
        Drawable d = getDrawable();
        if (d != null) {
            d.setDither(true);
        }
        Bitmap old = this.mBitmapDisplayed.getBitmap();
        this.mBitmapDisplayed.setBitmap(bitmap);
        this.mBitmapDisplayed.setRotation(rotation);
        if (old != null && old != bitmap && this.mRecycler != null) {
            this.mRecycler.recycle(old);
        }
    }

    public void clear() {
        setImageBitmapResetBase(null, true);
    }

    public void setImageBitmapResetBase(Bitmap bitmap, boolean resetSupp) {
        setImageRotateBitmapResetBase(new RotateBitmap(bitmap), resetSupp);
    }

    public void setImageRotateBitmapResetBase(final RotateBitmap bitmap, final boolean resetSupp) {
        if (getWidth() <= 0) {
            this.mOnLayoutRunnable = new Runnable() {
                public void run() {
                    ImageViewTouchBase.this.setImageRotateBitmapResetBase(bitmap, resetSupp);
                }
            };
            return;
        }
        if (bitmap.getBitmap() != null) {
            getProperBaseMatrix(bitmap, this.mBaseMatrix);
            setImageBitmap(bitmap.getBitmap(), bitmap.getRotation());
        } else {
            this.mBaseMatrix.reset();
            setImageBitmap(null);
        }
        if (resetSupp) {
            this.mSuppMatrix.reset();
        }
        setImageMatrix(getImageViewMatrix());
        this.mMaxZoom = maxZoom();
    }

    public void center(boolean horizontal, boolean vertical) {
        if (this.mBitmapDisplayed.getBitmap() != null) {
            Matrix m = getImageViewMatrix();
            RectF rect = new RectF(0.0f, 0.0f, (float) this.mBitmapDisplayed.getBitmap().getWidth(), (float) this.mBitmapDisplayed.getBitmap().getHeight());
            m.mapRect(rect);
            float height = rect.height();
            float width = rect.width();
            float deltaX = 0.0f;
            float deltaY = 0.0f;
            if (vertical) {
                int viewHeight = getHeight();
                if (height < ((float) viewHeight)) {
                    deltaY = ((((float) viewHeight) - height) / 2.0f) - rect.top;
                } else if (rect.top > 0.0f) {
                    deltaY = -rect.top;
                } else if (rect.bottom < ((float) viewHeight)) {
                    deltaY = ((float) getHeight()) - rect.bottom;
                }
            }
            if (horizontal) {
                int viewWidth = getWidth();
                if (width < ((float) viewWidth)) {
                    deltaX = ((((float) viewWidth) - width) / 2.0f) - rect.left;
                } else if (rect.left > 0.0f) {
                    deltaX = -rect.left;
                } else if (rect.right < ((float) viewWidth)) {
                    deltaX = ((float) viewWidth) - rect.right;
                }
            }
            postTranslate(deltaX, deltaY);
            setImageMatrix(getImageViewMatrix());
        }
    }

    public ImageViewTouchBase(Context context) {
        super(context);
        init();
    }

    public ImageViewTouchBase(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    private void init() {
        setScaleType(ScaleType.MATRIX);
    }

    /* access modifiers changed from: protected */
    public float getValue(Matrix matrix, int whichValue) {
        matrix.getValues(this.mMatrixValues);
        return this.mMatrixValues[whichValue];
    }

    /* access modifiers changed from: protected */
    public float getScale(Matrix matrix) {
        return getValue(matrix, 0);
    }

    public float getScale() {
        return getScale(this.mSuppMatrix);
    }

    private void getProperBaseMatrix(RotateBitmap bitmap, Matrix matrix) {
        float viewWidth = (float) getWidth();
        float viewHeight = (float) getHeight();
        float w = (float) bitmap.getWidth();
        float h = (float) bitmap.getHeight();
        matrix.reset();
        float scale = Math.min(Math.min(viewWidth / w, 3.0f), Math.min(viewHeight / h, 3.0f));
        matrix.postConcat(bitmap.getRotateMatrix());
        matrix.postScale(scale, scale);
        matrix.postTranslate((viewWidth - (w * scale)) / 2.0f, (viewHeight - (h * scale)) / 2.0f);
    }

    /* access modifiers changed from: protected */
    public Matrix getImageViewMatrix() {
        this.mDisplayMatrix.set(this.mBaseMatrix);
        this.mDisplayMatrix.postConcat(this.mSuppMatrix);
        return this.mDisplayMatrix;
    }

    /* access modifiers changed from: protected */
    public float maxZoom() {
        if (this.mBitmapDisplayed.getBitmap() == null) {
            return 1.0f;
        }
        return Math.max(((float) this.mBitmapDisplayed.getWidth()) / ((float) this.mThisWidth), ((float) this.mBitmapDisplayed.getHeight()) / ((float) this.mThisHeight)) * 4.0f;
    }

    /* access modifiers changed from: protected */
    public void zoomTo(float scale, float centerX, float centerY) {
        if (scale > this.mMaxZoom) {
            scale = this.mMaxZoom;
        }
        float deltaScale = scale / getScale();
        this.mSuppMatrix.postScale(deltaScale, deltaScale, centerX, centerY);
        setImageMatrix(getImageViewMatrix());
        center(true, true);
    }

    /* access modifiers changed from: protected */
    public void zoomTo(float scale, float centerX, float centerY, float durationMs) {
        final float incrementPerMs = (scale - getScale()) / durationMs;
        final float oldScale = getScale();
        final long startTime = System.currentTimeMillis();
        final float f = durationMs;
        final float f2 = centerX;
        final float f3 = centerY;
        this.mHandler.post(new Runnable() {
            public void run() {
                float currentMs = Math.min(f, (float) (System.currentTimeMillis() - startTime));
                ImageViewTouchBase.this.zoomTo(oldScale + (incrementPerMs * currentMs), f2, f3);
                if (currentMs < f) {
                    ImageViewTouchBase.this.mHandler.post(this);
                }
            }
        });
    }

    /* access modifiers changed from: protected */
    public void zoomTo(float scale) {
        zoomTo(scale, ((float) getWidth()) / 2.0f, ((float) getHeight()) / 2.0f);
    }

    /* access modifiers changed from: protected */
    public void zoomToPoint(float scale, float pointX, float pointY) {
        float cx = ((float) getWidth()) / 2.0f;
        float cy = ((float) getHeight()) / 2.0f;
        panBy(cx - pointX, cy - pointY);
        zoomTo(scale, cx, cy);
    }

    /* access modifiers changed from: protected */
    public void zoomIn() {
        zoomIn(SCALE_RATE);
    }

    /* access modifiers changed from: protected */
    public void zoomOut() {
        zoomOut(SCALE_RATE);
    }

    /* access modifiers changed from: protected */
    public void zoomIn(float rate) {
        if (getScale() < this.mMaxZoom && this.mBitmapDisplayed.getBitmap() != null) {
            this.mSuppMatrix.postScale(rate, rate, ((float) getWidth()) / 2.0f, ((float) getHeight()) / 2.0f);
            setImageMatrix(getImageViewMatrix());
        }
    }

    /* access modifiers changed from: protected */
    public void zoomOut(float rate) {
        if (this.mBitmapDisplayed.getBitmap() != null) {
            float cx = ((float) getWidth()) / 2.0f;
            float cy = ((float) getHeight()) / 2.0f;
            Matrix tmp = new Matrix(this.mSuppMatrix);
            tmp.postScale(1.0f / rate, 1.0f / rate, cx, cy);
            if (getScale(tmp) < 1.0f) {
                this.mSuppMatrix.setScale(1.0f, 1.0f, cx, cy);
            } else {
                this.mSuppMatrix.postScale(1.0f / rate, 1.0f / rate, cx, cy);
            }
            setImageMatrix(getImageViewMatrix());
            center(true, true);
        }
    }

    /* access modifiers changed from: protected */
    public void postTranslate(float dx, float dy) {
        this.mSuppMatrix.postTranslate(dx, dy);
    }

    /* access modifiers changed from: protected */
    public void panBy(float dx, float dy) {
        postTranslate(dx, dy);
        setImageMatrix(getImageViewMatrix());
    }
}