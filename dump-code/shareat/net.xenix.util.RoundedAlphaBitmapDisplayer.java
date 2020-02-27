package net.xenix.util;

import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Matrix.ScaleToFit;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader.TileMode;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.animation.AlphaAnimation;
import android.view.animation.DecelerateInterpolator;
import com.nostra13.universalimageloader.core.assist.LoadedFrom;
import com.nostra13.universalimageloader.core.display.BitmapDisplayer;
import com.nostra13.universalimageloader.core.imageaware.ImageAware;
import com.nostra13.universalimageloader.core.imageaware.ImageViewAware;

public class RoundedAlphaBitmapDisplayer implements BitmapDisplayer {
    private static boolean isAnimate;
    private final boolean animateFromDisk;
    private final boolean animateFromMemory;
    private final boolean animateFromNetwork;
    protected final int cornerRadius;
    private final int durationMillis;
    protected final int margin;

    public static class RoundedDrawable extends Drawable {
        protected final BitmapShader bitmapShader;
        protected final float cornerRadius;
        protected final RectF mBitmapRect;
        protected final RectF mRect = new RectF();
        protected final int margin;
        protected final Paint paint;

        public RoundedDrawable(Bitmap bitmap, int cornerRadius2, int margin2) {
            Bitmap dstBmp;
            this.cornerRadius = (float) cornerRadius2;
            this.margin = margin2;
            if (bitmap.getWidth() >= bitmap.getHeight()) {
                dstBmp = Bitmap.createBitmap(bitmap, (bitmap.getWidth() / 2) - (bitmap.getHeight() / 2), 0, bitmap.getHeight(), bitmap.getHeight());
            } else {
                dstBmp = Bitmap.createBitmap(bitmap, 0, (bitmap.getHeight() / 2) - (bitmap.getWidth() / 2), bitmap.getWidth(), bitmap.getWidth());
            }
            this.bitmapShader = new BitmapShader(dstBmp, TileMode.CLAMP, TileMode.CLAMP);
            this.mBitmapRect = new RectF((float) margin2, (float) margin2, (float) (dstBmp.getWidth() - margin2), (float) (dstBmp.getHeight() - margin2));
            this.paint = new Paint();
            this.paint.setAntiAlias(true);
            this.paint.setShader(this.bitmapShader);
        }

        /* access modifiers changed from: protected */
        public void onBoundsChange(Rect bounds) {
            super.onBoundsChange(bounds);
            this.mRect.set((float) this.margin, (float) this.margin, (float) (bounds.width() - this.margin), (float) (bounds.height() - this.margin));
            Matrix shaderMatrix = new Matrix();
            shaderMatrix.setRectToRect(this.mBitmapRect, this.mRect, ScaleToFit.FILL);
            this.bitmapShader.setLocalMatrix(shaderMatrix);
        }

        public void draw(Canvas canvas) {
            canvas.drawRoundRect(this.mRect, this.cornerRadius, this.cornerRadius, this.paint);
        }

        public int getOpacity() {
            return -3;
        }

        public void setAlpha(int alpha) {
            this.paint.setAlpha(alpha);
        }

        public void setColorFilter(ColorFilter cf) {
            this.paint.setColorFilter(cf);
        }
    }

    public RoundedAlphaBitmapDisplayer(int cornerRadiusPixels, int marginPixels, boolean isAnimate2) {
        this(cornerRadiusPixels, marginPixels, 0, true, true, true);
        isAnimate = isAnimate2;
    }

    public RoundedAlphaBitmapDisplayer(int cornerRadiusPixels, int marginPixels, int durationMillis2) {
        this(cornerRadiusPixels, marginPixels, durationMillis2, true, true, true);
    }

    public RoundedAlphaBitmapDisplayer(int cornerRadiusPixels, int marginPixels, int durationMillis2, boolean animateFromNetwork2, boolean animateFromMemory2, boolean animateFromDisk2) {
        this.cornerRadius = cornerRadiusPixels;
        this.margin = marginPixels;
        this.durationMillis = durationMillis2;
        this.animateFromNetwork = animateFromNetwork2;
        this.animateFromMemory = animateFromMemory2;
        this.animateFromDisk = animateFromDisk2;
    }

    public void display(Bitmap bitmap, ImageAware imageAware, LoadedFrom loadedFrom) {
        if (!(imageAware instanceof ImageViewAware)) {
            throw new IllegalArgumentException("ImageAware should wrap ImageView. ImageViewAware is expected.");
        }
        imageAware.setImageDrawable(new RoundedDrawable(bitmap, this.cornerRadius, this.margin));
        if ((this.animateFromNetwork && loadedFrom == LoadedFrom.NETWORK) || ((this.animateFromDisk && loadedFrom == LoadedFrom.DISC_CACHE) || (this.animateFromMemory && loadedFrom == LoadedFrom.MEMORY_CACHE))) {
            animate(imageAware.getWrappedView(), this.durationMillis);
        }
    }

    public static void animate(View imageView, int durationMillis2) {
        if (isAnimate && imageView != null) {
            AlphaAnimation fadeImage = new AlphaAnimation(0.0f, 1.0f);
            fadeImage.setDuration((long) durationMillis2);
            fadeImage.setInterpolator(new DecelerateInterpolator());
            imageView.startAnimation(fadeImage);
        }
    }
}