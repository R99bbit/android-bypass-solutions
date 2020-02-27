package com.nuvent.shareat.util.crop.camera;

import android.graphics.Bitmap;
import android.graphics.Matrix;
import com.naver.maps.map.NaverMap;

public class RotateBitmap {
    public static final String TAG = "RotateBitmap";
    private Bitmap mBitmap;
    private int mRotation;

    public RotateBitmap(Bitmap bitmap) {
        this.mBitmap = bitmap;
        this.mRotation = 0;
    }

    public RotateBitmap(Bitmap bitmap, int rotation) {
        this.mBitmap = bitmap;
        this.mRotation = rotation % NaverMap.MAXIMUM_BEARING;
    }

    public void setRotation(int rotation) {
        this.mRotation = rotation;
    }

    public int getRotation() {
        return this.mRotation;
    }

    public Bitmap getBitmap() {
        return this.mBitmap;
    }

    public void setBitmap(Bitmap bitmap) {
        this.mBitmap = bitmap;
    }

    public Matrix getRotateMatrix() {
        Matrix matrix = new Matrix();
        if (this.mRotation != 0) {
            matrix.preTranslate((float) (-(this.mBitmap.getWidth() / 2)), (float) (-(this.mBitmap.getHeight() / 2)));
            matrix.postRotate((float) this.mRotation);
            matrix.postTranslate((float) (getWidth() / 2), (float) (getHeight() / 2));
        }
        return matrix;
    }

    public boolean isOrientationChanged() {
        return (this.mRotation / 90) % 2 != 0;
    }

    public int getHeight() {
        if (isOrientationChanged()) {
            return this.mBitmap.getWidth();
        }
        return this.mBitmap.getHeight();
    }

    public int getWidth() {
        if (isOrientationChanged()) {
            return this.mBitmap.getHeight();
        }
        return this.mBitmap.getWidth();
    }

    public void recycle() {
        if (this.mBitmap != null) {
            this.mBitmap.recycle();
            this.mBitmap = null;
        }
    }
}