package com.igaworks.adbrix.util;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.widget.ImageView;

public class SizeAwareImageView extends ImageView {
    private int actualHeight;
    private int actualWidth;

    public SizeAwareImageView(Context context) {
        super(context);
    }

    public int getActualWidth() {
        return this.actualWidth;
    }

    public void setActualWidth(int actualWidth2) {
        this.actualWidth = actualWidth2;
    }

    public int getActualHeight() {
        return this.actualHeight;
    }

    public void setActualHeight(int actualHeight2) {
        this.actualHeight = actualHeight2;
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        float[] f = new float[9];
        getImageMatrix().getValues(f);
        float scaleX = f[0];
        float scaleY = f[4];
        Drawable d = getDrawable();
        int origW = d.getIntrinsicWidth();
        int origH = d.getIntrinsicHeight();
        int actW = Math.round(((float) origW) * scaleX);
        int actH = Math.round(((float) origH) * scaleY);
        this.actualWidth = actW;
        this.actualHeight = actH;
    }
}