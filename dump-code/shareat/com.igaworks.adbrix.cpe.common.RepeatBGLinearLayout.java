package com.igaworks.adbrix.cpe.common;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PaintFlagsDrawFilter;
import android.graphics.Shader.TileMode;
import android.util.AttributeSet;
import android.widget.LinearLayout;

public class RepeatBGLinearLayout extends LinearLayout {
    Context mContext;
    PaintFlagsDrawFilter mDF;
    Paint mPaint;
    BitmapShader mShader;
    Bitmap mTexture;

    public RepeatBGLinearLayout(Context context) {
        super(context);
    }

    public RepeatBGLinearLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public void init(Context context, Bitmap bitmap) {
        this.mContext = context;
        this.mDF = new PaintFlagsDrawFilter(6, 3);
        this.mTexture = bitmap;
        this.mShader = new BitmapShader(this.mTexture, TileMode.REPEAT, TileMode.REPEAT);
        this.mPaint = new Paint(2);
        this.mPaint.setDither(false);
    }

    public void onDraw(Canvas canvas) {
        if (this.mPaint == null) {
            this.mPaint = new Paint(2);
            this.mPaint.setDither(false);
        }
        canvas.setDrawFilter(this.mDF);
        this.mPaint.setShader(this.mShader);
        canvas.drawPaint(this.mPaint);
    }
}