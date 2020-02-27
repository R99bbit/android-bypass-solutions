package com.igaworks.adbrix.cpe.common;

import android.content.Context;
import android.util.TypedValue;
import android.widget.TextView;

public class PromotionConstant {
    public static final float BASE_HEIGHT = 800.0f;
    public static final float BASE_WIDTH = 480.0f;

    public static int convertPixelToDP(Context context, int px, boolean isX) {
        float norPx;
        int width = context.getResources().getDisplayMetrics().widthPixels;
        int height = context.getResources().getDisplayMetrics().heightPixels;
        if (context.getResources().getConfiguration().orientation == 2) {
            width = context.getResources().getDisplayMetrics().heightPixels;
            height = context.getResources().getDisplayMetrics().widthPixels;
        }
        float difX = ((float) width) / 480.0f;
        float difY = ((float) height) / 800.0f;
        if (difX != difY) {
            difY = difX;
        }
        float f = (float) px;
        if (isX) {
            norPx = ((float) px) * difX;
        } else {
            norPx = ((float) px) * difY;
        }
        if (norPx < 1.5f) {
            norPx = 1.5f;
        }
        return (int) TypedValue.applyDimension(0, norPx, context.getResources().getDisplayMetrics());
    }

    public static void setTextViewSize(Context context, TextView tv, int size) {
        tv.setTextSize(0, (float) calNormPixel(context, size, false));
    }

    public static int calNormPixel(Context context, int px, boolean isX) {
        int width = context.getResources().getDisplayMetrics().widthPixels;
        int height = context.getResources().getDisplayMetrics().heightPixels;
        if (context.getResources().getConfiguration().orientation == 2) {
            width = context.getResources().getDisplayMetrics().heightPixels;
            height = context.getResources().getDisplayMetrics().widthPixels;
        }
        float difX = ((float) width) / 480.0f;
        if (difX != ((float) height) / 800.0f) {
            float difY = difX;
        }
        int i = px;
        if (isX) {
            return (int) (((float) (px * width)) / 480.0f);
        }
        return (int) (((float) (px * height)) / 800.0f);
    }
}