package com.igaworks.core;

import android.app.Activity;
import android.content.Context;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.widget.TextView;

public class DisplaySetter {
    public static final float BASE_HEIGHT = 1920.0f;
    public static final float BASE_WIDTH = 1080.0f;
    private static int density;
    private static DisplayMetrics displayXY = new DisplayMetrics();
    private static boolean isInit = false;
    public static boolean isPortrait;
    private static double scale;

    private static void initScale(Context context) {
        if (context instanceof Activity) {
            Activity a = (Activity) context;
            DisplayMetrics metrics = new DisplayMetrics();
            a.getWindowManager().getDefaultDisplay().getMetrics(metrics);
            density = metrics.densityDpi;
            scale = 240.0d / ((double) density);
            a.getWindowManager().getDefaultDisplay().getMetrics(displayXY);
            isInit = true;
        }
        if (context.getResources().getConfiguration().orientation == 2) {
            isPortrait = false;
        } else {
            isPortrait = true;
        }
    }

    public static void setTextViewSize(Context context, TextView tv, int size) {
        tv.setTextSize(0, (float) calNormPixel(context, size, false));
    }

    public static int convertPixelToDP(Context context, int px, boolean isX) {
        float f;
        float norPx;
        float f2 = 1920.0f;
        initScale(context);
        float f3 = (float) context.getResources().getDisplayMetrics().widthPixels;
        if (isPortrait) {
            f = 1080.0f;
        } else {
            f = 1920.0f;
        }
        float difX = f3 / f;
        float f4 = (float) context.getResources().getDisplayMetrics().heightPixels;
        if (!isPortrait) {
            f2 = 1080.0f;
        }
        float difY = f4 / f2;
        if (difX != difY) {
            difY = difX;
        }
        float f5 = (float) px;
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

    public static int calNormPixel(Context context, int px, boolean isX) {
        float f;
        float f2 = 1920.0f;
        initScale(context);
        float f3 = (float) context.getResources().getDisplayMetrics().widthPixels;
        if (isPortrait) {
            f = 1080.0f;
        } else {
            f = 1920.0f;
        }
        float difX = f3 / f;
        float f4 = (float) context.getResources().getDisplayMetrics().heightPixels;
        if (!isPortrait) {
            f2 = 1080.0f;
        }
        float difY = f4 / f2;
        if (difX != difY) {
            difY = difX;
        }
        int i = px;
        if (isX) {
            return (int) (((float) px) * difX);
        }
        return (int) (((float) px) * difY);
    }

    public static float getNormalizeFactor(Context context) {
        return getPixelFactor(context);
    }

    public static float getPixelFactor(Context context) {
        if (!isInit) {
            initScale(context);
        }
        return (((float) Math.min(displayXY.heightPixels, displayXY.widthPixels)) / displayXY.density) / 130.0f;
    }

    public static DisplayMetrics getDisplayXY(Context context) {
        if (!isInit) {
            initScale(context);
        }
        return displayXY;
    }

    public static double getScale(Context context) {
        if (!isInit) {
            initScale(context);
        }
        if (scale == 0.0d) {
            return 1.0d;
        }
        return scale;
    }

    public static double getInverseOfScale(Context context) {
        if (!isInit) {
            initScale(context);
        }
        if (scale == 0.0d) {
            return 1.0d;
        }
        return 1.0d / scale;
    }
}