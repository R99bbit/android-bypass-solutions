package com.igaworks.adbrix.util;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.util.TypedValue;
import android.widget.TextView;

public class AnipangDialogUtil {
    public static final float BASE_HEIGHT = 960.0f;
    public static final float BASE_WIDTH = 576.0f;
    private static Canvas canvas;
    private static Bitmap output;

    public static int convertPixelToDP(Context context, int px, boolean isX) {
        float norPx;
        float difX = ((float) context.getResources().getDisplayMetrics().widthPixels) / 576.0f;
        float difY = ((float) context.getResources().getDisplayMetrics().heightPixels) / 960.0f;
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
        float difX = ((float) context.getResources().getDisplayMetrics().widthPixels) / 576.0f;
        if (difX != ((float) context.getResources().getDisplayMetrics().heightPixels) / 960.0f) {
            float difY = difX;
        }
        int i = px;
        if (isX) {
            return (int) (((float) (context.getResources().getDisplayMetrics().widthPixels * px)) / 576.0f);
        }
        return (int) (((float) (context.getResources().getDisplayMetrics().heightPixels * px)) / 960.0f);
    }

    public static Bitmap getRoundedCornerBitmap(Context context, Bitmap bitmap, int w, int h) {
        if (bitmap == null) {
            return null;
        }
        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        int desiredLength = (int) (((double) w) * 1.1d);
        if (height > desiredLength) {
            while (height > desiredLength) {
                bitmap = Bitmap.createScaledBitmap(bitmap, (width * desiredLength) / height, desiredLength, true);
                width = bitmap.getWidth();
                height = bitmap.getHeight();
            }
        } else {
            while (height < desiredLength) {
                bitmap = Bitmap.createScaledBitmap(bitmap, (width * desiredLength) / height, desiredLength, true);
                width = bitmap.getWidth();
                height = bitmap.getHeight();
            }
        }
        output = Bitmap.createBitmap(width, height, Config.ARGB_8888);
        canvas = new Canvas(output);
        Paint paint = new Paint();
        Rect rect = new Rect(0, 0, width, height);
        RectF rectF = new RectF(rect);
        float roundPx = (float) convertPixelToDP(context, 14, true);
        paint.setAntiAlias(true);
        canvas.drawARGB(0, 0, 0, 0);
        paint.setColor(-12434878);
        canvas.drawRoundRect(rectF, roundPx, roundPx, paint);
        paint.setXfermode(new PorterDuffXfermode(Mode.SRC_IN));
        canvas.drawBitmap(bitmap, rect, rect, paint);
        return output;
    }
}