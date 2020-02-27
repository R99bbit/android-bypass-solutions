package com.nuvent.shareat.util;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.graphics.Bitmap.Config;
import android.graphics.BitmapFactory;
import android.graphics.BitmapFactory.Options;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.media.ExifInterface;
import android.os.Environment;
import com.nuvent.shareat.R;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;

public class BitmapHelper {
    public static Bitmap getAdjustedBitmap(String path, int targetWidth, int targetHeight) {
        Options opts = new Options();
        opts.inJustDecodeBounds = true;
        BitmapFactory.decodeFile(path, opts);
        opts.inJustDecodeBounds = false;
        opts.inPreferredConfig = Config.RGB_565;
        int scaleFactor = Math.min(opts.outWidth / targetWidth, opts.outHeight / targetHeight);
        opts.inPurgeable = true;
        opts.inSampleSize = scaleFactor;
        Bitmap bitmap = BitmapFactory.decodeFile(path, opts);
        int angel = getBitmapAngle(path);
        if (angel > 0) {
            return getRotatedBitmap(bitmap, (float) angel);
        }
        return bitmap;
    }

    public static int getBitmapAngle(String path) {
        try {
            switch (new ExifInterface(path).getAttributeInt("Orientation", 1)) {
                case 1:
                    return 0;
                case 3:
                    return 180;
                case 6:
                    return 90;
                case 8:
                    return 270;
                default:
                    return 0;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return 0;
        }
    }

    public static Bitmap getRotatedBitmap(Bitmap source, float angle) {
        Bitmap bitmap = null;
        Matrix matrix = new Matrix();
        matrix.postRotate(angle);
        try {
            return Bitmap.createBitmap(source, 0, 0, source.getWidth(), source.getHeight(), matrix, true);
        } catch (OutOfMemoryError err) {
            err.printStackTrace();
            return bitmap;
        }
    }

    public static Bitmap getSquareBitmap(Bitmap source) {
        boolean landscape;
        int width = source.getWidth();
        int height = source.getHeight();
        if (width == height) {
            return source;
        }
        if (width > height) {
            landscape = true;
        } else {
            landscape = false;
        }
        Matrix matrix = new Matrix();
        if (!landscape) {
            return Bitmap.createBitmap(source, 0, (height - width) / 2, width, width, matrix, true);
        }
        return Bitmap.createBitmap(source, (width - height) / 2, 0, height, height, matrix, true);
    }

    public static Bitmap getCircleCroppedBitmap(Bitmap src, int radius) {
        Bitmap dst;
        if (src.getWidth() == radius && src.getHeight() == radius) {
            dst = src;
        } else {
            dst = Bitmap.createScaledBitmap(src, radius, radius, false);
        }
        Bitmap output = Bitmap.createBitmap(dst.getWidth(), dst.getHeight(), Config.ARGB_8888);
        Canvas canvas = new Canvas(output);
        Paint paint = new Paint();
        Rect rect = new Rect(0, 0, dst.getWidth(), dst.getHeight());
        paint.setAntiAlias(true);
        paint.setFilterBitmap(true);
        paint.setDither(true);
        canvas.drawARGB(0, 0, 0, 0);
        paint.setColor(Color.parseColor("#BAB399"));
        canvas.drawCircle(((float) (dst.getWidth() / 2)) + 0.7f, ((float) (dst.getHeight() / 2)) + 0.7f, ((float) (dst.getWidth() / 2)) + 0.1f, paint);
        paint.setXfermode(new PorterDuffXfermode(Mode.SRC_IN));
        canvas.drawBitmap(dst, rect, rect, paint);
        return output;
    }

    /* JADX WARNING: Removed duplicated region for block: B:34:0x005e A[SYNTHETIC, Splitter:B:34:0x005e] */
    public static String saveBitmapToJpeg(Bitmap source, String path, String name) {
        File dir;
        String str;
        if (path == null || path.length() <= 0) {
            dir = Environment.getExternalStorageDirectory();
        } else {
            dir = new File(Environment.getExternalStorageDirectory(), path);
            if (!dir.exists()) {
                dir.mkdirs();
            }
        }
        File jpeg = new File(dir, name);
        if (jpeg.exists()) {
            jpeg.delete();
        }
        FileOutputStream fos = null;
        try {
            FileOutputStream fos2 = new FileOutputStream(jpeg);
            try {
                source.compress(CompressFormat.JPEG, 75, fos2);
                str = jpeg.getAbsolutePath();
                if (fos2 != null) {
                    try {
                        fos2.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                FileOutputStream fileOutputStream = fos2;
            } catch (FileNotFoundException e2) {
                e = e2;
                fos = fos2;
            } catch (Throwable th) {
                th = th;
                fos = fos2;
                if (fos != null) {
                }
                throw th;
            }
        } catch (FileNotFoundException e3) {
            e = e3;
            try {
                e.printStackTrace();
                str = null;
                if (fos != null) {
                    try {
                        fos.close();
                    } catch (IOException e4) {
                        e4.printStackTrace();
                    }
                }
                return str;
            } catch (Throwable th2) {
                th = th2;
                if (fos != null) {
                    try {
                        fos.close();
                    } catch (IOException e5) {
                        e5.printStackTrace();
                    }
                }
                throw th;
            }
        }
        return str;
    }

    public static Bitmap getRoundedCornerBitmap(Bitmap bitmap) {
        Bitmap output = Bitmap.createBitmap(bitmap.getWidth(), bitmap.getHeight(), Config.ARGB_8888);
        Canvas canvas = new Canvas(output);
        Paint paint = new Paint();
        Rect rect = new Rect(0, 0, bitmap.getWidth(), bitmap.getHeight());
        RectF rectF = new RectF(rect);
        paint.setAntiAlias(true);
        canvas.drawARGB(0, 0, 0, 0);
        paint.setColor(-12434878);
        canvas.drawRoundRect(rectF, 12.0f, 12.0f, paint);
        paint.setXfermode(new PorterDuffXfermode(Mode.SRC_IN));
        canvas.drawBitmap(bitmap, rect, rect, paint);
        return output;
    }

    public static Bitmap getRoundedCornerBitmap(Context con, Rect rectSize, String path) {
        Bitmap original = getAdjustedBitmap(path, rectSize.right, rectSize.bottom);
        Bitmap mask = Bitmap.createScaledBitmap(BitmapFactory.decodeResource(con.getResources(), R.drawable.review_album), rectSize.right, rectSize.bottom, true);
        Bitmap original2 = Bitmap.createScaledBitmap(original, rectSize.right, rectSize.bottom, true);
        Bitmap result = Bitmap.createBitmap(rectSize.right, rectSize.bottom, Config.ARGB_8888);
        Canvas mCanvas = new Canvas(result);
        Paint paint = new Paint(1);
        paint.setXfermode(new PorterDuffXfermode(Mode.DST_IN));
        mCanvas.drawBitmap(original2, 0.0f, 0.0f, null);
        mCanvas.drawBitmap(mask, 0.0f, 0.0f, paint);
        paint.setXfermode(null);
        return result;
    }

    public static Bitmap getRoundedCornerBitmap(Context con, int maskBG, Rect rectSize, Bitmap original) {
        Bitmap mask = Bitmap.createScaledBitmap(BitmapFactory.decodeResource(con.getResources(), maskBG), rectSize.right, rectSize.bottom, true);
        Bitmap original2 = Bitmap.createScaledBitmap(original, rectSize.right, rectSize.bottom, true);
        Bitmap result = Bitmap.createBitmap(rectSize.right, rectSize.bottom, Config.ARGB_8888);
        Canvas mCanvas = new Canvas(result);
        Paint paint = new Paint(1);
        paint.setXfermode(new PorterDuffXfermode(Mode.DST_IN));
        mCanvas.drawBitmap(original2, 0.0f, 0.0f, null);
        mCanvas.drawBitmap(mask, 0.0f, 0.0f, paint);
        paint.setXfermode(null);
        return result;
    }

    public static Bitmap getBlurEffectBitmap(Context context, Bitmap sentBitmap, int radius) {
        if (sentBitmap == null) {
            return null;
        }
        if (sentBitmap.getConfig() == null) {
            return null;
        }
        Bitmap bitmap = sentBitmap.copy(sentBitmap.getConfig(), true);
        int w = bitmap.getWidth();
        int h = bitmap.getHeight();
        int wm = w - 1;
        int hm = h - 1;
        int wh = w * h;
        int div = radius + radius + 1;
        int[] pix = new int[wh];
        bitmap.getPixels(pix, 0, w, 0, 0, w, h);
        int[] r = new int[wh];
        int[] g = new int[wh];
        int[] b = new int[wh];
        int[] vmin = new int[Math.max(w, h)];
        int divsum = (div + 1) >> 1;
        int divsum2 = divsum * divsum;
        int dv256 = divsum2 * 256;
        int[] dv = new int[dv256];
        for (int i = 0; i < dv256; i++) {
            dv[i] = i / divsum2;
        }
        int yi = 0;
        int yw = 0;
        int[][] stack = (int[][]) Array.newInstance(Integer.TYPE, new int[]{div, 3});
        int r1 = radius + 1;
        for (int y = 0; y < h; y++) {
            int bsum = 0;
            int gsum = 0;
            int rsum = 0;
            int boutsum = 0;
            int goutsum = 0;
            int routsum = 0;
            int binsum = 0;
            int ginsum = 0;
            int rinsum = 0;
            for (int i2 = -radius; i2 <= radius; i2++) {
                int p = pix[Math.min(wm, Math.max(i2, 0)) + yi];
                int[] sir = stack[i2 + radius];
                sir[0] = (16711680 & p) >> 16;
                sir[1] = (65280 & p) >> 8;
                sir[2] = p & 255;
                int rbs = r1 - Math.abs(i2);
                rsum += sir[0] * rbs;
                gsum += sir[1] * rbs;
                bsum += sir[2] * rbs;
                if (i2 > 0) {
                    rinsum += sir[0];
                    ginsum += sir[1];
                    binsum += sir[2];
                } else {
                    routsum += sir[0];
                    goutsum += sir[1];
                    boutsum += sir[2];
                }
            }
            int stackpointer = radius;
            for (int x = 0; x < w; x++) {
                r[yi] = dv[rsum];
                g[yi] = dv[gsum];
                b[yi] = dv[bsum];
                int rsum2 = rsum - routsum;
                int gsum2 = gsum - goutsum;
                int bsum2 = bsum - boutsum;
                int[] sir2 = stack[((stackpointer - radius) + div) % div];
                int routsum2 = routsum - sir2[0];
                int goutsum2 = goutsum - sir2[1];
                int boutsum2 = boutsum - sir2[2];
                if (y == 0) {
                    vmin[x] = Math.min(x + radius + 1, wm);
                }
                int p2 = pix[vmin[x] + yw];
                sir2[0] = (16711680 & p2) >> 16;
                sir2[1] = (65280 & p2) >> 8;
                sir2[2] = p2 & 255;
                int rinsum2 = rinsum + sir2[0];
                int ginsum2 = ginsum + sir2[1];
                int binsum2 = binsum + sir2[2];
                rsum = rsum2 + rinsum2;
                gsum = gsum2 + ginsum2;
                bsum = bsum2 + binsum2;
                stackpointer = (stackpointer + 1) % div;
                int[] sir3 = stack[stackpointer % div];
                routsum = routsum2 + sir3[0];
                goutsum = goutsum2 + sir3[1];
                boutsum = boutsum2 + sir3[2];
                rinsum = rinsum2 - sir3[0];
                ginsum = ginsum2 - sir3[1];
                binsum = binsum2 - sir3[2];
                yi++;
            }
            yw += w;
        }
        for (int x2 = 0; x2 < w; x2++) {
            int bsum3 = 0;
            int gsum3 = 0;
            int rsum3 = 0;
            int boutsum3 = 0;
            int goutsum3 = 0;
            int routsum3 = 0;
            int binsum3 = 0;
            int ginsum3 = 0;
            int rinsum3 = 0;
            int yp = (-radius) * w;
            for (int i3 = -radius; i3 <= radius; i3++) {
                int yi2 = Math.max(0, yp) + x2;
                int[] sir4 = stack[i3 + radius];
                sir4[0] = r[yi2];
                sir4[1] = g[yi2];
                sir4[2] = b[yi2];
                int rbs2 = r1 - Math.abs(i3);
                rsum3 += r[yi2] * rbs2;
                gsum3 += g[yi2] * rbs2;
                bsum3 += b[yi2] * rbs2;
                if (i3 > 0) {
                    rinsum3 += sir4[0];
                    ginsum3 += sir4[1];
                    binsum3 += sir4[2];
                } else {
                    routsum3 += sir4[0];
                    goutsum3 += sir4[1];
                    boutsum3 += sir4[2];
                }
                if (i3 < hm) {
                    yp += w;
                }
            }
            int yi3 = x2;
            int stackpointer2 = radius;
            for (int y2 = 0; y2 < h; y2++) {
                pix[yi3] = (-16777216 & pix[yi3]) | (dv[rsum3] << 16) | (dv[gsum3] << 8) | dv[bsum3];
                int rsum4 = rsum3 - routsum3;
                int gsum4 = gsum3 - goutsum3;
                int bsum4 = bsum3 - boutsum3;
                int[] sir5 = stack[((stackpointer2 - radius) + div) % div];
                int routsum4 = routsum3 - sir5[0];
                int goutsum4 = goutsum3 - sir5[1];
                int boutsum4 = boutsum3 - sir5[2];
                if (x2 == 0) {
                    vmin[y2] = Math.min(y2 + r1, hm) * w;
                }
                int p3 = x2 + vmin[y2];
                sir5[0] = r[p3];
                sir5[1] = g[p3];
                sir5[2] = b[p3];
                int rinsum4 = rinsum3 + sir5[0];
                int ginsum4 = ginsum3 + sir5[1];
                int binsum4 = binsum3 + sir5[2];
                rsum3 = rsum4 + rinsum4;
                gsum3 = gsum4 + ginsum4;
                bsum3 = bsum4 + binsum4;
                stackpointer2 = (stackpointer2 + 1) % div;
                int[] sir6 = stack[stackpointer2];
                routsum3 = routsum4 + sir6[0];
                goutsum3 = goutsum4 + sir6[1];
                boutsum3 = boutsum4 + sir6[2];
                rinsum3 = rinsum4 - sir6[0];
                ginsum3 = ginsum4 - sir6[1];
                binsum3 = binsum4 - sir6[2];
                yi3 += w;
            }
        }
        bitmap.setPixels(pix, 0, w, 0, 0, w, h);
        return bitmap;
    }

    public static Options getBitmapSize(File imageFile) {
        Options options = new Options();
        options.inJustDecodeBounds = true;
        BitmapFactory.decodeFile(imageFile.getAbsolutePath(), options);
        return options;
    }

    public static String resizeFile(String originalUrl, int headerIdx) {
        File file = new File(originalUrl);
        Options option = getBitmapSize(file);
        float defaultSize = 640.0f;
        if (((float) (Boolean.valueOf(option.outWidth < option.outHeight).booleanValue() ? option.outWidth : option.outHeight)) <= 306.0f) {
            defaultSize = 306.0f;
        }
        float gap = option.outWidth < option.outHeight ? defaultSize / ((float) option.outWidth) : defaultSize / ((float) option.outHeight);
        float width = ((float) option.outWidth) * gap;
        float height = ((float) option.outHeight) * gap;
        int bitmapAngle = getBitmapAngle(originalUrl);
        if (bitmapAngle == 90 || bitmapAngle == 270) {
            float tmp = height;
            height = width;
            width = tmp;
        }
        Bitmap adjustedBitmap = Bitmap.createScaledBitmap(getAdjustedBitmap(originalUrl, (int) width, (int) height), (int) width, (int) height, true);
        String[] split = originalUrl.split("/");
        return saveBitmapToJpeg(adjustedBitmap, "", headerIdx + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + split[split.length - 1]);
    }

    public static Bitmap createCircleBitmap(Bitmap bitmap) {
        Bitmap output = Bitmap.createBitmap(bitmap.getWidth(), bitmap.getHeight(), Config.ARGB_8888);
        Rect rect = new Rect(0, 0, bitmap.getWidth(), bitmap.getHeight());
        Canvas canvas = new Canvas(output);
        Paint paint = new Paint();
        paint.setAntiAlias(true);
        int halfWidth = bitmap.getWidth() / 2;
        int halfHeight = bitmap.getHeight() / 2;
        canvas.drawCircle((float) halfWidth, (float) halfHeight, (float) Math.max(halfWidth, halfHeight), paint);
        paint.setXfermode(new PorterDuffXfermode(Mode.SRC_IN));
        canvas.drawBitmap(bitmap, rect, rect, paint);
        return output;
    }
}