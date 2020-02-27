package com.nostra13.universalimageloader.core.decode;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.BitmapFactory.Options;
import android.graphics.Matrix;
import android.media.ExifInterface;
import com.nostra13.universalimageloader.core.assist.ImageScaleType;
import com.nostra13.universalimageloader.core.assist.ImageSize;
import com.nostra13.universalimageloader.core.download.ImageDownloader.Scheme;
import com.nostra13.universalimageloader.utils.ImageSizeUtils;
import com.nostra13.universalimageloader.utils.IoUtils;
import com.nostra13.universalimageloader.utils.L;
import java.io.IOException;
import java.io.InputStream;

public class BaseImageDecoder implements ImageDecoder {
    protected static final String ERROR_CANT_DECODE_IMAGE = "Image can't be decoded [%s]";
    protected static final String LOG_FLIP_IMAGE = "Flip image horizontally [%s]";
    protected static final String LOG_ROTATE_IMAGE = "Rotate image on %1$d\u00b0 [%2$s]";
    protected static final String LOG_SCALE_IMAGE = "Scale subsampled image (%1$s) to %2$s (scale = %3$.5f) [%4$s]";
    protected static final String LOG_SUBSAMPLE_IMAGE = "Subsample original image (%1$s) to %2$s (scale = %3$d) [%4$s]";
    protected final boolean loggingEnabled;

    protected static class ExifInfo {
        public final boolean flipHorizontal;
        public final int rotation;

        protected ExifInfo() {
            this.rotation = 0;
            this.flipHorizontal = false;
        }

        protected ExifInfo(int rotation2, boolean flipHorizontal2) {
            this.rotation = rotation2;
            this.flipHorizontal = flipHorizontal2;
        }
    }

    protected static class ImageFileInfo {
        public final ExifInfo exif;
        public final ImageSize imageSize;

        protected ImageFileInfo(ImageSize imageSize2, ExifInfo exif2) {
            this.imageSize = imageSize2;
            this.exif = exif2;
        }
    }

    public BaseImageDecoder(boolean loggingEnabled2) {
        this.loggingEnabled = loggingEnabled2;
    }

    public Bitmap decode(ImageDecodingInfo decodingInfo) throws IOException {
        InputStream imageStream = getImageStream(decodingInfo);
        try {
            ImageFileInfo imageInfo = defineImageSizeAndRotation(imageStream, decodingInfo);
            imageStream = resetStream(imageStream, decodingInfo);
            Bitmap decodedBitmap = BitmapFactory.decodeStream(imageStream, null, prepareDecodingOptions(imageInfo.imageSize, decodingInfo));
            if (decodedBitmap != null) {
                return considerExactScaleAndOrientatiton(decodedBitmap, decodingInfo, imageInfo.exif.rotation, imageInfo.exif.flipHorizontal);
            }
            L.e(ERROR_CANT_DECODE_IMAGE, decodingInfo.getImageKey());
            return decodedBitmap;
        } finally {
            IoUtils.closeSilently(imageStream);
        }
    }

    /* access modifiers changed from: protected */
    public InputStream getImageStream(ImageDecodingInfo decodingInfo) throws IOException {
        return decodingInfo.getDownloader().getStream(decodingInfo.getImageUri(), decodingInfo.getExtraForDownloader());
    }

    /* access modifiers changed from: protected */
    public ImageFileInfo defineImageSizeAndRotation(InputStream imageStream, ImageDecodingInfo decodingInfo) throws IOException {
        ExifInfo exif;
        Options options = new Options();
        options.inJustDecodeBounds = true;
        BitmapFactory.decodeStream(imageStream, null, options);
        String imageUri = decodingInfo.getImageUri();
        if (!decodingInfo.shouldConsiderExifParams() || !canDefineExifParams(imageUri, options.outMimeType)) {
            exif = new ExifInfo();
        } else {
            exif = defineExifOrientation(imageUri);
        }
        return new ImageFileInfo(new ImageSize(options.outWidth, options.outHeight, exif.rotation), exif);
    }

    private boolean canDefineExifParams(String imageUri, String mimeType) {
        return "image/jpeg".equalsIgnoreCase(mimeType) && Scheme.ofUri(imageUri) == Scheme.FILE;
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:11:0x0027, code lost:
        r4 = 180;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:13:0x002b, code lost:
        r4 = 270;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x0020, code lost:
        r4 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0023, code lost:
        r4 = 90;
     */
    public ExifInfo defineExifOrientation(String imageUri) {
        int rotation = 0;
        boolean flip = false;
        try {
            switch (new ExifInterface(Scheme.FILE.crop(imageUri)).getAttributeInt("Orientation", 1)) {
                case 1:
                    break;
                case 2:
                    flip = true;
                    break;
                case 3:
                    break;
                case 4:
                    flip = true;
                    break;
                case 5:
                    flip = true;
                    break;
                case 6:
                    break;
                case 7:
                    flip = true;
                    break;
                case 8:
                    break;
            }
        } catch (IOException e) {
            L.w("Can't read EXIF tags from file [%s]", imageUri);
        }
        return new ExifInfo(rotation, flip);
    }

    /* access modifiers changed from: protected */
    public Options prepareDecodingOptions(ImageSize imageSize, ImageDecodingInfo decodingInfo) {
        boolean powerOf2;
        int scale;
        ImageScaleType scaleType = decodingInfo.getImageScaleType();
        if (scaleType == ImageScaleType.NONE) {
            scale = 1;
        } else if (scaleType == ImageScaleType.NONE_SAFE) {
            scale = ImageSizeUtils.computeMinImageSampleSize(imageSize);
        } else {
            ImageSize targetSize = decodingInfo.getTargetSize();
            if (scaleType == ImageScaleType.IN_SAMPLE_POWER_OF_2) {
                powerOf2 = true;
            } else {
                powerOf2 = false;
            }
            scale = ImageSizeUtils.computeImageSampleSize(imageSize, targetSize, decodingInfo.getViewScaleType(), powerOf2);
        }
        if (scale > 1 && this.loggingEnabled) {
            L.d(LOG_SUBSAMPLE_IMAGE, imageSize, imageSize.scaleDown(scale), Integer.valueOf(scale), decodingInfo.getImageKey());
        }
        Options decodingOptions = decodingInfo.getDecodingOptions();
        decodingOptions.inSampleSize = scale;
        return decodingOptions;
    }

    /* access modifiers changed from: protected */
    public InputStream resetStream(InputStream imageStream, ImageDecodingInfo decodingInfo) throws IOException {
        try {
            imageStream.reset();
            return imageStream;
        } catch (IOException e) {
            IoUtils.closeSilently(imageStream);
            return getImageStream(decodingInfo);
        }
    }

    /* access modifiers changed from: protected */
    public Bitmap considerExactScaleAndOrientatiton(Bitmap subsampledBitmap, ImageDecodingInfo decodingInfo, int rotation, boolean flipHorizontal) {
        Matrix m = new Matrix();
        ImageScaleType scaleType = decodingInfo.getImageScaleType();
        if (scaleType == ImageScaleType.EXACTLY || scaleType == ImageScaleType.EXACTLY_STRETCHED) {
            ImageSize srcSize = new ImageSize(subsampledBitmap.getWidth(), subsampledBitmap.getHeight(), rotation);
            float scale = ImageSizeUtils.computeImageScale(srcSize, decodingInfo.getTargetSize(), decodingInfo.getViewScaleType(), scaleType == ImageScaleType.EXACTLY_STRETCHED);
            if (Float.compare(scale, 1.0f) != 0) {
                m.setScale(scale, scale);
                if (this.loggingEnabled) {
                    L.d(LOG_SCALE_IMAGE, srcSize, srcSize.scale(scale), Float.valueOf(scale), decodingInfo.getImageKey());
                }
            }
        }
        if (flipHorizontal) {
            m.postScale(-1.0f, 1.0f);
            if (this.loggingEnabled) {
                L.d(LOG_FLIP_IMAGE, decodingInfo.getImageKey());
            }
        }
        if (rotation != 0) {
            m.postRotate((float) rotation);
            if (this.loggingEnabled) {
                L.d(LOG_ROTATE_IMAGE, Integer.valueOf(rotation), decodingInfo.getImageKey());
            }
        }
        Bitmap finalBitmap = Bitmap.createBitmap(subsampledBitmap, 0, 0, subsampledBitmap.getWidth(), subsampledBitmap.getHeight(), m, true);
        if (finalBitmap != subsampledBitmap) {
            subsampledBitmap.recycle();
        }
        return finalBitmap;
    }
}