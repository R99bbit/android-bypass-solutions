package com.nuvent.shareat.util.crop;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import com.nuvent.shareat.activity.crop.CropActivity;
import com.nuvent.shareat.widget.crop.HighlightView;

public class CropImageIntentBuilder {
    private static final int DEFAULT_SCALE = 1;
    private static final String EXTRA_ASPECT_X = "aspectX";
    private static final String EXTRA_ASPECT_Y = "aspectY";
    private static final String EXTRA_BITMAP_DATA = "data";
    private static final String EXTRA_CIRCLE_CROP = "circleCrop";
    private static final String EXTRA_NO_FACE_DETECTION = "noFaceDetection";
    private static final String EXTRA_OUTLINE_CIRCLE_COLOR = "outlineCircleColor";
    private static final String EXTRA_OUTLINE_COLOR = "outlineColor";
    private static final String EXTRA_OUTPUT_FORMAT = "outputFormat";
    private static final String EXTRA_OUTPUT_QUALITY = "outputQuality";
    private static final String EXTRA_OUTPUT_X = "outputX";
    private static final String EXTRA_OUTPUT_Y = "outputY";
    private static final String EXTRA_SCALE = "scale";
    private static final String EXTRA_SCALE_UP_IF_NEEDED = "scaleUpIfNeeded";
    private final int aspectX;
    private final int aspectY;
    private Bitmap bitmap;
    private boolean circleCrop;
    private boolean doFaceDetection;
    private int outlineCircleColor;
    private int outlineColor;
    private String outputFormat;
    private int outputQuality;
    private final int outputX;
    private final int outputY;
    private final Uri saveUri;
    private boolean scale;
    private boolean scaleUpIfNeeded;
    private Uri sourceImage;

    public CropImageIntentBuilder(int outputX2, int outputY2, Uri saveUri2) {
        this(1, 1, outputX2, outputY2, saveUri2);
    }

    public CropImageIntentBuilder(int aspectX2, int aspectY2, int outputX2, int outputY2, Uri saveUri2) {
        this.scale = true;
        this.scaleUpIfNeeded = true;
        this.doFaceDetection = true;
        this.circleCrop = false;
        this.outputFormat = null;
        this.outputQuality = 100;
        this.outlineColor = HighlightView.DEFAULT_OUTLINE_COLOR;
        this.outlineCircleColor = HighlightView.DEFAULT_OUTLINE_CIRCLE_COLOR;
        this.aspectX = aspectX2;
        this.aspectY = aspectY2;
        this.outputX = outputX2;
        this.outputY = outputY2;
        this.saveUri = saveUri2;
    }

    public Intent getIntent(Context context) {
        Intent intent = new Intent(context, CropActivity.class);
        intent.putExtra(EXTRA_ASPECT_X, this.aspectX);
        intent.putExtra(EXTRA_ASPECT_Y, this.aspectY);
        intent.putExtra(EXTRA_OUTPUT_X, this.outputX);
        intent.putExtra(EXTRA_OUTPUT_Y, this.outputY);
        intent.putExtra("output", this.saveUri);
        intent.putExtra(EXTRA_SCALE, this.scale);
        intent.putExtra(EXTRA_SCALE_UP_IF_NEEDED, this.scaleUpIfNeeded);
        intent.putExtra(EXTRA_NO_FACE_DETECTION, !this.doFaceDetection);
        intent.putExtra(EXTRA_CIRCLE_CROP, this.circleCrop);
        intent.putExtra(EXTRA_OUTPUT_FORMAT, this.outputFormat);
        intent.putExtra(EXTRA_OUTPUT_QUALITY, this.outputQuality);
        intent.putExtra(EXTRA_OUTLINE_COLOR, this.outlineColor);
        intent.putExtra(EXTRA_OUTLINE_CIRCLE_COLOR, this.outlineCircleColor);
        if (this.bitmap != null) {
            intent.putExtra("data", this.bitmap);
        }
        if (this.sourceImage != null) {
            intent.setData(this.sourceImage);
        }
        return intent;
    }

    public CropImageIntentBuilder setOutputQuality(int outputQuality2) {
        this.outputQuality = outputQuality2;
        return this;
    }

    public CropImageIntentBuilder setScale(boolean scale2) {
        this.scale = scale2;
        return this;
    }

    public CropImageIntentBuilder setScaleUpIfNeeded(boolean scaleUpIfNeeded2) {
        this.scaleUpIfNeeded = scaleUpIfNeeded2;
        return this;
    }

    public CropImageIntentBuilder setDoFaceDetection(boolean doFaceDetection2) {
        this.doFaceDetection = doFaceDetection2;
        return this;
    }

    public CropImageIntentBuilder setBitmap(Bitmap bitmap2) {
        this.bitmap = bitmap2;
        return this;
    }

    public CropImageIntentBuilder setSourceImage(Uri sourceImage2) {
        this.sourceImage = sourceImage2;
        return this;
    }

    public CropImageIntentBuilder setCircleCrop(boolean circleCrop2) {
        this.circleCrop = circleCrop2;
        return this;
    }

    public CropImageIntentBuilder setOutputFormat(String outputFormat2) {
        this.outputFormat = outputFormat2;
        return this;
    }

    public CropImageIntentBuilder setOutlineColor(int color) {
        this.outlineColor = color;
        return this;
    }

    public CropImageIntentBuilder setOutlineCircleColor(int color) {
        this.outlineCircleColor = color;
        return this;
    }
}