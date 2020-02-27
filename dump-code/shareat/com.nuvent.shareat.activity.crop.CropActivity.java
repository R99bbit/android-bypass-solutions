package com.nuvent.shareat.activity.crop;

import android.app.Activity;
import android.app.WallpaperManager;
import android.content.ContentResolver;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.graphics.Bitmap.Config;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.Path.Direction;
import android.graphics.PointF;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Region.Op;
import android.media.FaceDetector;
import android.media.FaceDetector.Face;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.crop.IImage;
import com.nuvent.shareat.util.crop.IImageList;
import com.nuvent.shareat.util.crop.camera.ImageManager;
import com.nuvent.shareat.util.crop.camera.Util;
import com.nuvent.shareat.widget.crop.CropImageView;
import com.nuvent.shareat.widget.crop.HighlightView;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.CountDownLatch;

public class CropActivity extends MonitoredActivity {
    public static final int CROP_FROM_STORE_DETAIL = 5858;
    public static final int CROP_FROM_VIEWER = 3838;
    private IImageList mAllImages;
    /* access modifiers changed from: private */
    public int mAspectX;
    /* access modifiers changed from: private */
    public int mAspectY;
    /* access modifiers changed from: private */
    public Bitmap mBitmap;
    /* access modifiers changed from: private */
    public boolean mCircleCrop = false;
    private ContentResolver mContentResolver;
    public HighlightView mCrop;
    /* access modifiers changed from: private */
    public boolean mDoFaceDetection = true;
    /* access modifiers changed from: private */
    public final Handler mHandler = new Handler();
    /* access modifiers changed from: private */
    public IImage mImage;
    /* access modifiers changed from: private */
    public CropImageView mImageView;
    /* access modifiers changed from: private */
    public int mOutlineCircleColor;
    /* access modifiers changed from: private */
    public int mOutlineColor;
    private CompressFormat mOutputFormat = CompressFormat.JPEG;
    private int mOutputQuality = 100;
    private int mOutputX;
    private int mOutputY;
    Runnable mRunFaceDetection = new Runnable() {
        Face[] mFaces = new Face[3];
        Matrix mImageMatrix;
        int mNumFaces;
        float mScale = 1.0f;

        /* access modifiers changed from: private */
        public void handleFace(Face f) {
            PointF midPoint = new PointF();
            int r = ((int) (f.eyesDistance() * this.mScale)) * 2;
            f.getMidPoint(midPoint);
            midPoint.x *= this.mScale;
            midPoint.y *= this.mScale;
            int midX = (int) midPoint.x;
            int midY = (int) midPoint.y;
            HighlightView hv = new HighlightView(CropActivity.this.mImageView, CropActivity.this.mOutlineColor, CropActivity.this.mOutlineCircleColor);
            Rect imageRect = new Rect(0, 0, CropActivity.this.mBitmap.getWidth(), CropActivity.this.mBitmap.getHeight());
            RectF faceRect = new RectF((float) midX, (float) midY, (float) midX, (float) midY);
            faceRect.inset((float) (-r), (float) (-r));
            if (faceRect.left < 0.0f) {
                faceRect.inset(-faceRect.left, -faceRect.left);
            }
            if (faceRect.top < 0.0f) {
                faceRect.inset(-faceRect.top, -faceRect.top);
            }
            if (faceRect.right > ((float) imageRect.right)) {
                faceRect.inset(faceRect.right - ((float) imageRect.right), faceRect.right - ((float) imageRect.right));
            }
            if (faceRect.bottom > ((float) imageRect.bottom)) {
                faceRect.inset(faceRect.bottom - ((float) imageRect.bottom), faceRect.bottom - ((float) imageRect.bottom));
            }
            hv.setup(this.mImageMatrix, imageRect, faceRect, CropActivity.this.mCircleCrop, (CropActivity.this.mAspectX == 0 || CropActivity.this.mAspectY == 0) ? false : true);
            CropActivity.this.mImageView.add(hv);
        }

        /* access modifiers changed from: private */
        public void makeDefault() {
            boolean z = false;
            HighlightView hv = new HighlightView(CropActivity.this.mImageView, CropActivity.this.mOutlineColor, CropActivity.this.mOutlineCircleColor);
            int width = CropActivity.this.mBitmap.getWidth();
            int height = CropActivity.this.mBitmap.getHeight();
            Rect imageRect = new Rect(0, 0, width, height);
            int cropWidth = (Math.min(width, height) * 5) / 5;
            int cropHeight = cropWidth;
            if (!(CropActivity.this.mAspectX == 0 || CropActivity.this.mAspectY == 0)) {
                if (CropActivity.this.mAspectX > CropActivity.this.mAspectY) {
                    cropHeight = (CropActivity.this.mAspectY * cropWidth) / CropActivity.this.mAspectX;
                } else {
                    cropWidth = (CropActivity.this.mAspectX * cropHeight) / CropActivity.this.mAspectY;
                }
            }
            int x = (width - cropWidth) / 2;
            int y = (height - cropHeight) / 2;
            RectF cropRect = new RectF((float) x, (float) y, (float) (x + cropWidth), (float) (y + cropHeight));
            Matrix matrix = this.mImageMatrix;
            boolean access$800 = CropActivity.this.mCircleCrop;
            if (!(CropActivity.this.mAspectX == 0 || CropActivity.this.mAspectY == 0)) {
                z = true;
            }
            hv.setup(matrix, imageRect, cropRect, access$800, z);
            CropActivity.this.mImageView.add(hv);
        }

        private Bitmap prepareBitmap() {
            if (CropActivity.this.mBitmap == null || CropActivity.this.mBitmap.isRecycled()) {
                return null;
            }
            if (CropActivity.this.mBitmap.getWidth() > 256) {
                this.mScale = 256.0f / ((float) CropActivity.this.mBitmap.getWidth());
            }
            Matrix matrix = new Matrix();
            matrix.setScale(this.mScale, this.mScale);
            return Bitmap.createBitmap(CropActivity.this.mBitmap, 0, 0, CropActivity.this.mBitmap.getWidth(), CropActivity.this.mBitmap.getHeight(), matrix, true);
        }

        public void run() {
            this.mImageMatrix = CropActivity.this.mImageView.getImageMatrix();
            Bitmap faceBitmap = prepareBitmap();
            this.mScale = 1.0f / this.mScale;
            if (faceBitmap != null && CropActivity.this.mDoFaceDetection) {
                this.mNumFaces = new FaceDetector(faceBitmap.getWidth(), faceBitmap.getHeight(), this.mFaces.length).findFaces(faceBitmap, this.mFaces);
            }
            if (!(faceBitmap == null || faceBitmap == CropActivity.this.mBitmap)) {
                faceBitmap.recycle();
            }
            CropActivity.this.mHandler.post(new Runnable() {
                public void run() {
                    boolean z;
                    CropActivity cropActivity = CropActivity.this;
                    if (AnonymousClass6.this.mNumFaces > 1) {
                        z = true;
                    } else {
                        z = false;
                    }
                    cropActivity.mWaitingToPick = z;
                    if (AnonymousClass6.this.mNumFaces > 0) {
                        for (int i = 0; i < AnonymousClass6.this.mNumFaces; i++) {
                            AnonymousClass6.this.handleFace(AnonymousClass6.this.mFaces[i]);
                        }
                    } else {
                        AnonymousClass6.this.makeDefault();
                    }
                    CropActivity.this.mImageView.invalidate();
                    if (CropActivity.this.mImageView.mHighlightViews.size() == 1) {
                        CropActivity.this.mCrop = CropActivity.this.mImageView.mHighlightViews.get(0);
                        CropActivity.this.mCrop.setFocus(true);
                    }
                    if (AnonymousClass6.this.mNumFaces > 1) {
                        Toast.makeText(CropActivity.this, R.string.multiface_crop_help, 0).show();
                    }
                }
            });
        }
    };
    private Uri mSaveUri = null;
    public boolean mSaving;
    private boolean mScale;
    private boolean mScaleUp = true;
    private boolean mSetWallpaper = false;
    public boolean mWaitingToPick;

    public void onCreate(Bundle icicle) {
        super.onCreate(icicle);
        this.mContentResolver = getContentResolver();
        setContentView(R.layout.activity_crop, 2);
        GAEvent.onGAScreenView(this, R.string.ga_instagram_share_crop);
        this.mImageView = (CropImageView) findViewById(R.id.image);
        showFavoriteButton(false);
        setTitle("\uc778\uc2a4\ud0c0\uadf8\ub7a8\uc73c\ub85c \uacf5\uc720");
        if (VERSION.SDK_INT > 10 && VERSION.SDK_INT < 16) {
            this.mImageView.setLayerType(1, null);
        }
        Intent intent = getIntent();
        Bundle extras = intent.getExtras();
        if (extras != null) {
            if (extras.getBoolean("circleCrop", false)) {
                this.mCircleCrop = true;
                this.mAspectX = 1;
                this.mAspectY = 1;
                this.mOutputFormat = CompressFormat.PNG;
            }
            this.mSaveUri = (Uri) extras.getParcelable("output");
            if (this.mSaveUri != null) {
                String outputFormatString = extras.getString("outputFormat");
                if (outputFormatString != null) {
                    this.mOutputFormat = CompressFormat.valueOf(outputFormatString);
                }
                this.mOutputQuality = extras.getInt("outputQuality", 100);
            } else {
                this.mSetWallpaper = extras.getBoolean("setWallpaper");
            }
            this.mBitmap = (Bitmap) extras.getParcelable("data");
            this.mAspectX = extras.getInt("aspectX");
            this.mAspectY = extras.getInt("aspectY");
            this.mOutputX = extras.getInt("outputX");
            this.mOutputY = extras.getInt("outputY");
            this.mOutlineColor = extras.getInt("outlineColor", HighlightView.DEFAULT_OUTLINE_COLOR);
            this.mOutlineCircleColor = extras.getInt("outlineCircleColor", HighlightView.DEFAULT_OUTLINE_CIRCLE_COLOR);
            this.mScale = extras.getBoolean("scale", true);
            this.mScaleUp = extras.getBoolean("scaleUpIfNeeded", true);
            boolean z = extras.containsKey("noFaceDetection") ? !extras.getBoolean("noFaceDetection") : true;
            this.mDoFaceDetection = z;
        }
        if (this.mBitmap == null) {
            Uri target = intent.getData();
            this.mAllImages = ImageManager.makeImageList(this.mContentResolver, target, 1);
            this.mImage = this.mAllImages.getImageForUri(target);
            if (this.mImage != null) {
                this.mBitmap = this.mImage.thumbBitmap(true);
            }
        }
        if (this.mBitmap == null) {
            finish();
            return;
        }
        findViewById(R.id.discard).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) CropActivity.this, (int) R.string.ga_instagram_share_crop, (int) R.string.ga_ev_click, (int) R.string.ga_instagram_share_cancel);
                CropActivity.this.setResult(0);
                CropActivity.this.finish();
            }
        });
        findViewById(R.id.save).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) CropActivity.this, (int) R.string.ga_instagram_share_crop, (int) R.string.ga_ev_click, (int) R.string.ga_instagram_share_confirm);
                CropActivity.this.onSaveClicked();
            }
        });
        startFaceDetection();
    }

    private void startFaceDetection() {
        if (!isFinishing()) {
            this.mImageView.setImageBitmapResetBase(this.mBitmap, true);
            Util.startBackgroundJob(this, null, getResources().getString(R.string.runningfacedetection), new Runnable() {
                public void run() {
                    final Bitmap b;
                    final CountDownLatch latch = new CountDownLatch(1);
                    if (CropActivity.this.mImage != null) {
                        b = CropActivity.this.mImage.fullSizeBitmap(-1, 1048576);
                    } else {
                        b = CropActivity.this.mBitmap;
                    }
                    CropActivity.this.mHandler.post(new Runnable() {
                        public void run() {
                            if (!(b == CropActivity.this.mBitmap || b == null)) {
                                CropActivity.this.mImageView.setImageBitmapResetBase(b, true);
                                CropActivity.this.mBitmap.recycle();
                                CropActivity.this.mBitmap = b;
                            }
                            if (CropActivity.this.mImageView.getScale() == 1.0f) {
                                CropActivity.this.mImageView.center(true, true);
                            }
                            latch.countDown();
                        }
                    });
                    try {
                        latch.await();
                        CropActivity.this.mRunFaceDetection.run();
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                }
            }, this.mHandler);
        }
    }

    /* access modifiers changed from: private */
    public void onSaveClicked() {
        Bitmap croppedImage;
        if (this.mCrop != null && !this.mSaving) {
            this.mSaving = true;
            if (this.mOutputX == 0 || this.mOutputY == 0 || this.mScale) {
                Rect r = this.mCrop.getCropRect();
                int width = r.width();
                int height = r.height();
                croppedImage = Bitmap.createBitmap(width, height, this.mCircleCrop ? Config.ARGB_8888 : Config.RGB_565);
                new Canvas(croppedImage).drawBitmap(this.mBitmap, r, new Rect(0, 0, width, height), null);
                this.mImageView.clear();
                this.mBitmap.recycle();
                if (this.mCircleCrop) {
                    Canvas c = new Canvas(croppedImage);
                    Path p = new Path();
                    p.addCircle(((float) width) / 2.0f, ((float) height) / 2.0f, ((float) width) / 2.0f, Direction.CW);
                    c.clipPath(p, Op.DIFFERENCE);
                    c.drawColor(0, Mode.CLEAR);
                }
                if (!(this.mOutputX == 0 || this.mOutputY == 0 || !this.mScale)) {
                    croppedImage = Util.transform(new Matrix(), croppedImage, this.mOutputX, this.mOutputY, this.mScaleUp, true);
                }
            } else {
                croppedImage = Bitmap.createBitmap(this.mOutputX, this.mOutputY, Config.RGB_565);
                Canvas canvas = new Canvas(croppedImage);
                Rect srcRect = this.mCrop.getCropRect();
                Rect dstRect = new Rect(0, 0, this.mOutputX, this.mOutputY);
                int dx = (srcRect.width() - dstRect.width()) / 2;
                int dy = (srcRect.height() - dstRect.height()) / 2;
                srcRect.inset(Math.max(0, dx), Math.max(0, dy));
                dstRect.inset(Math.max(0, -dx), Math.max(0, -dy));
                canvas.drawBitmap(this.mBitmap, srcRect, dstRect, null);
                this.mImageView.clear();
                this.mBitmap.recycle();
            }
            this.mImageView.setImageBitmapResetBase(croppedImage, true);
            this.mImageView.center(true, true);
            this.mImageView.mHighlightViews.clear();
            Bundle myExtras = getIntent().getExtras();
            if (myExtras == null || (myExtras.getParcelable("data") == null && !myExtras.getBoolean("return-data"))) {
                final Bitmap b = croppedImage;
                Util.startBackgroundJob(this, null, getResources().getString(this.mSetWallpaper ? R.string.wallpaper : R.string.savingImage), new Runnable() {
                    public void run() {
                        CropActivity.this.saveOutput(b);
                    }
                }, this.mHandler);
                return;
            }
            Bundle extras = new Bundle();
            extras.putParcelable("data", croppedImage);
            setResult(-1, new Intent().setAction("inline-data").putExtras(extras));
            finish();
        }
    }

    /* access modifiers changed from: private */
    public void saveOutput(Bitmap croppedImage) {
        if (this.mSaveUri != null) {
            OutputStream outputStream = null;
            try {
                outputStream = this.mContentResolver.openOutputStream(this.mSaveUri);
                if (outputStream != null) {
                    croppedImage.compress(this.mOutputFormat, this.mOutputQuality, outputStream);
                }
            } catch (IOException e) {
            } finally {
                Util.closeSilently((Closeable) outputStream);
            }
            setResult(-1, new Intent(this.mSaveUri.toString()).putExtras(new Bundle()));
        } else if (this.mSetWallpaper) {
            try {
                WallpaperManager.getInstance(this).setBitmap(croppedImage);
                setResult(-1);
            } catch (IOException e2) {
                setResult(0);
            }
        } else {
            Bundle extras = new Bundle();
            extras.putString("rect", this.mCrop.getCropRect().toString());
            File file = new File(this.mImage.getDataPath());
            File directory = new File(file.getParent());
            int x = 0;
            String fileName = file.getName();
            String fileName2 = fileName.substring(0, fileName.lastIndexOf("."));
            do {
                x++;
            } while (new File(directory.toString() + "/" + fileName2 + "-" + x + ".jpg").exists());
            try {
                setResult(-1, new Intent().setAction(ImageManager.addImage(this.mContentResolver, this.mImage.getTitle(), this.mImage.getDateTaken(), null, directory.toString(), fileName2 + "-" + x + ".jpg", croppedImage, null, new int[1]).toString()).putExtras(extras));
            } catch (Exception e3) {
            }
        }
        final Bitmap b = croppedImage;
        this.mHandler.post(new Runnable() {
            public void run() {
                CropActivity.this.mImageView.clear();
                b.recycle();
            }
        });
        finish();
    }

    /* access modifiers changed from: protected */
    public void onPause() {
        super.onPause();
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        if (this.mAllImages != null) {
            this.mAllImages.close();
        }
        super.onDestroy();
    }
}