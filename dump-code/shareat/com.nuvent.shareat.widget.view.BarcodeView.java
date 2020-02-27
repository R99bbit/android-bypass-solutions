package com.nuvent.shareat.widget.view;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import com.nostra13.universalimageloader.core.assist.FailReason;
import com.nostra13.universalimageloader.core.listener.ImageLoadingListener;
import com.nuvent.shareat.R;
import net.xenix.util.ImageDisplay;

public class BarcodeView extends FrameLayout {
    private Bitmap mBitmap;

    public BarcodeView(Context context) {
        super(context);
        init();
    }

    public BarcodeView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public BarcodeView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        View.inflate(getContext(), R.layout.view_slide_barcode, this);
    }

    public void setBarcodeUrl(String url) {
        ImageDisplay.getInstance().displayImageLoad(url, (ImageView) findViewById(R.id.barcodeImageView), (ImageLoadingListener) new ImageLoadingListener() {
            public void onLoadingStarted(String imageUri, View view) {
            }

            public void onLoadingFailed(String imageUri, View view, FailReason failReason) {
            }

            public void onLoadingComplete(String imageUri, View view, Bitmap loadedImage) {
                BarcodeView.this.setBitmap(loadedImage);
            }

            public void onLoadingCancelled(String imageUri, View view) {
            }
        });
    }

    public void hideDisableView() {
        findViewById(R.id.disableView).setVisibility(8);
    }

    public void setTimerLabel(String text) {
        ((TextView) findViewById(R.id.timerLabel)).setText(text);
        if (text.equals("00:00")) {
            ((TextView) findViewById(R.id.statusLabel)).setText("\uc720\ud6a8\uc2dc\uac04\ub9cc\ub8cc");
            findViewById(R.id.disableView).setVisibility(0);
            return;
        }
        ((TextView) findViewById(R.id.statusLabel)).setText("");
        if (8 != findViewById(R.id.disableView).getVisibility()) {
            findViewById(R.id.disableView).setVisibility(8);
        }
    }

    /* access modifiers changed from: private */
    public void setBitmap(Bitmap barcodeBitmap) {
        ((ImageView) findViewById(R.id.barcodeImageView)).setImageResource(17170445);
        Matrix matrix = new Matrix();
        matrix.postRotate(90.0f);
        if (!barcodeBitmap.isRecycled()) {
            this.mBitmap = Bitmap.createBitmap(barcodeBitmap, 0, 0, barcodeBitmap.getWidth(), barcodeBitmap.getHeight(), matrix, true);
            ((ImageView) findViewById(R.id.barcodeImageView)).setImageBitmap(this.mBitmap);
        }
    }
}