package com.nuvent.shareat.activity.common;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.support.v4.app.FragmentActivity;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.RelativeLayout;
import android.widget.RelativeLayout.LayoutParams;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.model.InstagramModel;
import com.nuvent.shareat.util.ExternalApp;
import com.nuvent.shareat.util.GAEvent;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import net.xenix.util.ImageDisplay;

public class InstagramShareActivity extends MainActionBarActivity implements OnClickListener {
    private final int COLOR = 2;
    private final int DARK = 1;
    private final int LIGHT = 0;
    private final int LOC_BOTTOM_RIGHT = 2;
    private final int LOC_TOP_LEFT = 0;
    private final int LOC_TOP_RIGHT = 1;
    private final int[] MARKS = {R.drawable.mark_light, R.drawable.mark_dark, R.drawable.mark_color};
    private int defaultMargin = 0;
    private RelativeLayout mCaptureView;
    private int mLightSelectIdx = 0;
    private View[] mLightSelectViews;
    private int mLocationSelectIdx = 0;
    private View[] mLocationSelectViews;
    private View mMarksView;
    private InstagramModel mModel;
    private ImageView mShareImgView;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_instagram, 2);
        showFavoriteButton(false);
        GAEvent.onGAScreenView(this, R.string.ga_instagram_share);
        setTitle("\uc778\uc2a4\ud0c0\uadf8\ub7a8\uc73c\ub85c \uacf5\uc720");
        this.mModel = (InstagramModel) getIntent().getSerializableExtra("model");
        this.defaultMargin = getResources().getDimensionPixelOffset(R.dimen.INSTAGRAM_SHARE_MARK_MARGIN);
        settingUI();
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
        deleteTmpFile();
        if (new File(this.mModel.getFileName()).exists()) {
            try {
                FileInputStream in = new FileInputStream(this.mModel.getFileName());
                BufferedInputStream buf = new BufferedInputStream(in);
                Bitmap bMap = BitmapFactory.decodeStream(buf);
                this.mShareImgView.setScaleType(ScaleType.FIT_CENTER);
                this.mShareImgView.setImageBitmap(bMap);
                this.mShareImgView.postInvalidate();
                if (in != null) {
                    in.close();
                }
                if (buf != null) {
                    buf.close();
                }
            } catch (Exception e) {
            }
        }
    }

    public void settingUI() {
        findViewById(R.id.share_btn).setOnClickListener(this);
        this.mMarksView = findViewById(R.id.share_horizontal_mark);
        this.mShareImgView = (ImageView) findViewById(R.id.share_instagram_img);
        this.mCaptureView = (RelativeLayout) findViewById(R.id.share_instagram_img_layout);
        this.mLocationSelectViews = new View[]{findViewById(R.id.loc_top_left), findViewById(R.id.loc_top_right), findViewById(R.id.loc_bottom_right)};
        this.mLightSelectViews = new View[]{findViewById(R.id.light_selector), findViewById(R.id.dark_selector), findViewById(R.id.color_selector)};
        for (View view : this.mLocationSelectViews) {
            view.setOnClickListener(this);
        }
        for (View view2 : this.mLightSelectViews) {
            view2.setOnClickListener(this);
        }
        selectedView(0, Boolean.valueOf(true));
        selectedView(0, Boolean.valueOf(false));
    }

    private void selectedView(int selectedIdx, Boolean isLoc) {
        View[] views;
        if (isLoc.booleanValue()) {
            views = this.mLocationSelectViews;
            onViewLocation(selectedIdx);
        } else {
            views = this.mLightSelectViews;
            onLightNDarkNColor(selectedIdx);
        }
        for (View view : views) {
            view.setSelected(false);
        }
        views[selectedIdx].setSelected(true);
    }

    private void onLightNDarkNColor(int selectedIdx) {
        this.mMarksView.setBackgroundResource(this.MARKS[selectedIdx]);
    }

    private void onViewLocation(int selectedIdx) {
        LayoutParams childParam = (LayoutParams) this.mMarksView.getLayoutParams();
        initRule(childParam);
        switch (selectedIdx) {
            case 0:
                childParam.addRule(10);
                childParam.leftMargin = this.defaultMargin;
                childParam.topMargin = this.defaultMargin;
                break;
            case 1:
                childParam.addRule(10);
                childParam.addRule(11);
                childParam.rightMargin = this.defaultMargin;
                childParam.topMargin = this.defaultMargin;
                break;
            case 2:
                childParam.addRule(12);
                childParam.addRule(11);
                childParam.rightMargin = this.defaultMargin;
                childParam.bottomMargin = this.defaultMargin;
                break;
        }
        this.mMarksView.setLayoutParams(childParam);
    }

    private void initRule(ViewGroup.LayoutParams params) {
        int[] rules = ((LayoutParams) params).getRules();
        for (int i = 0; i < rules.length; i++) {
            rules[i] = 0;
        }
    }

    private void deleteTmpFile() {
        File shareTmpFile = new File(Environment.getExternalStorageDirectory() + ImageDisplay.TEMP_SHARE_FILE_NAME);
        if (shareTmpFile.exists()) {
            shareTmpFile.delete();
        }
    }

    private void createInstagramIntent(String mediaPath) {
        String captionText = "#share@NU\uc778\uc2a4\ud0c0\uacf5\uc2dd\uacc4\uc815\n...\n\ub9ac\ubdf0\ub0b4\uc6a9 \ubc0f \ub9e4\uc7a5 \uc124\uba85\nPhoto by \uc791\uc131\uc790 or \ub9e4\uc7a5\uba85\nURL : $http://\ub9e4\uc7a5\uc0c1\uc138\ub9ac\ubdf0\uc8fc\uc18c";
        if (this.mModel != null) {
            captionText = this.mModel.getCaptionText(this);
        }
        Intent share = new Intent("android.intent.action.SEND");
        share.setType("image/*");
        share.putExtra("android.intent.extra.STREAM", Uri.fromFile(new File(mediaPath)));
        share.putExtra("android.intent.extra.TEXT", captionText);
        share.setPackage(ExternalApp.INSTAGRAM);
        if (!ExternalApp.onInstallApp((FragmentActivity) this, (int) R.string.INTAGRAM_INSTALL_CONFIRM_MSG, share, (String) ExternalApp.INSTAGRAM)) {
            startActivity(share);
            finish(false);
        }
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.color_selector /*2131296494*/:
                this.mLightSelectIdx = 2;
                selectedView(this.mLightSelectIdx, Boolean.valueOf(false));
                return;
            case R.id.dark_selector /*2131296550*/:
                this.mLightSelectIdx = 1;
                selectedView(this.mLightSelectIdx, Boolean.valueOf(false));
                return;
            case R.id.light_selector /*2131296786*/:
                this.mLightSelectIdx = 0;
                selectedView(this.mLightSelectIdx, Boolean.valueOf(false));
                return;
            case R.id.loc_bottom_right /*2131296804*/:
                this.mLocationSelectIdx = 2;
                selectedView(this.mLocationSelectIdx, Boolean.valueOf(true));
                return;
            case R.id.loc_top_left /*2131296805*/:
                this.mLocationSelectIdx = 0;
                selectedView(this.mLocationSelectIdx, Boolean.valueOf(true));
                return;
            case R.id.loc_top_right /*2131296806*/:
                this.mLocationSelectIdx = 1;
                selectedView(this.mLocationSelectIdx, Boolean.valueOf(true));
                return;
            case R.id.share_btn /*2131297297*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_instagram_share, (int) R.string.ga_ev_click, (int) R.string.ga_instagram_share_share);
                this.mCaptureView.buildDrawingCache();
                Bitmap captureView = Bitmap.createScaledBitmap(this.mCaptureView.getDrawingCache(), ImageDisplay.THUMBNAIL_IMAGE_SIZE, ImageDisplay.THUMBNAIL_IMAGE_SIZE, true);
                try {
                    String shareTmpPath = Environment.getExternalStorageDirectory() + ImageDisplay.TEMP_SHARE_FILE_NAME;
                    captureView.compress(CompressFormat.PNG, 100, new FileOutputStream(shareTmpPath));
                    createInstagramIntent(shareTmpPath);
                    return;
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                    return;
                }
            default:
                return;
        }
    }
}