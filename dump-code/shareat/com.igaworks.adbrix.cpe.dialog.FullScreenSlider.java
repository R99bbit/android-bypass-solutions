package com.igaworks.adbrix.cpe.dialog;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.support.v4.view.ViewCompat;
import android.view.ViewGroup.LayoutParams;
import android.widget.FrameLayout;
import com.igaworks.adbrix.core.ADBrixHttpManager;

public class FullScreenSlider extends Dialog {
    public static final int SLIDE_AREA_ID = 27033;
    public static FullScreenSlider slider;
    private Activity activity;
    private int campaignKey;
    private int currentSlideNo = -1;
    private int position;

    public FullScreenSlider(Context context, Activity activity2, int campaignKey2, int position2) {
        super(context, 16973836);
        this.campaignKey = campaignKey2;
        this.position = position2;
        this.activity = activity2;
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        getWindow().setFlags(1024, 1024);
        getWindow().getDecorView().setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        slider = this;
        if (this.campaignKey == 0) {
            dismiss();
            return;
        }
        if (savedInstanceState != null) {
            try {
                this.currentSlideNo = savedInstanceState.getInt("slideNo", -1);
            } catch (Exception e) {
                dismiss();
                e.printStackTrace();
            }
        } else {
            this.currentSlideNo = this.position;
        }
        createView();
    }

    private void createView() {
        FrameLayout containerLayout = new FrameLayout(this.activity);
        containerLayout.setId(27033);
        LayoutParams containerLayoutParam = new LayoutParams(-1, -1);
        if (ADBrixHttpManager.schedule == null || ADBrixHttpManager.schedule.getSchedule() == null) {
            dismiss();
            return;
        }
        containerLayout.addView(new PlaceDetailsLayout(this.activity, this.campaignKey, this.currentSlideNo, true));
        addContentView(containerLayout, containerLayoutParam);
    }
}