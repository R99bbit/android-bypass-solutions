package com.igaworks.adbrix.cpe.activitydialog;

import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentTransaction;
import android.support.v4.view.ViewCompat;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager.LayoutParams;
import android.widget.FrameLayout;
import com.igaworks.adbrix.core.ADBrixHttpManager;

public class FullScreenSlider extends FragmentActivity {
    public static final int SLIDE_AREA_ID = 27033;
    public static FullScreenSlider slider;
    private int campaignKey;
    private int currentSlideNo = -1;
    private int position;

    public /* bridge */ /* synthetic */ View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        return super.onCreateView(view, str, context, attributeSet);
    }

    public /* bridge */ /* synthetic */ View onCreateView(String str, Context context, AttributeSet attributeSet) {
        return super.onCreateView(str, context, attributeSet);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        slider = this;
        LayoutParams lpWindow = getWindow().getAttributes();
        lpWindow.flags = 2;
        lpWindow.dimAmount = 0.6f;
        lpWindow.width = -1;
        lpWindow.height = -2;
        getWindow().setAttributes(lpWindow);
        getWindow().setSoftInputMode(16);
        getWindow().getDecorView().setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        getWindow().setFormat(1);
        getWindow().addFlags(4096);
        this.campaignKey = getIntent().getIntExtra("campaignKey", 0);
        this.position = getIntent().getIntExtra("position", 0);
        if (this.campaignKey == 0) {
            finish();
            return;
        }
        if (savedInstanceState != null) {
            try {
                this.currentSlideNo = savedInstanceState.getInt("slideNo", -1);
            } catch (Exception e) {
                finish();
                e.printStackTrace();
            }
        } else {
            this.currentSlideNo = this.position;
        }
        createView();
    }

    private void createView() {
        FrameLayout containerLayout = new FrameLayout(this);
        containerLayout.setId(27033);
        ViewGroup.LayoutParams containerLayoutParam = new ViewGroup.LayoutParams(-1, -1);
        if (ADBrixHttpManager.schedule == null || ADBrixHttpManager.schedule.getSchedule() == null) {
            finish();
            return;
        }
        FragmentTransaction ft = getSupportFragmentManager().beginTransaction();
        ft.replace(27033, PlaceDetailsFragment.newInstance(this.campaignKey, this.currentSlideNo, true));
        ft.setTransition(FragmentTransaction.TRANSIT_FRAGMENT_FADE);
        ft.commit();
        addContentView(containerLayout, containerLayoutParam);
    }

    /* access modifiers changed from: protected */
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        if (PlaceDetailsFragment.pdFragment != null && PlaceDetailsFragment.pdFragment.mPager != null) {
            outState.putInt("slideNo", PlaceDetailsFragment.pdFragment.mPager.getCurrentItem());
        }
    }
}