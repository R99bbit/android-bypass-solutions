package com.igaworks.adbrix.cpe.dialog;

import android.app.Activity;
import android.graphics.Bitmap;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.cpe.common.CirclePageIndicator;
import com.igaworks.adbrix.cpe.common.PageIndicator;
import com.igaworks.adbrix.model.Promotion;
import com.igaworks.adbrix.util.CPEConstant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class PlaceDetailsLayout extends LinearLayout {
    public static final String TAG = "detailsFragment";
    public static PlaceDetailsLayout pdLayout;
    private int campaignKey;
    private boolean isFullScreen = false;
    private PlaceSlidesAdapter mAdapter;
    private PageIndicator mIndicator;
    public ViewPager mPager;
    private Promotion promotion;
    private int slideNo = -1;
    private List<Bitmap> usedBitmap;

    public PlaceDetailsLayout(Activity context, int campaignKey2, int slideNo2, boolean isFullScreen2) {
        super(context);
        pdLayout = this;
        setLayoutParams(new LayoutParams(-1, -1));
        this.campaignKey = campaignKey2;
        this.slideNo = slideNo2;
        this.isFullScreen = isFullScreen2;
        try {
            Iterator<Promotion> it = ADBrixHttpManager.schedule.getSchedule().getPromotions().iterator();
            while (true) {
                if (it.hasNext()) {
                    Promotion promotion2 = it.next();
                    if (promotion2.getCampaignKey() == campaignKey2) {
                        this.promotion = promotion2;
                        break;
                    }
                } else {
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            if (PromotionDialog.promotionDialog != null) {
                PromotionDialog.promotionDialog.finishDialog();
            }
        }
        init(context);
    }

    public void init(Activity context) {
        FrameLayout root = new FrameLayout(context);
        root.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        if (this.promotion == null) {
            PromotionDialog.promotionDialog.finishDialog();
            return;
        }
        this.mAdapter = new PlaceSlidesAdapter(context, this.promotion.getDisplay().getSlide().getResource(), this.campaignKey, this.isFullScreen);
        this.mPager = new ViewPager(context);
        this.mPager.setId(10649);
        this.mPager.setAdapter(this.mAdapter);
        root.addView(this.mPager);
        if (this.promotion.getDisplay().getSlide().getResource() != null && this.promotion.getDisplay().getSlide().getResource().size() > 1) {
            this.mIndicator = new CirclePageIndicator(context);
            FrameLayout.LayoutParams mIndicatorParam = new FrameLayout.LayoutParams(-1, -2, 80);
            this.mIndicator.setViewPager(this.mPager);
            ((CirclePageIndicator) this.mIndicator).setSnap(true);
            int adImageSectionTitleMargin = CPEConstant.convertPixelToDP(context, 4, true);
            ((CirclePageIndicator) this.mIndicator).setPadding(adImageSectionTitleMargin, adImageSectionTitleMargin, adImageSectionTitleMargin, adImageSectionTitleMargin);
            ((CirclePageIndicator) this.mIndicator).setLayoutParams(mIndicatorParam);
            this.mIndicator.setOnPageChangeListener(new OnPageChangeListener() {
                public void onPageSelected(int position) {
                }

                public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                }

                public void onPageScrollStateChanged(int state) {
                }
            });
            root.addView((CirclePageIndicator) this.mIndicator);
        }
        if (this.slideNo > -1) {
            this.mPager.setCurrentItem(this.slideNo);
        }
        addView(root);
    }

    public void addUsingBitmap(Bitmap bitmap) {
        if (!this.isFullScreen) {
            if (this.usedBitmap == null) {
                this.usedBitmap = new ArrayList();
            }
            if (!this.usedBitmap.contains(bitmap)) {
                this.usedBitmap.add(bitmap);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        try {
            if (this.usedBitmap != null && !this.isFullScreen) {
                this.usedBitmap.clear();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}