package com.igaworks.adbrix.cpe.activitydialog;

import android.graphics.Bitmap;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.cpe.common.CirclePageIndicator;
import com.igaworks.adbrix.cpe.common.PageIndicator;
import com.igaworks.adbrix.model.Promotion;
import com.igaworks.adbrix.util.CPEConstant;
import java.util.ArrayList;
import java.util.List;

public class PlaceDetailsFragment extends Fragment {
    public static final String TAG = "detailsFragment";
    public static PlaceDetailsFragment pdFragment;
    private int campaignKey;
    private boolean isFullScreen = false;
    private PlaceSlidesFragmentAdapter mAdapter;
    private PageIndicator mIndicator;
    public ViewPager mPager;
    private Promotion promotion;
    private int slideNo = -1;
    private List<Bitmap> usedBitmap;

    public static PlaceDetailsFragment newInstance(int campaignKey2, int slideNo2, boolean isFullScreen2) {
        PlaceDetailsFragment pdf = new PlaceDetailsFragment();
        Bundle bundle = new Bundle();
        bundle.putInt("campaignKey", campaignKey2);
        bundle.putInt("slideNo", slideNo2);
        bundle.putBoolean("isFullScreen", isFullScreen2);
        pdf.setArguments(bundle);
        return pdf;
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        pdFragment = this;
        this.campaignKey = getArguments().getInt("campaignKey");
        this.slideNo = getArguments().getInt("slideNo", -1);
        this.isFullScreen = getArguments().getBoolean("isFullScreen", false);
        try {
            for (Promotion promotion2 : ADBrixHttpManager.schedule.getSchedule().getPromotions()) {
                if (promotion2.getCampaignKey() == this.campaignKey) {
                    this.promotion = promotion2;
                    return;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            if (PromotionActivityDialog.promotionDialog != null) {
                PromotionActivityDialog.promotionDialog.finish();
            }
        }
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        FrameLayout root = new FrameLayout(getActivity());
        root.setLayoutParams(new LayoutParams(-1, -1));
        if (this.promotion == null) {
            PromotionActivityDialog.promotionDialog.finish();
        } else {
            this.mAdapter = new PlaceSlidesFragmentAdapter(getChildFragmentManager(), this.promotion.getDisplay().getSlide().getResource(), this.campaignKey, this.isFullScreen);
            this.mPager = new ViewPager(getActivity());
            this.mPager.setId(10649);
            this.mPager.setAdapter(this.mAdapter);
            root.addView(this.mPager);
            if (this.promotion.getDisplay().getSlide().getResource() != null && this.promotion.getDisplay().getSlide().getResource().size() > 1) {
                this.mIndicator = new CirclePageIndicator(getActivity());
                LayoutParams mIndicatorParam = new LayoutParams(-1, -2, 80);
                this.mIndicator.setViewPager(this.mPager);
                ((CirclePageIndicator) this.mIndicator).setSnap(true);
                int adImageSectionTitleMargin = CPEConstant.convertPixelToDP(getActivity(), 4, true);
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
        }
        return root;
    }

    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
    }

    public void onSaveInstanceState(Bundle outState) {
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

    public void onDetach() {
        super.onDetach();
        try {
            if (this.usedBitmap != null && !this.isFullScreen) {
                this.usedBitmap.clear();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}