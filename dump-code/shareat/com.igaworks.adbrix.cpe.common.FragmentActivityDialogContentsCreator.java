package com.igaworks.adbrix.cpe.common;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.util.SparseArray;
import android.widget.FrameLayout;
import android.widget.LinearLayout.LayoutParams;
import com.igaworks.adbrix.cpe.activitydialog.PlaceDetailsFragment;
import com.igaworks.adbrix.model.Media;
import com.igaworks.adbrix.model.Promotion;
import com.igaworks.adbrix.util.CPEConstant;
import java.util.List;

public class FragmentActivityDialogContentsCreator extends CommonDialogContentsCreator {
    private static FragmentActivityDialogContentsCreator singleton;

    private FragmentActivityDialogContentsCreator(Context context, Activity activity, Media media, List<Integer> campaignKeys, SparseArray<Promotion> promotions, boolean isPortrait, int currentCampaignKey, int primaryCampaignKey, String spaceKey, DialogActionListener actionListener, Handler handler, boolean showIcon) {
        super(context, activity, media, campaignKeys, promotions, isPortrait, currentCampaignKey, primaryCampaignKey, spaceKey, actionListener, handler, showIcon);
    }

    public static FragmentActivityDialogContentsCreator getInstance(Context context, Activity activity, Media media, List<Integer> campaignKeys, SparseArray<Promotion> promotions, boolean isPortrait, int currentCampaignKey, int primaryCampaignKey, String spaceKey, DialogActionListener actionListener, Handler handler, boolean newInstance, boolean showIcon) {
        if (newInstance || singleton == null) {
            singleton = new FragmentActivityDialogContentsCreator(context, activity, media, campaignKeys, promotions, isPortrait, currentCampaignKey, primaryCampaignKey, spaceKey, actionListener, handler, showIcon);
        } else {
            singleton.isPortrait = isPortrait;
        }
        return singleton;
    }

    public void finishDialog() {
        try {
            if (this.adImageSectionLl != null) {
                this.adImageSectionLl.removeAllViews();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.actionListener.finishDialog();
    }

    public void setSlideImageSection() {
        LayoutParams slideAreaParam;
        try {
            this.slideArea = new FrameLayout(this.context);
            if (this.isPortrait) {
                slideAreaParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 395, true), CPEConstant.convertPixelToDP(this.context, 246, false));
            } else {
                slideAreaParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 442, true), CPEConstant.convertPixelToDP(this.context, 275, false));
            }
            this.slideArea.setId(6553);
            this.slideArea.setLayoutParams(slideAreaParam);
            this.slideArea.setBackgroundColor(-1);
            this.adImageSectionLl.addView(this.slideArea);
            this.actionListener.setSlideArea(((Promotion) this.promotions.get(this.currentCampaignKey)).getCampaignKey(), this.currentSlideNo);
            if (this.currentSlideNo > -1 && PlaceDetailsFragment.pdFragment != null && PlaceDetailsFragment.pdFragment.mPager != null) {
                this.currentSlideNo = -1;
            }
        } catch (Exception e) {
            e.printStackTrace();
            this.actionListener.finishDialog();
        }
    }

    public void changePromotionContents() {
        try {
            this.adTitleTv.setText(((Promotion) this.promotions.get(this.currentCampaignKey)).getDisplay().getTitle());
            this.actionListener.setSlideArea(((Promotion) this.promotions.get(this.currentCampaignKey)).getCampaignKey(), this.currentSlideNo);
            setRewardView();
            this.progressModel = null;
            setPlayBtnClickListener();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}