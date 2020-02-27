package com.igaworks.adbrix.cpe.common;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.util.SparseArray;
import android.widget.FrameLayout;
import android.widget.LinearLayout.LayoutParams;
import com.igaworks.adbrix.cpe.activitydialog.PlaceDetailsFragment;
import com.igaworks.adbrix.cpe.dialog.PlaceDetailsLayout;
import com.igaworks.adbrix.model.Media;
import com.igaworks.adbrix.model.Promotion;
import com.igaworks.adbrix.util.CPEConstant;
import java.util.List;

public class DialogContentsCreator extends CommonDialogContentsCreator {
    private Activity activity;

    public DialogContentsCreator(Context context, Activity activity2, Media media, List<Integer> campaignKeys, SparseArray<Promotion> promotions, boolean isPortrait, int currentCampaignKey, int primaryCampaignKey, String spaceKey, DialogActionListener actionListener, Handler handler, boolean showIcon) {
        super(context, activity2, media, campaignKeys, promotions, isPortrait, currentCampaignKey, primaryCampaignKey, spaceKey, actionListener, handler, showIcon);
        this.activity = activity2;
    }

    public Activity getActivity() {
        return this.activity;
    }

    public void setActivity(Activity activity2) {
        this.activity = activity2;
    }

    public void finishDialog() {
        this.actionListener.finishDialog();
    }

    public void setSlideImageSection() {
        LayoutParams slideAreaParam;
        try {
            this.slideArea = new FrameLayout(this.activity);
            if (this.isPortrait) {
                slideAreaParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 395, true), CPEConstant.convertPixelToDP(this.context, 246, true));
            } else {
                slideAreaParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 442, true), CPEConstant.convertPixelToDP(this.context, 275, false));
            }
            this.slideArea.setId(6553);
            this.slideArea.setLayoutParams(slideAreaParam);
            this.slideArea.setBackgroundColor(-1);
            this.adImageSectionLl.addView(this.slideArea);
            this.slideArea.addView(new PlaceDetailsLayout(this.activity, ((Promotion) this.promotions.get(this.currentCampaignKey)).getCampaignKey(), this.currentSlideNo, false));
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
            this.slideArea.removeAllViews();
            this.slideArea.addView(new PlaceDetailsLayout(this.activity, ((Promotion) this.promotions.get(this.currentCampaignKey)).getCampaignKey(), this.currentSlideNo, false));
            setRewardView();
            this.progressModel = null;
            setPlayBtnClickListener();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}