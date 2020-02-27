package com.igaworks.adbrix.cpe.dialog;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.os.Handler;
import android.util.SparseArray;
import android.view.WindowManager;
import android.widget.LinearLayout.LayoutParams;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.cpe.common.DialogActionListener;
import com.igaworks.adbrix.cpe.common.DialogContentsCreator;
import com.igaworks.adbrix.interfaces.ADBrixCallbackListener;
import com.igaworks.adbrix.interfaces.PromotionActionListener;
import com.igaworks.adbrix.model.Language;
import com.igaworks.adbrix.model.Media;
import com.igaworks.adbrix.model.Promotion;
import com.igaworks.adbrix.model.Theme;
import com.igaworks.adbrix.util.CPEConstant;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import java.util.List;

public class PromotionDialog extends Dialog implements DialogActionListener {
    public static final String CLICK_ACTION_CLOSE = "no";
    public static final String CLICK_ACTION_URL = "url";
    public static final String CLOSE_BTN_URL = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/popup_close_bt.png";
    public static final String TYPE_IMAGE = "image";
    public static final String TYPE_WEB = "web";
    public static PromotionDialog promotionDialog;
    private Activity activity;
    private LayoutParams containerParam;
    private DialogContentsCreator contentsProvider;
    private int currentCampaignKey;
    private int currentSlideNo = -1;
    private boolean isPortrait;
    private Media media;
    private ADBrixCallbackListener onPlayBtnClickListener;
    private PromotionActionListener promotionActionListener;
    private SparseArray<Promotion> promotions;
    private int windowPadding;

    public PromotionDialog(Context context, int primaryCampaignKey, List<Integer> campaignKeys, String spaceKey, ADBrixCallbackListener onPlayBtnClickListener2, PromotionActionListener promotionActionListener2) {
        super(context);
        try {
            this.activity = (Activity) context;
            this.onPlayBtnClickListener = onPlayBtnClickListener2;
            this.promotionActionListener = promotionActionListener2;
            promotionDialog = this;
            this.media = ADBrixHttpManager.schedule.getSchedule().getMedia();
            if (this.media == null) {
                this.media = new Media();
            }
            if (this.media.getLanguage() == null) {
                this.media.setLanguage(new Language());
            }
            if (this.media.getTheme() == null) {
                this.media.setTheme(new Theme());
            }
            if (campaignKeys == null || campaignKeys.size() < 1) {
                dismiss();
                return;
            }
            this.promotions = new SparseArray<>();
            for (Promotion promotion : ADBrixHttpManager.schedule.getSchedule().getPromotions()) {
                if (campaignKeys.contains(Integer.valueOf(promotion.getCampaignKey()))) {
                    this.promotions.put(promotion.getCampaignKey(), promotion);
                }
            }
            requestWindowFeature(1);
            this.windowPadding = CPEConstant.convertPixelToDP(this.activity, 10, true);
            WindowManager.LayoutParams lpWindow = getWindow().getAttributes();
            lpWindow.flags = 2;
            lpWindow.dimAmount = 0.7f;
            lpWindow.width = -1;
            lpWindow.height = -1;
            lpWindow.gravity = 17;
            getWindow().setAttributes(lpWindow);
            getWindow().setSoftInputMode(16);
            getWindow().getDecorView().setBackgroundColor(0);
            getWindow().getDecorView().setPadding(0, 0, 0, 0);
            getWindow().setFormat(1);
            getWindow().addFlags(4096);
            getWindow().setFlags(1024, 1024);
            getWindow().setGravity(17);
            if (this.activity.getResources().getConfiguration().orientation == 2) {
                this.isPortrait = false;
            } else {
                this.isPortrait = true;
            }
            IgawLogger.Logging(this.activity, IgawConstant.QA_TAG, String.format("Promotion Dialog Open : primary campaign key = %d, current campaign key = %d, slide no = %d", new Object[]{Integer.valueOf(primaryCampaignKey), Integer.valueOf(this.currentCampaignKey), Integer.valueOf(this.currentSlideNo)}), 3);
            this.contentsProvider = new DialogContentsCreator(getContext(), this.activity, this.media, campaignKeys, this.promotions, this.isPortrait, this.currentCampaignKey, primaryCampaignKey, spaceKey, this, new Handler(), true);
            this.containerParam = new LayoutParams(-1, -1);
            addContentView(this.contentsProvider.getRootView(), this.containerParam);
        } catch (Exception e) {
            dismiss();
            e.printStackTrace();
        }
    }

    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        try {
            if (this.contentsProvider != null) {
                this.contentsProvider.onResume();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void onBackPressed() {
        finishDialog();
    }

    public void finishDialog() {
        if (this.promotionActionListener != null) {
            this.promotionActionListener.onHideDialog();
        }
        dismiss();
    }

    public void setSlideArea(int campaignKey, int currentSlideNo2) {
    }

    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (hasFocus) {
            try {
                if (this.contentsProvider != null) {
                    this.contentsProvider.onResume();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void onPlayBtnClick() {
        try {
            if (this.promotionActionListener != null) {
                this.promotionActionListener.onPlayButtonClick();
            }
            if (this.onPlayBtnClickListener != null) {
                this.onPlayBtnClickListener.run();
            }
        } catch (Exception e) {
        }
    }
}