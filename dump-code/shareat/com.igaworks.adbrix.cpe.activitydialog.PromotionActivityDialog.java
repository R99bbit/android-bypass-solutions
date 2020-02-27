package com.igaworks.adbrix.cpe.activitydialog;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentTransaction;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.View;
import android.view.WindowManager;
import android.widget.LinearLayout.LayoutParams;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.cpe.CPECompletionHandler;
import com.igaworks.adbrix.cpe.common.DialogActionListener;
import com.igaworks.adbrix.cpe.common.FragmentActivityDialogContentsCreator;
import com.igaworks.adbrix.interfaces.ADBrixCallbackListener;
import com.igaworks.adbrix.interfaces.PromotionActionListener;
import com.igaworks.adbrix.model.Language;
import com.igaworks.adbrix.model.Media;
import com.igaworks.adbrix.model.Promotion;
import com.igaworks.adbrix.model.Theme;
import com.igaworks.adbrix.util.CPEConstant;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

public class PromotionActivityDialog extends FragmentActivity implements DialogActionListener {
    public static final int CAN_NOT_PARTICIPATE_RESULT_CODE = 5302;
    public static final String CLICK_ACTION_CLOSE = "no";
    public static final String CLICK_ACTION_URL = "url";
    public static final String CLOSE_BTN_URL = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/popup_close_bt.png";
    public static final int SLIDE_AREA_ID = 6553;
    public static final int THUMBNAIL_ARROW_ID = 18841;
    public static final int THUMBNAIL_IV_ID = 22937;
    public static final String TYPE_IMAGE = "image";
    public static final String TYPE_WEB = "web";
    public static boolean isActive = false;
    public static ADBrixCallbackListener onPlayBtnClickListener;
    public static PromotionActionListener promotionActionListener;
    public static PromotionActivityDialog promotionDialog;
    private List<Integer> campaignKeys;
    private LayoutParams containerParam;
    public FragmentActivityDialogContentsCreator contentsProvider;
    private int currentCampaignKey;
    private int currentSlideNo;
    private Bitmap img;
    private boolean isPortrait;
    private Media media;
    private int primaryCampaignKey;
    private SparseArray<Promotion> promotions;
    private String spaceKey;
    protected int windowPadding;

    public /* bridge */ /* synthetic */ View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        return super.onCreateView(view, str, context, attributeSet);
    }

    public /* bridge */ /* synthetic */ View onCreateView(String str, Context context, AttributeSet attributeSet) {
        return super.onCreateView(str, context, attributeSet);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
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
            if (savedInstanceState != null) {
                this.currentCampaignKey = savedInstanceState.getInt("currentCampaignKey");
                this.currentSlideNo = savedInstanceState.getInt("slideNo", -1);
            } else {
                this.primaryCampaignKey = getIntent().getIntExtra("primaryCampaignKey", 0);
            }
            this.spaceKey = getIntent().getStringExtra("spaceKey");
            this.campaignKeys = getIntent().getIntegerArrayListExtra("campaignKeys");
            if (this.campaignKeys == null || this.campaignKeys.size() < 1) {
                finish();
                return;
            }
            this.promotions = new SparseArray<>();
            for (Promotion promotion : ADBrixHttpManager.schedule.getSchedule().getPromotions()) {
                if (this.campaignKeys.contains(Integer.valueOf(promotion.getCampaignKey()))) {
                    this.promotions.put(promotion.getCampaignKey(), promotion);
                }
            }
            requestWindowFeature(1);
            this.windowPadding = CPEConstant.convertPixelToDP(this, 10, true);
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
            getWindow().setGravity(17);
            if (getResources().getConfiguration().orientation == 2) {
                this.isPortrait = false;
            } else {
                this.isPortrait = true;
            }
            IgawLogger.Logging(this, IgawConstant.QA_TAG, String.format("Promotion Dialog Open : primary campaign key = %d, current campaign key = %d, slide no = %d", new Object[]{Integer.valueOf(this.primaryCampaignKey), Integer.valueOf(this.currentCampaignKey), Integer.valueOf(this.currentSlideNo)}), 3);
            if (this.contentsProvider == null) {
                this.contentsProvider = FragmentActivityDialogContentsCreator.getInstance(this, this, this.media, this.campaignKeys, this.promotions, this.isPortrait, this.currentCampaignKey, this.primaryCampaignKey, this.spaceKey, this, new Handler(), savedInstanceState == null, true);
            }
            this.containerParam = new LayoutParams(-1, -1);
            addContentView(this.contentsProvider.getRootView(), this.containerParam);
        } catch (Exception e) {
            finish();
            e.printStackTrace();
        }
    }

    public static Bitmap getBitmapFromURL(String link) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(link).openConnection();
            connection.setDoInput(true);
            connection.connect();
            return BitmapFactory.decodeStream(connection.getInputStream());
        } catch (IOException e) {
            return null;
        }
    }

    public static void saveImageFile(String url) {
        String fileName = CPECompletionHandler.computeHashedName(url);
        Bitmap bitmap = getBitmapFromURL(url);
        File mFile1 = new File(new StringBuilder(String.valueOf(Environment.getExternalStorageDirectory().getAbsolutePath())).append("/adbrix/").toString());
        if (!mFile1.exists()) {
            mFile1.mkdirs();
        }
        File mFile2 = new File(mFile1, fileName);
        if (!mFile2.exists()) {
            try {
                FileOutputStream outStream = new FileOutputStream(mFile2);
                bitmap.compress(CompressFormat.PNG, 100, outStream);
                outStream.flush();
                outStream.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e2) {
                e2.printStackTrace();
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onSaveInstanceState(Bundle outState) {
        try {
            outState.putInt("currentCampaignKey", this.contentsProvider.getCurrentCampaignKey());
            if (!(PlaceDetailsFragment.pdFragment == null || PlaceDetailsFragment.pdFragment.mPager == null)) {
                outState.putInt("slideNo", PlaceDetailsFragment.pdFragment.mPager.getCurrentItem());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        super.onSaveInstanceState(outState);
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
        isActive = true;
        if (this.contentsProvider == null) {
            this.contentsProvider = FragmentActivityDialogContentsCreator.getInstance(this, this, this.media, this.campaignKeys, this.promotions, this.isPortrait, this.currentCampaignKey, this.primaryCampaignKey, this.spaceKey, this, new Handler(), true, true);
        } else {
            this.contentsProvider.setActionListener(this);
        }
        this.contentsProvider.onResume();
    }

    /* access modifiers changed from: protected */
    public void onPause() {
        super.onPause();
        isActive = false;
    }

    public void finishDialog() {
        if (promotionActionListener != null) {
            promotionActionListener.onHideDialog();
        }
        finish();
    }

    public void setSlideArea(int campaignKey, int currentSlideNo2) {
        FragmentTransaction ft = getSupportFragmentManager().beginTransaction();
        ft.add(6553, (Fragment) PlaceDetailsFragment.newInstance(campaignKey, currentSlideNo2, false));
        ft.setTransition(FragmentTransaction.TRANSIT_FRAGMENT_FADE);
        ft.commit();
    }

    public void onPlayBtnClick() {
        try {
            if (promotionActionListener != null) {
                promotionActionListener.onPlayButtonClick();
            }
            if (onPlayBtnClickListener != null) {
                onPlayBtnClickListener.run();
            }
        } catch (Exception e) {
        }
    }
}