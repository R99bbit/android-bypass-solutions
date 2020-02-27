package com.igaworks.adbrix.cpe.common;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.ColorMatrix;
import android.graphics.ColorMatrixColorFilter;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.shapes.RectShape;
import android.graphics.drawable.shapes.RoundRectShape;
import android.graphics.drawable.shapes.Shape;
import android.net.Uri;
import android.os.Handler;
import android.support.v4.view.ViewCompat;
import android.util.Pair;
import android.util.SparseArray;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.AbsListView;
import android.widget.ArrayAdapter;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.cpe.CPECompletionHandler;
import com.igaworks.adbrix.interfaces.ParticipationProgressCallbackListener;
import com.igaworks.adbrix.model.Media;
import com.igaworks.adbrix.model.Promotion;
import com.igaworks.adbrix.model.StepRewardModel;
import com.igaworks.adbrix.util.CPEConstant;
import com.igaworks.adbrix.util.DialogUtil;
import com.igaworks.commerce.db.DemographicDAO;
import com.igaworks.core.DeviceIDManger;
import com.igaworks.core.DisplaySetter;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.cpe.ConditionChecker;
import com.igaworks.dao.CPEImpressionDAOFactory;
import com.igaworks.dao.CoreIDDAO;
import com.igaworks.dao.NotAvailableCampaignDAO;
import com.igaworks.dao.tracking.TrackingActivitySQLiteDB;
import com.igaworks.impl.InternalAction;
import com.igaworks.model.ParticipationProgressModel;
import com.igaworks.model.ParticipationProgressResponseModel;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.image.ImageCacheFactory;
import com.igaworks.util.image.ImageDownloadAsyncCallback;
import io.fabric.sdk.android.services.settings.SettingsJsonConstants;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

public abstract class CommonDialogContentsCreator implements ParticipationProgressCallbackListener {
    public static final int CAN_NOT_PARTICIPATE_RESULT_CODE = 5302;
    public static final String CLICK_ACTION_CLOSE = "no";
    public static final String CLICK_ACTION_URL = "url";
    public static final String CLOSE_BTN_URL = "http://static.adbrix.igaworks.com/adbrix_res/sdk_res/popup_close_bt.png";
    private static final int HIGH_DPI_STATUS_BAR_HEIGHT = 38;
    private static final int LOW_DPI_STATUS_BAR_HEIGHT = 19;
    private static final int MEDIUM_DPI_STATUS_BAR_HEIGHT = 25;
    public static final int ON_PARTICIPATION_IN_ANOTHER_APP = 5303;
    public static final int SLIDE_AREA_ID = 6553;
    public static final int THUMBNAIL_ARROW_ID = 18841;
    public static final int THUMBNAIL_IV_ID = 22937;
    public static final int THUMBNAIL_LL_ID = 22936;
    public static final String TYPE_IMAGE = "image";
    public static final String TYPE_WEB = "web";
    protected DialogActionListener actionListener;
    protected Activity activity;
    protected LinearLayout adImageSectionLl;
    protected int adImageSectionPadding;
    protected int adImageSectionTitleMargin;
    protected TextView adTitleTv;
    protected List<Integer> campaignKeys;
    protected SparseArray<LinearLayout> campaignThumbnails;
    protected ImageView closeBtnIv;
    private FrameLayout containerLayout;
    protected LinearLayout contentsMainLl;
    protected int contentsMainMargin;
    protected Context context;
    protected int currentCampaignKey;
    protected int currentSlideNo = -1;
    protected int dialogMainPadding;
    protected int dialogRound;
    protected int dividerSize;
    protected Handler handler;
    protected List<Integer> impressionAddedCampaign;
    protected TextView isCompleteTitleTv;
    protected boolean isPortrait;
    private OnClickListener landingBtnClickLisetner = new OnClickListener() {
        public void onClick(View v) {
            String landingUrlStr;
            try {
                if (ConditionChecker.checkInstalled(CommonDialogContentsCreator.this.context, CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getTargetAppScheme())) {
                    CommonDialogContentsCreator.this.context.startActivity(CommonDialogContentsCreator.this.context.getPackageManager().getLaunchIntentForPackage(CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getTargetAppScheme()));
                } else {
                    RequestParameter parameter = RequestParameter.getATRequestParameter(CommonDialogContentsCreator.this.context);
                    String google_ad_id = CoreIDDAO.getInstance().getGoogleAdId(CommonDialogContentsCreator.this.context);
                    List<Pair<String, String>> demoList = parameter.getPersistantDemoInfo_v2();
                    String landingUrlStr2 = CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getDisplay().getClickUrl();
                    String queryStr = Uri.parse(landingUrlStr2).getQuery();
                    if (demoList != null) {
                        String usn = null;
                        Iterator<Pair<String, String>> it = demoList.iterator();
                        while (true) {
                            if (it.hasNext()) {
                                Pair<String, String> item = it.next();
                                if (((String) item.first).equals(DemographicDAO.KEY_USN)) {
                                    usn = (String) item.second;
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        if (usn == null) {
                            usn = "";
                        }
                        if (queryStr == null || queryStr.length() <= 0) {
                            landingUrlStr = new StringBuilder(String.valueOf(landingUrlStr2)).append("?usn=").append(Uri.encode(usn)).toString();
                        } else {
                            landingUrlStr = new StringBuilder(String.valueOf(landingUrlStr2)).append("&usn=").append(Uri.encode(usn)).toString();
                        }
                    } else if (queryStr == null || queryStr.length() <= 0) {
                        landingUrlStr = new StringBuilder(String.valueOf(landingUrlStr2)).append("?usn=").toString();
                    } else {
                        landingUrlStr = new StringBuilder(String.valueOf(landingUrlStr2)).append("&usn=").toString();
                    }
                    String landingUrlStr3 = new StringBuilder(String.valueOf(landingUrlStr)).append("&agreement_key=").append(google_ad_id).append("&src_appkey=").append(parameter.getAppkey()).append("&r_key=").append(CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getDisplay().getSlide().getResourceKey()).toString();
                    IgawLogger.Logging(CommonDialogContentsCreator.this.context, IgawConstant.QA_TAG, "Adbrix > promotion landing url : " + landingUrlStr3, 3);
                    if (CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getDisplay().isIsMarketUrl()) {
                        CommonDialogContentsCreator.this.webview = new WebView(CommonDialogContentsCreator.this.context);
                        CommonDialogContentsCreator.this.webviewParam = new LayoutParams(-2, -2);
                        CommonDialogContentsCreator.this.webview.setVerticalScrollBarEnabled(false);
                        CommonDialogContentsCreator.this.webview.setHorizontalScrollBarEnabled(false);
                        CommonDialogContentsCreator.this.webview.setBackgroundColor(-1);
                        CommonDialogContentsCreator.this.webview.setWebViewClient(new IgawPromotionWebViewClient(CommonDialogContentsCreator.this, null));
                        CommonDialogContentsCreator.this.webview.loadUrl(landingUrlStr3);
                    } else {
                        CommonDialogContentsCreator.this.context.startActivity(new Intent("android.intent.action.VIEW", Uri.parse(landingUrlStr3)));
                    }
                }
                IgawLogger.Logging(CommonDialogContentsCreator.this.context, IgawConstant.QA_TAG, "Adbrix > actionListener is null : " + (CommonDialogContentsCreator.this.actionListener == null), 3);
                if (CommonDialogContentsCreator.this.actionListener != null) {
                    CommonDialogContentsCreator.this.actionListener.onPlayBtnClick();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    };
    protected Media media;
    protected TextView missionTitleTv;
    protected TextView notAvailableTv;
    private OnClickListener onFailBtnClickListener = new OnClickListener() {
        public void onClick(View v) {
            Toast.makeText(CommonDialogContentsCreator.this.context, "\ucc38\uc5ec \uc815\ubcf4\ub97c \uac00\uc838\uc624\uc9c0 \ubabb\ud588\uc2b5\ub2c8\ub2e4. \uc7a0\uc2dc \ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.", 0).show();
        }
    };
    protected boolean onGetProgressModel = false;
    private OnClickListener onReadyBtnClickListener = new OnClickListener() {
        public void onClick(View v) {
            Toast.makeText(CommonDialogContentsCreator.this.context, "\ucc38\uc5ec \uc815\ubcf4\ub97c \uac00\uc838\uc624\ub294 \uc911\uc785\ub2c8\ub2e4.", 0).show();
        }
    };
    protected ImageView playBtnIv;
    protected LinearLayout playBtnLl;
    protected int primaryCampaignKey;
    protected FrameLayout progressCircle;
    protected ParticipationProgressResponseModel progressModel;
    protected SparseArray<ParticipationProgressResponseModel> progressModels;
    protected SparseArray<Promotion> promotions;
    protected List<Integer> rCks;
    protected ImageView rewardIv;
    protected ShapeDrawable roundedActiveThumbSd;
    protected ShapeDrawable roundedInactiveThumbSd;
    protected Shape roundedThumbShape;
    protected boolean showIcon;
    protected FrameLayout slideArea;
    protected String spaceKey;
    protected int statusBarHeight;
    protected int stepListColumnMargin;
    protected LinearLayout stepListLl;
    protected FrameLayout stepLoadingFl;
    protected LinearLayout stepRewardContainer;
    protected int stepRewardWidth;
    protected int thumbBorderWidth;
    protected int thumbnailArrowSize;
    protected int thumbnailItemMargin;
    protected int thumbnailItemSize;
    protected int thumbnailListPadding;
    protected HorizontalScrollView thumbnailListSv;
    protected LinearLayout webViewParent;
    protected WebView webview;
    protected LayoutParams webviewParam;
    protected int windowPadding;

    private class IgawPromotionWebViewClient extends WebViewClient {
        private IgawPromotionWebViewClient() {
        }

        /* synthetic */ IgawPromotionWebViewClient(CommonDialogContentsCreator commonDialogContentsCreator, IgawPromotionWebViewClient igawPromotionWebViewClient) {
            this();
        }

        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            IgawLogger.Logging(CommonDialogContentsCreator.this.context, IgawConstant.QA_TAG, String.format("IgawPromotionWebViewClient >> shouldOverrideUrlLoading : %s", new Object[]{url}), 2, false);
            if (url.startsWith("http")) {
                return true;
            }
            CommonDialogContentsCreator.this.context.startActivity(new Intent("android.intent.action.VIEW", Uri.parse(url)));
            return false;
        }
    }

    private class StepRewardListAdapter extends ArrayAdapter<StepRewardModel> {
        public static final String EVEN_BG_COLOR = "#242d3e";
        public static final int MISSION_TV_ID = 14745;
        public static final String ODD_BG_COLOR = "#20293b";
        public int checkIvSize;
        /* access modifiers changed from: private */
        public Context context;
        public int rowHeight;

        public StepRewardListAdapter(Context context2, int textViewResourceId) {
            super(context2, textViewResourceId);
            this.context = context2;
            this.rowHeight = CPEConstant.convertPixelToDP(context2, 39, false);
            this.checkIvSize = CPEConstant.convertPixelToDP(context2, 30, false);
        }

        public int getCount() {
            return CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getDisplay().getStepReward().size();
        }

        public View getView(int position, View convertView, ViewGroup parent) {
            LinearLayout linearLayout = new LinearLayout(this.context);
            try {
                linearLayout.setLayoutParams(new AbsListView.LayoutParams(-1, -2));
                linearLayout.setOrientation(1);
                linearLayout.setBackgroundColor(Color.parseColor(position % 2 == 0 ? EVEN_BG_COLOR : ODD_BG_COLOR));
                LinearLayout contentsLl = new LinearLayout(this.context);
                LayoutParams contentsLlParam = new LayoutParams(-1, this.rowHeight);
                contentsLl.setGravity(17);
                int padding = CPEConstant.convertPixelToDP(this.context, 5, true);
                contentsLl.setPadding(0, padding, 0, padding);
                contentsLl.setLayoutParams(contentsLlParam);
                contentsLl.setOrientation(0);
                TextView missionTv = new TextView(this.context);
                LayoutParams layoutParams = new LayoutParams(CommonDialogContentsCreator.this.missionTitleTv.getWidth(), -2);
                missionTv.setId(MISSION_TV_ID);
                missionTv.setLayoutParams(layoutParams);
                missionTv.setGravity(17);
                missionTv.setText(CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getDisplay().getStepReward().get(position).getName());
                missionTv.setTextColor(Color.parseColor("#657084"));
                missionTv.setTypeface(null, 1);
                CPEConstant.setTextViewSize(this.context, missionTv, 15);
                TextView textView = new TextView(this.context);
                LayoutParams layoutParams2 = new LayoutParams(CommonDialogContentsCreator.this.rewardIv.getWidth(), -2);
                textView.setLayoutParams(layoutParams2);
                textView.setGravity(17);
                textView.setText(new StringBuilder(String.valueOf(CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getDisplay().getStepReward().get(position).getReward())).toString());
                textView.setTextColor(Color.parseColor("#657084"));
                textView.setTypeface(null, 1);
                CPEConstant.setTextViewSize(this.context, textView, 15);
                final ImageView checkIv = new ImageView(this.context);
                checkIv.setLayoutParams(new LayoutParams(CommonDialogContentsCreator.this.isCompleteTitleTv.getWidth(), -1));
                checkIv.setScaleType(ScaleType.FIT_CENTER);
                String checkUrl = CommonDialogContentsCreator.this.media.getTheme().getMissionCheckOff();
                if (CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getDisplay().getStepReward().get(position).isComplete()) {
                    checkUrl = CommonDialogContentsCreator.this.media.getTheme().getMissionCheckOn();
                    missionTv.setTextColor(Color.parseColor("#ffffff"));
                    textView.setTextColor(Color.parseColor("#ffffff"));
                }
                if (CommonHelper.CheckPermissionForCommonSDK(this.context)) {
                    final ImageView imageView = checkIv;
                    CPECompletionHandler.getImageDownloader(this.context).download(checkUrl, checkIv, null, null, new ImageDownloadAsyncCallback(checkUrl, checkIv, ImageCacheFactory.getInstance().get("imagecache"), null) {
                        public void onResultCustom(Bitmap bitmap) {
                            imageView.setImageBitmap(bitmap);
                        }
                    });
                } else {
                    final String _checkUrl = checkUrl;
                    InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                        public void run() {
                            final Bitmap bitmap = CommonHelper.getBitmapFromURL(_checkUrl);
                            Handler handler = new Handler(StepRewardListAdapter.this.context.getMainLooper());
                            final ImageView imageView = checkIv;
                            handler.post(new Runnable() {
                                public void run() {
                                    try {
                                        imageView.setImageBitmap(bitmap);
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                }
                            });
                        }
                    });
                }
                contentsLl.addView(missionTv);
                contentsLl.addView(textView);
                contentsLl.addView(checkIv);
                linearLayout.addView(contentsLl);
                linearLayout.addView(CommonDialogContentsCreator.this.getDividerView(1));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return linearLayout;
        }
    }

    public abstract void changePromotionContents();

    public abstract void finishDialog();

    public abstract void setSlideImageSection();

    public int getCurrentCampaignKey() {
        return this.currentCampaignKey;
    }

    public void setCurrentCampaignKey(int currentCampaignKey2) {
        this.currentCampaignKey = currentCampaignKey2;
    }

    protected CommonDialogContentsCreator(Context context2, Activity activity2, Media media2, List<Integer> campaignKeys2, SparseArray<Promotion> promotions2, boolean isPortrait2, int currentCampaignKey2, int primaryCampaignKey2, String spaceKey2, DialogActionListener actionListener2, Handler handler2, boolean showIcon2) {
        this.spaceKey = spaceKey2;
        this.media = media2;
        this.context = context2;
        this.activity = activity2;
        this.campaignKeys = campaignKeys2;
        this.promotions = promotions2;
        this.impressionAddedCampaign = new ArrayList();
        this.isPortrait = isPortrait2;
        this.currentCampaignKey = currentCampaignKey2;
        this.primaryCampaignKey = primaryCampaignKey2;
        this.handler = handler2;
        this.actionListener = actionListener2;
        this.showIcon = showIcon2;
        this.windowPadding = CPEConstant.convertPixelToDP(context2, 10, true);
        this.dialogRound = CPEConstant.convertPixelToDP(context2, 13, true);
        this.thumbBorderWidth = CPEConstant.convertPixelToDP(context2, 4, true);
        this.roundedThumbShape = new RoundRectShape(new float[]{(float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound}, null, null);
        this.roundedActiveThumbSd = new CustomShapeDrawable(this.roundedThumbShape, Color.parseColor("#dc1f38"), Color.parseColor("#dc1f38"), this.thumbBorderWidth);
        this.roundedInactiveThumbSd = new CustomShapeDrawable(this.roundedThumbShape, Color.parseColor("#d1d1d1"), Color.parseColor("#d1d1d1"), this.thumbBorderWidth, true);
        this.contentsMainMargin = CPEConstant.convertPixelToDP(context2, 10, true);
        this.dialogMainPadding = CPEConstant.convertPixelToDP(context2, 10, true);
        this.adImageSectionPadding = CPEConstant.convertPixelToDP(context2, 4, true);
        this.adImageSectionTitleMargin = CPEConstant.convertPixelToDP(context2, 4, true);
        this.thumbnailItemSize = CPEConstant.convertPixelToDP(context2, 70, true);
        this.thumbnailItemMargin = CPEConstant.convertPixelToDP(context2, 6, true);
        this.thumbnailListPadding = CPEConstant.convertPixelToDP(context2, 10, true);
        this.stepRewardWidth = (int) (((double) Math.min(DisplaySetter.getDisplayXY(activity2).heightPixels, DisplaySetter.getDisplayXY(activity2).widthPixels)) * 0.45d);
        this.thumbnailArrowSize = CPEConstant.convertPixelToDP(context2, 8, true);
        this.dividerSize = CPEConstant.convertPixelToDP(context2, 1, true);
        if (primaryCampaignKey2 > 0) {
            this.currentCampaignKey = primaryCampaignKey2;
        }
    }

    public void setIsPortrait(boolean isPortrait2) {
        this.isPortrait = isPortrait2;
    }

    public View getRootView() {
        this.containerLayout = new FrameLayout(this.context);
        try {
            if (this.isPortrait) {
                this.containerLayout.addView(getContainerOnPortrait());
            } else {
                this.containerLayout.addView(getContainerOnLandscape());
            }
            setCurrentCampaign(this.currentCampaignKey > 0 ? this.currentCampaignKey : this.campaignKeys.get(0).intValue());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return this.containerLayout;
    }

    public View getContainerOnLandscape() {
        RoundRectShape roundRectShape = new RoundRectShape(new float[]{(float) this.dialogRound, (float) this.dialogRound, 0.0f, 0.0f, 0.0f, 0.0f, (float) this.dialogRound, (float) this.dialogRound}, null, null);
        CustomShapeDrawable customShapeDrawable = new CustomShapeDrawable(roundRectShape, -1, ViewCompat.MEASURED_STATE_MASK, CPEConstant.convertPixelToDP(this.context, 1, true));
        FrameLayout contentsContainerFl = new FrameLayout(this.context);
        FrameLayout.LayoutParams contentsContainerFlParam = new FrameLayout.LayoutParams(CPEConstant.convertPixelToDP(this.context, 680, true), CPEConstant.convertPixelToDP(this.context, 438, true), 17);
        contentsContainerFl.setLayoutParams(contentsContainerFlParam);
        LinearLayout contentsContainerLl = new LinearLayout(this.context);
        FrameLayout.LayoutParams contentsContainerLlParam = new FrameLayout.LayoutParams(CPEConstant.convertPixelToDP(this.context, 655, true), CPEConstant.convertPixelToDP(this.context, 412, true), 17);
        contentsContainerLl.setLayoutParams(contentsContainerLlParam);
        this.contentsMainLl = new LinearLayout(this.context);
        LayoutParams layoutParams = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 655, true), -1);
        this.contentsMainLl.setLayoutParams(layoutParams);
        this.contentsMainLl.setOrientation(0);
        this.contentsMainLl.setGravity(17);
        LinearLayout linearLayout = new LinearLayout(this.context);
        LayoutParams layoutParams2 = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 462, true), -1);
        linearLayout.setOrientation(1);
        linearLayout.setLayoutParams(layoutParams2);
        linearLayout.setBackgroundDrawable(customShapeDrawable);
        this.adImageSectionLl = new LinearLayout(this.context);
        this.adImageSectionLl.setLayoutParams(new LayoutParams(-1, 0, 1.0f));
        this.adImageSectionLl.setOrientation(1);
        this.adImageSectionLl.setBackgroundColor(0);
        this.adImageSectionLl.setPadding(this.dialogMainPadding, this.dialogMainPadding + this.adImageSectionPadding, this.dialogMainPadding, 0);
        setTitleAndAdSlideView();
        linearLayout.addView(this.adImageSectionLl);
        this.thumbnailListSv = new HorizontalScrollView(this.context);
        this.thumbnailListSv.setHorizontalScrollBarEnabled(false);
        this.thumbnailListSv.setFillViewport(true);
        this.thumbnailListSv.setPadding(this.thumbnailListPadding, this.thumbnailListPadding / 4, this.thumbnailListPadding, this.thumbnailListPadding);
        LayoutParams layoutParams3 = new LayoutParams(-1, -2);
        this.thumbnailListSv.setLayoutParams(layoutParams3);
        int stepRewardPadding = CPEConstant.convertPixelToDP(this.context, 38, true);
        int rightWidth = CPEConstant.convertPixelToDP(this.context, 193, true);
        if (!this.showIcon || this.campaignKeys.size() <= 1) {
            contentsContainerFlParam.height = ((CPEConstant.convertPixelToDP(this.context, 438, true) - this.thumbnailItemSize) - this.thumbnailArrowSize) - (this.thumbnailListPadding / 4);
            contentsContainerLlParam.height = ((CPEConstant.convertPixelToDP(this.context, 412, true) - this.thumbnailItemSize) - this.thumbnailArrowSize) - (this.thumbnailListPadding / 4);
        } else {
            setCampaignThumbnailListView();
        }
        linearLayout.addView(this.thumbnailListSv);
        this.stepLoadingFl = new FrameLayout(this.context);
        LayoutParams layoutParams4 = new LayoutParams(rightWidth, -1);
        this.stepLoadingFl.setLayoutParams(layoutParams4);
        if (CommonHelper.CheckPermissionForCommonSDK(this.activity)) {
            CPECompletionHandler.getImageDownloader(this.context).download(this.media.getTheme().getPlayBtnAreaBG(), null, null, null, new ImageDownloadAsyncCallback(this.media.getTheme().getPlayBtnAreaBG(), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                public void onResultCustom(Bitmap bitmap) {
                    try {
                        int width = bitmap.getWidth();
                        int height = bitmap.getHeight();
                        int desiredLength = CPEConstant.convertPixelToDP(CommonDialogContentsCreator.this.context, 25, true);
                        while (height < desiredLength) {
                            bitmap = Bitmap.createScaledBitmap(bitmap, (width * desiredLength) / height, desiredLength, true);
                            width = bitmap.getWidth();
                            height = bitmap.getHeight();
                        }
                        CommonDialogContentsCreator.this.stepLoadingFl.setBackgroundDrawable(new RoundedRepeatShapDrawable(new RoundRectShape(new float[]{0.0f, 0.0f, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, 0.0f, 0.0f}, null, null), -1, ViewCompat.MEASURED_STATE_MASK, 0, bitmap));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
        } else {
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    final Bitmap bitmap = CommonHelper.getBitmapFromURL(CommonDialogContentsCreator.this.media.getTheme().getPlayBtnAreaBG());
                    new Handler(CommonDialogContentsCreator.this.context.getMainLooper()).post(new Runnable() {
                        public void run() {
                            try {
                                Bitmap bitmap_new = bitmap;
                                int width = bitmap.getWidth();
                                int height = bitmap.getHeight();
                                int desiredLength = CPEConstant.convertPixelToDP(CommonDialogContentsCreator.this.context, 25, true);
                                while (height < desiredLength) {
                                    bitmap_new = Bitmap.createScaledBitmap(bitmap, (width * desiredLength) / height, desiredLength, true);
                                    width = bitmap_new.getWidth();
                                    height = bitmap_new.getHeight();
                                }
                                CommonDialogContentsCreator.this.stepLoadingFl.setBackgroundDrawable(new RoundedRepeatShapDrawable(new RoundRectShape(new float[]{0.0f, 0.0f, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, 0.0f, 0.0f}, null, null), -1, ViewCompat.MEASURED_STATE_MASK, 0, bitmap_new));
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        this.notAvailableTv = new TextView(this.context);
        FrameLayout.LayoutParams layoutParams5 = new FrameLayout.LayoutParams(rightWidth, -2, 17);
        this.notAvailableTv.setLayoutParams(layoutParams5);
        this.notAvailableTv.setTextColor(-1);
        this.notAvailableTv.setGravity(17);
        this.notAvailableTv.setTextSize(2, 13.0f);
        this.stepRewardContainer = new LinearLayout(this.context);
        LayoutParams layoutParams6 = new LayoutParams(rightWidth, -1);
        this.stepRewardContainer.setOrientation(1);
        this.stepRewardContainer.setLayoutParams(layoutParams6);
        this.stepRewardContainer.setPadding(0, stepRewardPadding, 0, 0);
        setRewardView();
        this.stepLoadingFl.addView(this.notAvailableTv);
        this.stepLoadingFl.addView(this.stepRewardContainer);
        this.contentsMainLl.addView(linearLayout);
        this.contentsMainLl.addView(this.stepLoadingFl);
        this.closeBtnIv = new ImageView(this.context);
        int closeBtnSize = CPEConstant.convertPixelToDP(this.context, 40, true);
        this.closeBtnIv.setLayoutParams(new FrameLayout.LayoutParams(closeBtnSize, closeBtnSize, 5));
        if (CommonHelper.CheckPermissionForCommonSDK(this.activity)) {
            CPECompletionHandler.getImageDownloader(this.context).download(this.media.getTheme().getCloseBtn(), null, null, this.progressCircle, new ImageDownloadAsyncCallback(this.media.getTheme().getCloseBtn(), null, ImageCacheFactory.getInstance().get("imagecache"), this.progressCircle) {
                public void onResultCustom(Bitmap bitmap) {
                    try {
                        CommonDialogContentsCreator.this.closeBtnIv.setImageBitmap(bitmap);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
        } else {
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    final Bitmap bm = CommonHelper.getBitmapFromURL(CommonDialogContentsCreator.this.media.getTheme().getCloseBtn());
                    new Handler(CommonDialogContentsCreator.this.context.getMainLooper()).post(new Runnable() {
                        public void run() {
                            try {
                                CommonDialogContentsCreator.this.closeBtnIv.setImageBitmap(bm);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        this.closeBtnIv.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                CommonDialogContentsCreator.this.finishDialog();
            }
        });
        contentsContainerLl.addView(this.contentsMainLl);
        contentsContainerFl.addView(contentsContainerLl);
        contentsContainerFl.addView(this.closeBtnIv);
        return contentsContainerFl;
    }

    public View getContainerOnPortrait() {
        RoundRectShape roundRectShape = new RoundRectShape(new float[]{(float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound, 0.0f, 0.0f, 0.0f, 0.0f}, null, null);
        CustomShapeDrawable customShapeDrawable = new CustomShapeDrawable(roundRectShape, -1, ViewCompat.MEASURED_STATE_MASK, CPEConstant.convertPixelToDP(this.context, 1, false));
        FrameLayout contentsContainerFl = new FrameLayout(this.context);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(CPEConstant.convertPixelToDP(this.context, 445, true), CPEConstant.convertPixelToDP(this.context, SettingsJsonConstants.ANALYTICS_FLUSH_INTERVAL_SECS_DEFAULT, false), 17);
        contentsContainerFl.setLayoutParams(layoutParams);
        LinearLayout contentsContainerLl = new LinearLayout(this.context);
        FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(CPEConstant.convertPixelToDP(this.context, 415, true), CPEConstant.convertPixelToDP(this.context, 572, false), 17);
        contentsContainerLl.setLayoutParams(layoutParams2);
        this.contentsMainLl = new LinearLayout(this.context);
        LayoutParams layoutParams3 = new LayoutParams(-1, -2);
        this.contentsMainLl.setLayoutParams(layoutParams3);
        this.contentsMainLl.setOrientation(1);
        this.adImageSectionLl = new LinearLayout(this.context);
        this.adImageSectionLl.setLayoutParams(new LayoutParams(-1, -2));
        this.adImageSectionLl.setOrientation(1);
        this.adImageSectionLl.setBackgroundDrawable(customShapeDrawable);
        this.adImageSectionLl.setPadding(this.dialogMainPadding, this.dialogMainPadding, this.dialogMainPadding, this.dialogMainPadding);
        setTitleAndAdSlideView();
        this.contentsMainLl.addView(this.adImageSectionLl);
        this.stepLoadingFl = new FrameLayout(this.context);
        LayoutParams layoutParams4 = new LayoutParams(-1, CPEConstant.convertPixelToDP(this.context, CPEConstant.DIALOG_REWARD_HEIGHT_PORTRAIT, false));
        this.stepLoadingFl.setLayoutParams(layoutParams4);
        this.notAvailableTv = new TextView(this.context);
        FrameLayout.LayoutParams layoutParams5 = new FrameLayout.LayoutParams(-2, -2, 17);
        this.notAvailableTv.setLayoutParams(layoutParams5);
        this.notAvailableTv.setTextColor(-1);
        this.notAvailableTv.setTextSize(2, 13.0f);
        this.stepRewardContainer = new LinearLayout(this.context);
        LayoutParams layoutParams6 = new LayoutParams(-1, -1);
        this.stepRewardContainer.setOrientation(0);
        this.stepRewardContainer.setLayoutParams(layoutParams6);
        List<StepRewardModel> rewardList = this.promotions.get(this.currentCampaignKey).getDisplay().getStepReward();
        setRewardView();
        this.stepLoadingFl.addView(this.notAvailableTv);
        this.stepLoadingFl.addView(this.stepRewardContainer);
        this.contentsMainLl.addView(this.stepLoadingFl);
        LinearLayout linearLayout = new LinearLayout(this.context);
        LayoutParams layoutParams7 = new LayoutParams(-1, -2);
        linearLayout.setLayoutParams(layoutParams7);
        linearLayout.setOrientation(0);
        LinearLayout linearLayout2 = linearLayout;
        linearLayout2.setPadding(this.thumbnailListPadding, this.thumbnailListPadding / 2, this.thumbnailListPadding, this.thumbnailListPadding);
        this.thumbnailListSv = new HorizontalScrollView(this.context);
        LayoutParams layoutParams8 = new LayoutParams(-1, -1);
        this.thumbnailListSv.setHorizontalScrollBarEnabled(false);
        this.thumbnailListSv.setLayoutParams(layoutParams8);
        if (!this.showIcon || this.campaignKeys.size() <= 1) {
            if (rewardList.size() > 1) {
                layoutParams4.height += this.dialogRound;
            }
            if (CommonHelper.CheckPermissionForCommonSDK(this.activity)) {
                CPECompletionHandler.getImageDownloader(this.context).download(this.media.getTheme().getPlayBtnAreaBG(), null, null, null, new ImageDownloadAsyncCallback(this.media.getTheme().getPlayBtnAreaBG(), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                    public void onResultCustom(Bitmap bitmap) {
                        try {
                            int width = bitmap.getWidth();
                            int height = bitmap.getHeight();
                            int desiredLength = CPEConstant.convertPixelToDP(CommonDialogContentsCreator.this.context, 25, true);
                            while (height < desiredLength) {
                                bitmap = Bitmap.createScaledBitmap(bitmap, (width * desiredLength) / height, desiredLength, true);
                                width = bitmap.getWidth();
                                height = bitmap.getHeight();
                            }
                            CommonDialogContentsCreator.this.stepLoadingFl.setBackgroundDrawable(new RoundedRepeatShapDrawable(new RoundRectShape(new float[]{0.0f, 0.0f, 0.0f, 0.0f, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound}, null, null), -1, 0, 0, bitmap));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
            } else {
                InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                    public void run() {
                        final Bitmap bitmap = CommonHelper.getBitmapFromURL(CommonDialogContentsCreator.this.media.getTheme().getPlayBtnAreaBG());
                        new Handler(CommonDialogContentsCreator.this.context.getMainLooper()).post(new Runnable() {
                            public void run() {
                                try {
                                    Bitmap bitmap_new = bitmap;
                                    int width = bitmap.getWidth();
                                    int height = bitmap.getHeight();
                                    int desiredLength = CPEConstant.convertPixelToDP(CommonDialogContentsCreator.this.context, 25, true);
                                    while (height < desiredLength) {
                                        bitmap_new = Bitmap.createScaledBitmap(bitmap, (width * desiredLength) / height, desiredLength, true);
                                        width = bitmap_new.getWidth();
                                        height = bitmap_new.getHeight();
                                    }
                                    CommonDialogContentsCreator.this.stepLoadingFl.setBackgroundDrawable(new RoundedRepeatShapDrawable(new RoundRectShape(new float[]{0.0f, 0.0f, 0.0f, 0.0f, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound, (float) CommonDialogContentsCreator.this.dialogRound}, null, null), -1, 0, 0, bitmap_new));
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                    }
                });
            }
            layoutParams.height = ((CPEConstant.convertPixelToDP(this.context, SettingsJsonConstants.ANALYTICS_FLUSH_INTERVAL_SECS_DEFAULT, true) - this.thumbnailItemSize) - this.thumbnailArrowSize) - (this.thumbnailListPadding / 2);
            layoutParams2.height = ((CPEConstant.convertPixelToDP(this.context, 572, true) - this.thumbnailItemSize) - this.thumbnailArrowSize) - (this.thumbnailListPadding / 2);
        } else {
            if (CommonHelper.CheckPermissionForCommonSDK(this.activity)) {
                CPECompletionHandler.getImageDownloader(this.context).download(this.media.getTheme().getPlayBtnAreaBG(), null, null, null, new ImageDownloadAsyncCallback(this.media.getTheme().getPlayBtnAreaBG(), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                    public void onResultCustom(Bitmap bitmap) {
                        try {
                            int width = bitmap.getWidth();
                            int height = bitmap.getHeight();
                            int desiredLength = CPEConstant.convertPixelToDP(CommonDialogContentsCreator.this.context, 25, true);
                            while (height < desiredLength) {
                                bitmap = Bitmap.createScaledBitmap(bitmap, (width * desiredLength) / height, desiredLength, true);
                                width = bitmap.getWidth();
                                height = bitmap.getHeight();
                            }
                            CommonDialogContentsCreator.this.stepLoadingFl.setBackgroundDrawable(new RoundedRepeatShapDrawable(new RectShape(), -1, 0, 0, bitmap));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
            } else {
                InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                    public void run() {
                        final Bitmap bitmap = CommonHelper.getBitmapFromURL(CommonDialogContentsCreator.this.media.getTheme().getPlayBtnAreaBG());
                        new Handler(CommonDialogContentsCreator.this.context.getMainLooper()).post(new Runnable() {
                            public void run() {
                                try {
                                    Bitmap bitmap_new = bitmap;
                                    int width = bitmap.getWidth();
                                    int height = bitmap.getHeight();
                                    int desiredLength = CPEConstant.convertPixelToDP(CommonDialogContentsCreator.this.context, 25, true);
                                    while (height < desiredLength) {
                                        bitmap_new = Bitmap.createScaledBitmap(bitmap, (width * desiredLength) / height, desiredLength, true);
                                        width = bitmap_new.getWidth();
                                        height = bitmap_new.getHeight();
                                    }
                                    CommonDialogContentsCreator.this.stepLoadingFl.setBackgroundDrawable(new RoundedRepeatShapDrawable(new RectShape(), -1, 0, 0, bitmap_new));
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                    }
                });
            }
            LinearLayout linearLayout3 = linearLayout;
            linearLayout3.setBackgroundDrawable(new CustomShapeDrawable(new RoundRectShape(new float[]{0.0f, 0.0f, 0.0f, 0.0f, (float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound, (float) this.dialogRound}, null, null), -1, ViewCompat.MEASURED_STATE_MASK, CPEConstant.convertPixelToDP(this.context, 1, false)));
            layoutParams7.height = CPEConstant.convertPixelToDP(this.context, 102, false);
            setCampaignThumbnailListView();
            linearLayout.addView(this.thumbnailListSv);
            this.contentsMainLl.addView(linearLayout);
        }
        this.closeBtnIv = new ImageView(this.context);
        int closeBtnSize = CPEConstant.convertPixelToDP(this.context, 40, true);
        this.closeBtnIv.setLayoutParams(new FrameLayout.LayoutParams(closeBtnSize, closeBtnSize, 5));
        if (CommonHelper.CheckPermissionForCommonSDK(this.activity)) {
            CPECompletionHandler.getImageDownloader(this.context).download(this.media.getTheme().getCloseBtn(), null, null, this.progressCircle, new ImageDownloadAsyncCallback(this.media.getTheme().getCirclePlayBtn(), null, ImageCacheFactory.getInstance().get("imagecache"), this.progressCircle) {
                public void onResultCustom(Bitmap bitmap) {
                    try {
                        CommonDialogContentsCreator.this.closeBtnIv.setImageBitmap(bitmap);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
        } else {
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    final Bitmap bitmap = CommonHelper.getBitmapFromURL(CommonDialogContentsCreator.this.media.getTheme().getCloseBtn());
                    new Handler(CommonDialogContentsCreator.this.context.getMainLooper()).post(new Runnable() {
                        public void run() {
                            try {
                                CommonDialogContentsCreator.this.closeBtnIv.setImageBitmap(bitmap);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        this.closeBtnIv.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                CommonDialogContentsCreator.this.finishDialog();
            }
        });
        contentsContainerLl.addView(this.contentsMainLl);
        contentsContainerFl.addView(contentsContainerLl);
        contentsContainerFl.addView(this.closeBtnIv);
        return contentsContainerFl;
    }

    private void setTitleAndAdSlideView() {
        this.adTitleTv = new TextView(this.context);
        LayoutParams adTitleParam = new LayoutParams(-2, -2);
        adTitleParam.bottomMargin = this.adImageSectionTitleMargin;
        this.adTitleTv.setLayoutParams(adTitleParam);
        this.adTitleTv.setIncludeFontPadding(false);
        this.adTitleTv.setSingleLine(true);
        this.adTitleTv.setText(this.promotions.get(this.currentCampaignKey).getDisplay() == null ? "\uc774\ubca4\ud2b8" : this.promotions.get(this.currentCampaignKey).getDisplay().getTitle());
        this.adTitleTv.setTypeface(null, 1);
        this.adTitleTv.setBackgroundColor(-1);
        this.adTitleTv.setTextColor(Color.parseColor("#000000"));
        this.adImageSectionLl.addView(this.adTitleTv);
        CPEConstant.setTextViewSize(this.context, this.adTitleTv, 18);
        this.adImageSectionLl.post(new Runnable() {
            public void run() {
                CommonDialogContentsCreator.this.setSlideImageSection();
            }
        });
    }

    /* access modifiers changed from: protected */
    public View setRewardView() {
        LayoutParams stepListLlParam;
        int i = 0;
        List<StepRewardModel> rewardList = this.promotions.get(this.currentCampaignKey).getDisplay().getStepReward();
        this.stepRewardContainer.removeAllViews();
        this.stepListLl = new LinearLayout(this.context);
        if (this.isPortrait) {
            stepListLlParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 264, true), -1);
            if ((!this.showIcon || this.campaignKeys.size() < 2) && rewardList.size() > 1) {
                stepListLlParam.bottomMargin = this.dialogRound;
            }
        } else {
            stepListLlParam = (!this.showIcon || this.campaignKeys.size() <= 1) ? new LayoutParams(-1, ((CPEConstant.convertPixelToDP(this.context, 274, true) - this.thumbnailItemSize) - this.thumbnailArrowSize) - this.thumbnailListPadding) : new LayoutParams(-1, CPEConstant.convertPixelToDP(this.context, 274, true));
        }
        this.stepListLl.setOrientation(1);
        this.stepListLl.setLayoutParams(stepListLlParam);
        if (rewardList == null || rewardList.size() < 1) {
            this.stepRewardContainer.setVisibility(0);
            this.notAvailableTv.setVisibility(8);
            if (!this.isPortrait) {
                this.stepRewardContainer.addView(this.stepListLl);
                View dividerView = getDividerView(this.isPortrait ? 0 : 1);
                dividerView.setVisibility(4);
                this.stepRewardContainer.addView(dividerView);
            }
            setNonRewardView(rewardList.size());
        } else {
            this.stepRewardContainer.addView(this.stepListLl);
            LinearLayout linearLayout = this.stepRewardContainer;
            if (!this.isPortrait) {
                i = 1;
            }
            linearLayout.addView(getDividerView(i));
            setMultiStepRewardView(rewardList.size());
        }
        return this.stepListLl;
    }

    private void setNonRewardView(int numOfReward) {
        this.stepRewardContainer.addView(getPlayBtnView(numOfReward));
    }

    private void setMultiStepRewardView(int numOfReward) {
        if (this.promotions.get(this.currentCampaignKey).getDisplay().getStepReward().size() > 1) {
            setStepListView();
        } else {
            setOneStepView();
        }
        this.stepRewardContainer.addView(getPlayBtnView(numOfReward));
    }

    private View getPlayBtnView(int numOfReward) {
        LayoutParams playBtnLlParam;
        int btnSize;
        this.playBtnLl = new RepeatBGLinearLayout(this.context);
        String playBtnUrl = this.media.getTheme().getCirclePlayBtn();
        if (this.isPortrait) {
            this.playBtnLl.setGravity(17);
            if (numOfReward > 0) {
                btnSize = CPEConstant.convertPixelToDP(this.context, 120, true);
                playBtnLlParam = new LayoutParams(-1, -1);
            } else {
                btnSize = CPEConstant.convertPixelToDP(this.context, 140, true);
                playBtnLlParam = new LayoutParams(-1, -1);
            }
        } else {
            playBtnLlParam = new LayoutParams(-1, -1);
            playBtnUrl = this.media.getTheme().getSquarePlayBtn();
            this.playBtnLl.setGravity(81);
            int playBtnLlPadding = CPEConstant.convertPixelToDP(this.context, this.isPortrait ? 5 : 10, true);
            this.playBtnLl.setPadding(playBtnLlPadding, playBtnLlPadding, playBtnLlPadding, playBtnLlPadding);
            btnSize = -1;
        }
        this.playBtnLl.setLayoutParams(playBtnLlParam);
        this.playBtnLl.setGravity(17);
        this.playBtnIv = new ImageView(this.context);
        this.playBtnIv.setLayoutParams(new LayoutParams(btnSize, btnSize));
        this.playBtnIv.setScaleType(ScaleType.FIT_CENTER);
        if (CommonHelper.CheckPermissionForCommonSDK(this.activity)) {
            CPECompletionHandler.getImageDownloader(this.context).download(playBtnUrl, null, null, null, new ImageDownloadAsyncCallback(playBtnUrl, null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                public void onResultCustom(Bitmap bitmap) {
                    CommonDialogContentsCreator.this.playBtnIv.setImageBitmap(bitmap);
                }
            });
        } else {
            final String _playBtnUrl = playBtnUrl;
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    final Bitmap bitmap = CommonHelper.getBitmapFromURL(_playBtnUrl);
                    new Handler(CommonDialogContentsCreator.this.context.getMainLooper()).post(new Runnable() {
                        public void run() {
                            try {
                                CommonDialogContentsCreator.this.playBtnIv.setImageBitmap(bitmap);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        this.playBtnLl.addView(this.playBtnIv);
        return this.playBtnLl;
    }

    private void setOneStepView() {
        int stepItemWidth;
        StepRewardModel reward = this.promotions.get(this.currentCampaignKey).getDisplay().getStepReward().get(0);
        int tvRound = CPEConstant.convertPixelToDP(this.context, this.isPortrait ? 18 : 18, true);
        int marginBetweenItem = CPEConstant.convertPixelToDP(this.context, 2, true);
        int stepDescLlPadding = CPEConstant.convertPixelToDP(this.context, 10, true);
        int nextArrowSize = CPEConstant.convertPixelToDP(this.context, 14, true);
        int rewardIvSize = CPEConstant.convertPixelToDP(this.context, 20, true);
        int stepItemHeight = CPEConstant.convertPixelToDP(this.context, this.isPortrait ? 38 : 38, true);
        LinearLayout linearLayout = new LinearLayout(this.context);
        LayoutParams layoutParams = new LayoutParams(-1, -1);
        linearLayout.setOrientation(1);
        linearLayout.setLayoutParams(layoutParams);
        if (this.isPortrait) {
            linearLayout.setGravity(17);
            linearLayout.setPadding(stepDescLlPadding, stepDescLlPadding, stepDescLlPadding, stepDescLlPadding);
            stepItemWidth = CPEConstant.convertPixelToDP(this.context, 180, true);
        } else {
            linearLayout.setGravity(1);
            linearLayout.setPadding(stepDescLlPadding, 0, stepDescLlPadding, 0);
            stepItemWidth = CPEConstant.convertPixelToDP(this.context, 160, true);
        }
        RoundRectShape roundRectShape = new RoundRectShape(new float[]{(float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound}, null, null);
        CustomShapeDrawable customShapeDrawable = new CustomShapeDrawable(roundRectShape, Color.parseColor(this.media.getTheme().getFirstUnitBGColorForOneStep()), Color.parseColor(this.media.getTheme().getFirstUnitBGColorForOneStep()), 0);
        RoundRectShape roundRectShape2 = new RoundRectShape(new float[]{(float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound}, null, null);
        CustomShapeDrawable customShapeDrawable2 = new CustomShapeDrawable(roundRectShape2, Color.parseColor(this.media.getTheme().getSecondUnitBGColorForOneStep()), Color.parseColor(this.media.getTheme().getSecondUnitBGColorForOneStep()), 0);
        RoundRectShape roundRectShape3 = new RoundRectShape(new float[]{(float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound, (float) tvRound}, null, null);
        CustomShapeDrawable customShapeDrawable3 = new CustomShapeDrawable(roundRectShape3, Color.parseColor(this.media.getTheme().getRewardUnitBGColorForOneStep()), Color.parseColor(this.media.getTheme().getRewardUnitBGColorForOneStep()), 0);
        TextView textView = new TextView(this.context);
        LayoutParams layoutParams2 = new LayoutParams(stepItemWidth, stepItemHeight);
        layoutParams2.bottomMargin = marginBetweenItem;
        textView.setLayoutParams(layoutParams2);
        textView.setBackgroundDrawable(customShapeDrawable);
        textView.setText(this.media.getLanguage().getFirstUnitForOneStep());
        textView.setTypeface(textView.getTypeface(), 1);
        textView.setGravity(17);
        textView.setTextColor(Color.parseColor("#3f292d"));
        textView.setTextSize(2, 13.0f);
        final ImageView nextIv1 = new ImageView(this.context);
        LayoutParams layoutParams3 = new LayoutParams(nextArrowSize, nextArrowSize);
        layoutParams3.bottomMargin = marginBetweenItem;
        nextIv1.setLayoutParams(layoutParams3);
        nextIv1.setScaleType(ScaleType.FIT_CENTER);
        if (CommonHelper.CheckPermissionForCommonSDK(this.activity)) {
            CPECompletionHandler.getImageDownloader(this.context).download(this.media.getTheme().getStepArrow(), null, null, null, new ImageDownloadAsyncCallback(this.media.getTheme().getStepArrow(), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                public void onResultCustom(Bitmap bitmap) {
                    nextIv1.setImageBitmap(bitmap);
                }
            });
        } else {
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    final Bitmap bitmap = CommonHelper.getBitmapFromURL(CommonDialogContentsCreator.this.media.getTheme().getStepArrow());
                    Handler handler = new Handler(CommonDialogContentsCreator.this.context.getMainLooper());
                    final ImageView imageView = nextIv1;
                    handler.post(new Runnable() {
                        public void run() {
                            try {
                                imageView.setImageBitmap(bitmap);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        TextView textView2 = new TextView(this.context);
        LayoutParams layoutParams4 = new LayoutParams(stepItemWidth, stepItemHeight);
        layoutParams4.bottomMargin = marginBetweenItem;
        textView2.setLayoutParams(layoutParams4);
        textView2.setBackgroundDrawable(customShapeDrawable2);
        textView2.setText(reward.getName());
        textView2.setTypeface(textView2.getTypeface(), 1);
        textView2.setGravity(17);
        textView2.setTextColor(Color.parseColor("#3f292d"));
        textView2.setTextSize(2, 13.0f);
        final ImageView imageView = new ImageView(this.context);
        LayoutParams layoutParams5 = new LayoutParams(nextArrowSize, nextArrowSize);
        layoutParams5.bottomMargin = marginBetweenItem;
        imageView.setLayoutParams(layoutParams5);
        imageView.setScaleType(ScaleType.FIT_CENTER);
        if (CommonHelper.CheckPermissionForCommonSDK(this.activity)) {
            CPECompletionHandler.getImageDownloader(this.context).download(this.media.getTheme().getStepArrow(), null, null, null, new ImageDownloadAsyncCallback(this.media.getTheme().getStepArrow(), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                public void onResultCustom(Bitmap bitmap) {
                    imageView.setImageBitmap(bitmap);
                }
            });
        } else {
            final ImageView imageView2 = imageView;
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    final Bitmap bitmap = CommonHelper.getBitmapFromURL(CommonDialogContentsCreator.this.media.getTheme().getStepArrow());
                    Handler handler = new Handler(CommonDialogContentsCreator.this.context.getMainLooper());
                    final ImageView imageView = imageView2;
                    handler.post(new Runnable() {
                        public void run() {
                            try {
                                imageView.setImageBitmap(bitmap);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        LinearLayout linearLayout2 = new LinearLayout(this.context);
        LayoutParams layoutParams6 = new LayoutParams(stepItemWidth, stepItemHeight);
        linearLayout2.setLayoutParams(layoutParams6);
        linearLayout2.setGravity(17);
        linearLayout2.setBackgroundDrawable(customShapeDrawable3);
        linearLayout2.setOrientation(0);
        final ImageView imageView3 = new ImageView(this.context);
        LayoutParams layoutParams7 = new LayoutParams(rewardIvSize, rewardIvSize);
        imageView3.setLayoutParams(layoutParams7);
        if (CommonHelper.CheckPermissionForCommonSDK(this.context)) {
            CPECompletionHandler.getImageDownloader(this.context).download(ADBrixHttpManager.schedule.getSchedule().getMedia().getRewardIcon(), null, null, null, new ImageDownloadAsyncCallback(ADBrixHttpManager.schedule.getSchedule().getMedia().getRewardIcon(), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                public void onResultCustom(Bitmap bitmap) {
                    imageView3.setImageBitmap(bitmap);
                }
            });
        } else {
            final ImageView imageView4 = imageView3;
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    final Bitmap bitmap = CommonHelper.getBitmapFromURL(ADBrixHttpManager.schedule.getSchedule().getMedia().getRewardIcon());
                    Handler handler = new Handler(CommonDialogContentsCreator.this.context.getMainLooper());
                    final ImageView imageView = imageView4;
                    handler.post(new Runnable() {
                        public void run() {
                            try {
                                imageView.setImageBitmap(bitmap);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        TextView textView3 = new TextView(this.context);
        textView3.setText(" " + this.media.getLanguage().getRewardUnitForOneStep() + " " + reward.getReward());
        textView3.setTypeface(textView3.getTypeface(), 1);
        textView3.setTextColor(Color.parseColor("#3f292d"));
        textView3.setTextSize(2, 13.0f);
        linearLayout2.addView(imageView3);
        linearLayout2.addView(textView3);
        linearLayout.addView(textView);
        linearLayout.addView(nextIv1);
        linearLayout.addView(textView2);
        linearLayout.addView(imageView);
        linearLayout.addView(linearLayout2);
        this.stepListLl.addView(linearLayout);
    }

    private void setStepListView() {
        LayoutParams stepListTitleLlParam;
        LayoutParams missionTitleTvParam;
        LayoutParams rewardIvParam;
        LayoutParams isCompleteTitleTvParam;
        int rowHeight = CPEConstant.convertPixelToDP(this.context, 36, false);
        LinearLayout stepListTitleLl = new LinearLayout(this.context);
        stepListTitleLl.setOrientation(0);
        stepListTitleLl.setBackgroundColor(Color.parseColor("#182030"));
        stepListTitleLl.setGravity(17);
        int stepListTitleLlPadding = CPEConstant.convertPixelToDP(this.context, 5, true);
        stepListTitleLl.setPadding(0, stepListTitleLlPadding, 0, stepListTitleLlPadding);
        this.stepListColumnMargin = CPEConstant.convertPixelToDP(this.context, 7, true);
        this.missionTitleTv = new TextView(this.context);
        this.missionTitleTv.setGravity(17);
        this.missionTitleTv.setText(this.media.getLanguage().getMission());
        this.missionTitleTv.setTextColor(Color.parseColor("#24e0f7"));
        this.missionTitleTv.setTypeface(this.missionTitleTv.getTypeface(), 1);
        CPEConstant.setTextViewSize(this.context, this.missionTitleTv, 15);
        int rewardIvSize = CPEConstant.convertPixelToDP(this.context, 20, true);
        this.rewardIv = new ImageView(this.context);
        this.rewardIv.setScaleType(ScaleType.FIT_CENTER);
        if (CommonHelper.CheckPermissionForCommonSDK(this.context)) {
            CPECompletionHandler.getImageDownloader(this.context).download(ADBrixHttpManager.schedule.getSchedule().getMedia().getRewardIcon(), null, null, null, new ImageDownloadAsyncCallback(ADBrixHttpManager.schedule.getSchedule().getMedia().getRewardIcon(), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                public void onResultCustom(Bitmap bitmap) {
                    try {
                        CommonDialogContentsCreator.this.rewardIv.setImageBitmap(bitmap);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
        } else {
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    final Bitmap bitmap = CommonHelper.getBitmapFromURL(ADBrixHttpManager.schedule.getSchedule().getMedia().getRewardIcon());
                    new Handler(CommonDialogContentsCreator.this.context.getMainLooper()).post(new Runnable() {
                        public void run() {
                            try {
                                CommonDialogContentsCreator.this.rewardIv.setImageBitmap(bitmap);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        this.isCompleteTitleTv = new TextView(this.context);
        this.isCompleteTitleTv.setText(this.media.getLanguage().getIsComplete());
        this.isCompleteTitleTv.setTextColor(Color.parseColor("#ffffff"));
        this.isCompleteTitleTv.setTypeface(this.isCompleteTitleTv.getTypeface(), 1);
        this.isCompleteTitleTv.setGravity(17);
        CPEConstant.setTextViewSize(this.context, this.isCompleteTitleTv, 15);
        stepListTitleLl.addView(this.missionTitleTv);
        stepListTitleLl.addView(getDividerView(0));
        stepListTitleLl.addView(this.rewardIv);
        stepListTitleLl.addView(getDividerView(0));
        stepListTitleLl.addView(this.isCompleteTitleTv);
        ListView listView = new ListView(this.context);
        LayoutParams layoutParams = new LayoutParams(-1, -2);
        listView.setLayoutParams(layoutParams);
        if (this.isPortrait) {
            stepListTitleLlParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 264, true), rowHeight);
            missionTitleTvParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 161, true), -2, 1.0f);
            rewardIvParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 50, true), rewardIvSize);
            isCompleteTitleTvParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 50, true), -2);
        } else {
            stepListTitleLlParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 193, true), rowHeight);
            missionTitleTvParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 113, true), -2, 1.0f);
            rewardIvParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 40, true), rewardIvSize);
            isCompleteTitleTvParam = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 40, true), -2);
        }
        stepListTitleLl.setLayoutParams(stepListTitleLlParam);
        this.missionTitleTv.setLayoutParams(missionTitleTvParam);
        this.rewardIv.setLayoutParams(rewardIvParam);
        this.isCompleteTitleTv.setLayoutParams(isCompleteTitleTvParam);
        this.stepListLl.addView(stepListTitleLl);
        this.stepListLl.addView(getDividerView(1));
        this.stepListLl.addView(listView);
        listView.setAdapter(new StepRewardListAdapter(this.context, StepRewardListAdapter.MISSION_TV_ID));
        listView.setDividerHeight(0);
    }

    /* access modifiers changed from: private */
    public View getDividerView(int orientation) {
        LayoutParams dividerLlParam;
        LayoutParams divider1Param;
        LayoutParams divider2Param;
        if (orientation == 0) {
            dividerLlParam = new LayoutParams(-2, -1);
            divider1Param = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 1, true), -1);
            divider2Param = new LayoutParams(CPEConstant.convertPixelToDP(this.context, 0, true), -1);
        } else {
            dividerLlParam = new LayoutParams(-1, -2);
            divider1Param = new LayoutParams(-1, CPEConstant.convertPixelToDP(this.context, 1, true));
            divider2Param = new LayoutParams(-1, CPEConstant.convertPixelToDP(this.context, 0, true));
        }
        LinearLayout dividerLl = new LinearLayout(this.context);
        dividerLl.setLayoutParams(dividerLlParam);
        dividerLl.setOrientation(orientation);
        ImageView divider1 = new ImageView(this.context);
        divider1.setLayoutParams(divider1Param);
        divider1.setImageDrawable(new ColorDrawable(Color.parseColor("#131924")));
        divider1.setScaleType(ScaleType.FIT_XY);
        ImageView divider2 = new ImageView(this.context);
        divider2.setLayoutParams(divider2Param);
        divider2.setImageDrawable(new ColorDrawable(Color.parseColor("#344360")));
        divider2.setScaleType(ScaleType.FIT_XY);
        dividerLl.addView(divider1);
        dividerLl.addView(divider2);
        return dividerLl;
    }

    private void setCampaignThumbnailListView() {
        LinearLayout linearLayout = new LinearLayout(this.context);
        LayoutParams layoutParams = new LayoutParams(-1, -1);
        linearLayout.setOrientation(0);
        linearLayout.setBackgroundColor(-1);
        linearLayout.setLayoutParams(layoutParams);
        this.campaignThumbnails = new SparseArray<>();
        if (this.rCks == null || this.rCks.size() != this.campaignKeys.size()) {
            long seed = System.nanoTime();
            this.rCks = new ArrayList();
            this.rCks.addAll(this.campaignKeys);
            this.rCks.remove(this.campaignKeys.indexOf(Integer.valueOf(this.currentCampaignKey)));
            Collections.shuffle(this.rCks, new Random(seed));
            this.rCks.add(0, Integer.valueOf(this.currentCampaignKey));
        }
        int thumbPadding = CPEConstant.convertPixelToDP(this.context, 6, true);
        int arrowHeight = CPEConstant.convertPixelToDP(this.context, 8, false);
        for (Integer intValue : this.rCks) {
            int item = intValue.intValue();
            LinearLayout linearLayout2 = new LinearLayout(this.context);
            LayoutParams layoutParams2 = new LayoutParams(this.thumbnailItemSize + thumbPadding, this.thumbnailItemSize + thumbPadding + arrowHeight);
            linearLayout2.setOrientation(1);
            linearLayout2.setGravity(17);
            linearLayout2.setLayoutParams(layoutParams2);
            linearLayout2.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    int idx = CommonDialogContentsCreator.this.campaignThumbnails.indexOfValue((LinearLayout) v);
                    if (CommonDialogContentsCreator.this.campaignThumbnails.keyAt(idx) != CommonDialogContentsCreator.this.currentCampaignKey) {
                        CommonDialogContentsCreator.this.setCurrentCampaign(CommonDialogContentsCreator.this.campaignThumbnails.keyAt(idx));
                        CommonDialogContentsCreator.this.changePromotionContents();
                    }
                }
            });
            if (item != this.rCks.get(0).intValue()) {
                if (this.isPortrait) {
                    layoutParams2.leftMargin = CPEConstant.convertPixelToDP(this.context, 6, true);
                } else {
                    layoutParams2.leftMargin = CPEConstant.convertPixelToDP(this.context, 12, true);
                }
            }
            final ImageView arrowIv = new ImageView(this.context);
            LayoutParams layoutParams3 = new LayoutParams((int) (((float) arrowHeight) * 1.3f), arrowHeight);
            arrowIv.setId(18841);
            arrowIv.setLayoutParams(layoutParams3);
            arrowIv.setScaleType(ScaleType.FIT_XY);
            if (CommonHelper.CheckPermissionForCommonSDK(this.context)) {
                CPECompletionHandler.getImageDownloader(this.context).download(this.media.getTheme().getSelectedAppArrow(), null, null, null, new ImageDownloadAsyncCallback(this.media.getTheme().getSelectedAppArrow(), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                    public void onResultCustom(Bitmap bitmap) {
                        arrowIv.setImageBitmap(bitmap);
                    }
                });
            } else {
                InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                    public void run() {
                        final Bitmap bitmap = CommonHelper.getBitmapFromURL(CommonDialogContentsCreator.this.media.getTheme().getSelectedAppArrow());
                        Handler handler = new Handler(CommonDialogContentsCreator.this.context.getMainLooper());
                        final ImageView imageView = arrowIv;
                        handler.post(new Runnable() {
                            public void run() {
                                try {
                                    imageView.setImageBitmap(bitmap);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                    }
                });
            }
            LinearLayout linearLayout3 = new LinearLayout(this.context);
            LayoutParams layoutParams4 = new LayoutParams(this.thumbnailItemSize + thumbPadding, this.thumbnailItemSize + thumbPadding);
            linearLayout3.setLayoutParams(layoutParams4);
            linearLayout3.setId(THUMBNAIL_LL_ID);
            linearLayout3.setGravity(17);
            final ImageView thumbIv = new ImageView(this.context);
            LayoutParams layoutParams5 = new LayoutParams(this.thumbnailItemSize, this.thumbnailItemSize);
            thumbIv.setId(22937);
            thumbIv.setLayoutParams(layoutParams5);
            thumbIv.setScaleType(ScaleType.FIT_XY);
            if (CommonHelper.CheckPermissionForCommonSDK(this.context)) {
                CPECompletionHandler.getImageDownloader(this.context).download(this.promotions.get(item).getDisplay().getIcon().getResource(), null, null, null, new ImageDownloadAsyncCallback(this.promotions.get(item).getDisplay().getIcon().getResource(), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                    public void onResultCustom(Bitmap bitmap) {
                        thumbIv.setImageBitmap(DialogUtil.getRoundedCornerBitmap(CommonDialogContentsCreator.this.context, bitmap, CommonDialogContentsCreator.this.thumbnailItemSize, CommonDialogContentsCreator.this.thumbnailItemSize));
                    }
                });
            } else {
                final int i = item;
                InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                    public void run() {
                        final Bitmap bitmap = CommonHelper.getBitmapFromURL(CommonDialogContentsCreator.this.promotions.get(i).getDisplay().getIcon().getResource());
                        Handler handler = new Handler(CommonDialogContentsCreator.this.context.getMainLooper());
                        final ImageView imageView = thumbIv;
                        handler.post(new Runnable() {
                            public void run() {
                                try {
                                    imageView.setImageBitmap(DialogUtil.getRoundedCornerBitmap(CommonDialogContentsCreator.this.context, bitmap, CommonDialogContentsCreator.this.thumbnailItemSize, CommonDialogContentsCreator.this.thumbnailItemSize));
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                    }
                });
            }
            linearLayout3.addView(thumbIv);
            linearLayout2.addView(arrowIv);
            linearLayout2.addView(linearLayout3);
            linearLayout.addView(linearLayout2);
            this.campaignThumbnails.put(item, linearLayout2);
        }
        this.thumbnailListSv.addView(linearLayout);
    }

    public void setCurrentCampaign(int campaignKey) {
        this.currentCampaignKey = campaignKey;
        addImpression(this.context, this.currentCampaignKey, this.promotions.get(this.currentCampaignKey).getDisplay().getSlide().getResourceKey(), this.spaceKey);
        if (this.campaignThumbnails != null && this.campaignThumbnails.size() > 0) {
            for (Integer intValue : this.campaignKeys) {
                int item = intValue.intValue();
                if (item == campaignKey) {
                    ((ImageView) this.campaignThumbnails.get(item).findViewById(22937)).setColorFilter(null);
                    ((LinearLayout) this.campaignThumbnails.get(item).findViewById(THUMBNAIL_LL_ID)).setBackgroundDrawable(this.roundedActiveThumbSd);
                    ((ImageView) this.campaignThumbnails.get(item).findViewById(18841)).setVisibility(0);
                    this.progressModel = null;
                    setPlayBtnClickListener();
                } else {
                    setGrayScale((ImageView) this.campaignThumbnails.get(item).findViewById(22937));
                    ((LinearLayout) this.campaignThumbnails.get(item).findViewById(THUMBNAIL_LL_ID)).setBackgroundDrawable(this.roundedInactiveThumbSd);
                    ((ImageView) this.campaignThumbnails.get(item).findViewById(18841)).setVisibility(4);
                }
            }
        } else if (this.promotions.get(this.currentCampaignKey).getDisplay() != null && (this.promotions.get(this.currentCampaignKey).getDisplay().getStepReward() == null || this.promotions.get(this.currentCampaignKey).getDisplay().getStepReward().size() < 1)) {
            setPlayBtnClickListener();
        }
        if (this.contentsMainLl != null) {
            this.contentsMainLl.invalidate();
        }
    }

    private void addImpression(Context context2, int campaignKey, int resourceKey, String spaceKey2) {
        if (!this.impressionAddedCampaign.contains(Integer.valueOf(campaignKey))) {
            try {
                Date time = Calendar.getInstance().getTime();
                TrackingActivitySQLiteDB.getInstance(context2).setImpressionData(context2, campaignKey, resourceKey, spaceKey2, CommonHelper.GetKSTCreateAtAsString(), null, null);
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                CPEImpressionDAOFactory.getImpressionDAO("impression", "session_count", 1).increaseImpressionData(context2, 1, new StringBuilder(String.valueOf(campaignKey)).toString(), "session_count");
                CPEImpressionDAOFactory.getImpressionDAO("impression", "last_imp_minute", 1).setImpressionData(context2, 1, new StringBuilder(String.valueOf(campaignKey)).toString(), "last_imp_minute", new StringBuilder(String.valueOf(new Date().getTime())).toString());
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            this.impressionAddedCampaign.add(Integer.valueOf(campaignKey));
        }
    }

    /* access modifiers changed from: protected */
    public void setPlayBtnClickListener() {
        try {
            RequestParameter parameter = RequestParameter.getATRequestParameter(this.context);
            if (this.promotions.get(this.currentCampaignKey).getDisplay().getStepReward().size() <= 0 || this.progressModel != null) {
                this.playBtnIv.setOnClickListener(this.landingBtnClickLisetner);
                return;
            }
            this.playBtnIv.setOnClickListener(this.onReadyBtnClickListener);
            if (this.progressModels != null && this.progressModels.indexOfKey(this.currentCampaignKey) > -1) {
                this.progressModel = this.progressModels.get(this.currentCampaignKey);
                setProgressModel();
            } else if (!this.onGetProgressModel) {
                ADBrixHttpManager httpManager = ADBrixHttpManager.getManager(this.context);
                DeviceIDManger puidCreator = DeviceIDManger.getInstance(this.context);
                String usn = null;
                try {
                    if (this.context != null) {
                        usn = this.context.getSharedPreferences("persistantDemoForTracking", 0).getString(DemographicDAO.KEY_USN, null);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                httpManager.getParticipationProgressForADBrix(parameter, this.context, parameter.getAppkey(), this.currentCampaignKey, puidCreator.getAESPuid(this.context), usn, this);
                addProgressCircle(this.context, this.stepLoadingFl);
                this.onGetProgressModel = true;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void setGrayScale(ImageView v) {
        ColorMatrix matrix = new ColorMatrix();
        matrix.setSaturation(0.0f);
        v.setColorFilter(new ColorMatrixColorFilter(matrix));
    }

    public void setGrayScale(Drawable v) {
        ColorMatrix matrix = new ColorMatrix();
        matrix.setSaturation(0.0f);
        v.setColorFilter(new ColorMatrixColorFilter(matrix));
    }

    private void addProgressCircle(Context context2, ViewGroup parent) {
        try {
            if (!(this.progressCircle == null || this.stepLoadingFl == null)) {
                ((ViewGroup) this.progressCircle.getParent()).removeViewInLayout(this.progressCircle);
                this.progressCircle = null;
            }
            this.progressCircle = new FrameLayout(context2);
            ProgressBar progressCirclePb = new ProgressBar(context2);
            LayoutParams pcParam = new LayoutParams(-1, -1);
            FrameLayout.LayoutParams pcpbParam = new FrameLayout.LayoutParams(-2, -2);
            pcpbParam.gravity = 17;
            pcParam.gravity = 17;
            progressCirclePb.setLayoutParams(pcpbParam);
            this.progressCircle.setLayoutParams(pcParam);
            this.progressCircle.addView(progressCirclePb);
            parent.addView(this.progressCircle);
        } catch (Exception e) {
        }
    }

    public void onResume() {
        try {
            if (this.promotions.get(this.currentCampaignKey).getDisplay().getStepReward().size() > 0 && !this.onGetProgressModel) {
                RequestParameter parameter = RequestParameter.getATRequestParameter(this.context);
                ADBrixHttpManager httpManager = ADBrixHttpManager.getManager(this.context);
                DeviceIDManger puidCreator = DeviceIDManger.getInstance(this.context);
                String usn = null;
                try {
                    if (this.context != null) {
                        usn = this.context.getSharedPreferences("persistantDemoForTracking", 0).getString(DemographicDAO.KEY_USN, null);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                httpManager.getParticipationProgressForADBrix(parameter, this.context, parameter.getAppkey(), this.currentCampaignKey, puidCreator.getAESPuid(this.context), usn, this);
                addProgressCircle(this.context, this.stepLoadingFl);
                this.onGetProgressModel = true;
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void setProgressModel() {
        this.handler.post(new Runnable() {
            public void run() {
                try {
                    if (!(CommonDialogContentsCreator.this.progressCircle == null || CommonDialogContentsCreator.this.stepLoadingFl == null)) {
                        ViewParent cParent = CommonDialogContentsCreator.this.progressCircle.getParent();
                        ((ViewGroup) cParent).removeViewInLayout(CommonDialogContentsCreator.this.progressCircle);
                        CommonDialogContentsCreator.this.progressCircle = null;
                        ((View) cParent).invalidate();
                    }
                    if (CommonDialogContentsCreator.this.progressModel == null || !CommonDialogContentsCreator.this.progressModel.isResult()) {
                        CommonDialogContentsCreator.this.stepRewardContainer.setVisibility(8);
                        CommonDialogContentsCreator.this.notAvailableTv.setVisibility(0);
                        if (CommonDialogContentsCreator.this.progressModel != null) {
                            String errorMsg = CommonDialogContentsCreator.this.media.getLanguage().getUnknownError();
                            switch (CommonDialogContentsCreator.this.progressModel.getResultCode()) {
                                case 5302:
                                    errorMsg = CommonDialogContentsCreator.this.media.getLanguage().getCanNotParticipate();
                                    break;
                                case CommonDialogContentsCreator.ON_PARTICIPATION_IN_ANOTHER_APP /*5303*/:
                                    errorMsg = CommonDialogContentsCreator.this.media.getLanguage().getAnotherAppParticipate();
                                    break;
                            }
                            if (CommonDialogContentsCreator.this.notAvailableTv != null) {
                                CommonDialogContentsCreator.this.notAvailableTv.setText(errorMsg);
                            }
                            NotAvailableCampaignDAO.getInstance().saveNotAvailableCampaign(CommonDialogContentsCreator.this.context, CommonDialogContentsCreator.this.currentCampaignKey);
                        } else if (CommonDialogContentsCreator.this.notAvailableTv != null) {
                            CommonDialogContentsCreator.this.notAvailableTv.setText(CommonDialogContentsCreator.this.media.getLanguage().getUnknownError());
                        }
                    } else {
                        CommonDialogContentsCreator.this.stepRewardContainer.setVisibility(0);
                        CommonDialogContentsCreator.this.notAvailableTv.setVisibility(8);
                        if (!(CommonDialogContentsCreator.this.progressModel == null || CommonDialogContentsCreator.this.progressModel.getData() == null)) {
                            List<StepRewardModel> steps = CommonDialogContentsCreator.this.promotions.get(CommonDialogContentsCreator.this.currentCampaignKey).getDisplay().getStepReward();
                            int completeSteps = 0;
                            for (StepRewardModel step : steps) {
                                Iterator<ParticipationProgressModel> it = CommonDialogContentsCreator.this.progressModel.getData().iterator();
                                while (true) {
                                    if (!it.hasNext()) {
                                        break;
                                    } else if (it.next().getConversionKey() == step.getConversionKey()) {
                                        step.setComplete(true);
                                        completeSteps++;
                                        break;
                                    } else {
                                        step.setComplete(false);
                                    }
                                }
                            }
                            if (steps.size() > 0 && completeSteps == steps.size()) {
                                CommonDialogContentsCreator.this.stepRewardContainer.setVisibility(8);
                                CommonDialogContentsCreator.this.notAvailableTv.setVisibility(0);
                                if (CommonDialogContentsCreator.this.notAvailableTv != null) {
                                    CommonDialogContentsCreator.this.notAvailableTv.setText(CommonDialogContentsCreator.this.media.getLanguage().getAlreadyParticipated());
                                }
                                NotAvailableCampaignDAO.getInstance().saveNotAvailableCampaign(CommonDialogContentsCreator.this.context, CommonDialogContentsCreator.this.currentCampaignKey);
                            }
                        }
                        CommonDialogContentsCreator.this.setRewardView();
                        CommonDialogContentsCreator.this.setPlayBtnClickListener();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    CommonDialogContentsCreator.this.finishDialog();
                }
            }
        });
    }

    public DialogActionListener getActionListener() {
        return this.actionListener;
    }

    public void setActionListener(DialogActionListener actionListener2) {
        this.actionListener = actionListener2;
    }

    public void callback(ParticipationProgressResponseModel model) {
        int i = 0;
        try {
            this.onGetProgressModel = false;
            if (this.progressModels == null) {
                this.progressModels = new SparseArray<>();
            }
            this.progressModel = model;
            this.progressModels.append(this.currentCampaignKey, model);
            if (model == null) {
                IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "Adbrix > get participation progress failed.", 3);
                this.playBtnIv.setOnClickListener(this.onFailBtnClickListener);
                return;
            }
            Context context2 = this.context;
            StringBuilder sb = new StringBuilder("Adbrix > get participation progress result size = ");
            if (model.getData() != null) {
                i = model.getData().size();
            }
            IgawLogger.Logging(context2, IgawConstant.QA_TAG, sb.append(i).toString(), 3);
            setProgressModel();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}