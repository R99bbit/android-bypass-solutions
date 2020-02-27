package com.nuvent.shareat.widget.view;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.text.SpannableStringBuilder;
import android.text.method.LinkMovementMethod;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import com.facebook.appevents.AppEventsConstants;
import com.naver.maps.geometry.LatLng;
import com.naver.maps.map.CameraPosition;
import com.naver.maps.map.NaverMap;
import com.naver.maps.map.OnMapReadyCallback;
import com.naver.maps.map.overlay.Marker;
import com.naver.maps.map.overlay.OverlayImage;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.MenuActivity;
import com.nuvent.shareat.activity.main.SearchTagActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.store.StoreMenuApi;
import com.nuvent.shareat.dialog.CouponDialog;
import com.nuvent.shareat.dialog.CouponDialog.onClickDialog;
import com.nuvent.shareat.event.TabClickEvent;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.SpanTagModel;
import com.nuvent.shareat.model.store.ChartModel;
import com.nuvent.shareat.model.store.ReviewCountModel;
import com.nuvent.shareat.model.store.StoreDetailModel;
import com.nuvent.shareat.model.store.StoreImageModel;
import com.nuvent.shareat.model.store.StoreMenuModel;
import com.nuvent.shareat.model.store.StoreMenuResultModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.ShareAtUtil;
import com.nuvent.shareat.widget.view.CustomClickableSpan.OnSpanClick;
import de.greenrobot.event.EventBus;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.xenix.util.ImageDisplay;
import net.xenix.util.ProportionalImageView;

public class StoreDetailView extends FrameLayout implements OnMapReadyCallback {
    private CameraPosition cameraPosition;
    /* access modifiers changed from: private */
    public ArrayList<StoreMenuModel> mMenuModels;
    /* access modifiers changed from: private */
    public String mMenuType = "DB";
    /* access modifiers changed from: private */
    public StoreDetailModel mModel;
    private NaverMap mNaverMap;
    private ImageView[] mPageIndicator;
    private ImagePagerAdapter mPagerAdapter;

    public static class ImagePagerAdapter extends PagerAdapter {
        /* access modifiers changed from: private */
        public Context mContext;
        private LayoutInflater mLayoutInflater;
        /* access modifiers changed from: private */
        public ImageViewerClickListener mListener;
        /* access modifiers changed from: private */
        public StoreDetailModel mModel;
        private ArrayList<StoreImageModel> mStoreImageModel;

        public interface ImageViewerClickListener {
            void onViewerClick(int i, StoreDetailModel storeDetailModel);
        }

        public void addImageViewrClickListener(ImageViewerClickListener listener) {
            if (this.mListener == null || this.mListener != listener) {
                this.mListener = listener;
            }
        }

        public void removemageViewrClickListener() {
            this.mListener = null;
        }

        private ImagePagerAdapter(Context context, ArrayList<StoreImageModel> storeImageModel, StoreDetailModel model) {
            this.mStoreImageModel = new ArrayList<>();
            this.mStoreImageModel = storeImageModel;
            this.mContext = context;
            this.mLayoutInflater = (LayoutInflater) context.getSystemService("layout_inflater");
            this.mModel = model;
        }

        public int getItemPosition(Object object) {
            return -2;
        }

        public int getCount() {
            return this.mStoreImageModel.size();
        }

        public View instantiateItem(ViewGroup container, final int position) {
            View view = this.mLayoutInflater.inflate(R.layout.view_store_image_page, null);
            ImageDisplay.getInstance().displayImageLoad(this.mStoreImageModel.get(position).getImg_path(), (ImageView) view.findViewById(R.id.pageImageView), (int) R.drawable.main_shop_photo);
            view.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    GAEvent.onGaEvent((Activity) (BaseActivity) ImagePagerAdapter.this.mContext, (int) R.string.ga_store_detail, (int) R.string.ga_ev_img_search, (int) R.string.ga_store_detail_main_image);
                    if (ImagePagerAdapter.this.mListener != null) {
                        ImagePagerAdapter.this.mListener.onViewerClick(position, ImagePagerAdapter.this.mModel);
                    }
                }
            });
            container.addView(view);
            return view;
        }

        public void destroyItem(ViewGroup container, int position, Object object) {
            container.removeView((View) object);
        }

        public boolean isViewFromObject(View view, Object object) {
            return view == object;
        }
    }

    public StoreDetailView(Context context) {
        super(context);
        init();
    }

    public StoreDetailView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public StoreDetailView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private String findHomepageLink(String strHomepageLinkText) {
        StringBuffer sb = new StringBuffer();
        Matcher matcher = Pattern.compile("(http|https|ftp)://[^\\s^\\.]+(\\.[^\\s^\\.^\"^']+)*").matcher(strHomepageLinkText);
        if (matcher.find()) {
            sb.append(matcher.group(0));
        }
        return sb.toString();
    }

    private String findHomepageLinkLine(String strTrafficInfo, String strSplit) {
        String[] arrTrafficInfo = strTrafficInfo.split(strSplit);
        for (int i = 0; i < arrTrafficInfo.length; i++) {
            if (Pattern.compile("(http|https|ftp)://[^\\s^\\.]+(\\.[^\\s^\\.^\"^']+)*").matcher(arrTrafficInfo[i]).find()) {
                return arrTrafficInfo[i];
            }
        }
        return null;
    }

    private String replaceLast(String string, String toReplace, String replacement) {
        int pos = string.lastIndexOf(toReplace);
        if (pos > -1) {
            return string.substring(0, pos) + replacement + string.substring(toReplace.length() + pos, string.length());
        }
        return string;
    }

    public void setData(StoreDetailModel model, ArrayList<StoreImageModel> models, Typeface typeface) {
        this.mModel = model;
        setViewPager(models);
        SpannableStringBuilder ssb = new SpannableStringBuilder(model.getHashTag());
        Iterator<SpanTagModel> it = ShareAtUtil.getTags(model.getHashTag()).iterator();
        while (it.hasNext()) {
            SpanTagModel tag = it.next();
            String substring = model.getHashTag().substring(tag.start, tag.end);
            AnonymousClass1 r0 = new OnSpanClick() {
                public void onClick(String text) {
                    Intent intent = new Intent(StoreDetailView.this.getContext(), SearchTagActivity.class);
                    if (text.contains(",")) {
                        text = text.replace(",", "");
                    }
                    intent.putExtra("title", text);
                    ((BaseActivity) StoreDetailView.this.getContext()).pushActivity(intent);
                }
            };
            ssb.setSpan(new CustomClickableSpan(substring, r0), tag.start, tag.end, 33);
        }
        if (true == CardView.DELIVERY.equals(this.mModel.getPaymentMethodType())) {
            findViewById(R.id.menu_icon_layout).setVisibility(8);
            findViewById(R.id.menuGroupLayout).setVisibility(8);
            findViewById(R.id.payment_count_summary_layout).setVisibility(8);
            findViewById(R.id.dotted_line1).setVisibility(8);
            findViewById(R.id.timeFormatLabel).setVisibility(8);
            findViewById(R.id.timeLabel).setVisibility(8);
            ((TextView) findViewById(R.id.distanceLabel)).setText("MAP");
        } else {
            ((TextView) findViewById(R.id.distanceLabel)).setText(model.getDistance());
        }
        if (this.mModel.getUseBizChat() == null || true == "N".equals(this.mModel.getUseBizChat())) {
            findViewById(R.id.kakao_inquire_layout).setVisibility(8);
        } else if (true == "Y".equals(this.mModel.getUseBizChat())) {
            View findViewById = findViewById(R.id.kakao_inquire);
            AnonymousClass2 r02 = new OnClickListener() {
                public void onClick(View v) {
                    if (!SessionManager.getInstance().hasSession()) {
                        ((BaseActivity) StoreDetailView.this.getContext()).showLoginDialog();
                        return;
                    }
                    String link = StoreDetailView.this.mModel.getUseBizChatURL();
                    if (link != null) {
                        try {
                            StoreDetailView.this.getContext().startActivity(new Intent("android.intent.action.VIEW", Uri.parse(link + "&title=" + URLEncoder.encode(StoreDetailView.this.mModel.getPartner_name1(), "UTF-8") + "&phone_os=A&phone_model=" + URLEncoder.encode(Build.MODEL, "UTF-8") + "&parameter1=" + ShareatApp.getInstance().getPhonenumber() + "&parameter2=" + URLEncoder.encode(SessionManager.getInstance().getUserModel().getUser_id(), "UTF-8"))));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
            };
            findViewById.setOnClickListener(r02);
        }
        findViewById(R.id.navigationButtonLayout).setVisibility(0);
        ((TextView) findViewById(R.id.storeTagLabel)).setText(ssb);
        ((TextView) findViewById(R.id.storeTagLabel)).setMovementMethod(LinkMovementMethod.getInstance());
        ((TextView) findViewById(R.id.storeDescriptionLabel)).setText(model.getIntroduce());
        ((TextView) findViewById(R.id.reviewButtonCountLabel)).setText(String.valueOf(model.getCnt_review()));
        ((TextView) findViewById(R.id.menuButtonLabel)).setText("Menu");
        ((TextView) findViewById(R.id.payCountLabel)).setText(model.getPayCount());
        ((TextView) findViewById(R.id.callNumLabel)).setText(model.getCallNumber());
        ((TextView) findViewById(R.id.timeLabel)).setText(model.getEventTimeFormat()[0]);
        ((TextView) findViewById(R.id.timeFormatLabel)).setText(model.getEventTimeFormat()[1]);
        ((TextView) findViewById(R.id.salesTimeLabel)).setText(model.getSalesTime());
        ((TextView) findViewById(R.id.addressLabel)).setText(model.getAddress());
        ((TextView) findViewById(R.id.payDescriptionLabel)).setText(model.eventMsg());
        LinearLayout imageContentsLayout = (LinearLayout) findViewById(R.id.storeDetailImageContentsLayout);
        String[] storeDetailContentsImages = model.getDetailContentsImgArray();
        if (storeDetailContentsImages != null) {
            LinearLayout imageContentsList = (LinearLayout) findViewById(R.id.storeDetailImageContentsList);
            imageContentsList.removeAllViews();
            int length = storeDetailContentsImages.length;
            for (int i = 0; i < length; i++) {
                String detailContentsImageUrl = storeDetailContentsImages[i];
                ProportionalImageView imageContentsImageView = new ProportionalImageView(getContext());
                imageContentsImageView.setLayoutParams(new LayoutParams(-1, -2));
                imageContentsImageView.setAdjustViewBounds(true);
                ImageDisplay.getInstance().displayImageLoad(detailContentsImageUrl, imageContentsImageView);
                imageContentsList.addView(imageContentsImageView);
            }
        } else {
            imageContentsLayout.setVisibility(8);
        }
        if (model.getTraffinc_info() == null || model.getTraffinc_info().isEmpty()) {
            findViewById(R.id.storeInfoLayout).setVisibility(8);
        } else {
            String strTrafficInfo = model.getTraffinc_info();
            String strHomeLinkText = findHomepageLinkLine(strTrafficInfo, "\r\n");
            if (strHomeLinkText != null && !strHomeLinkText.isEmpty()) {
                strTrafficInfo = replaceLast(strTrafficInfo.replace(strHomeLinkText, ""), "\r\n", "");
                String strHomeLink = findHomepageLink(strHomeLinkText);
                if (strHomeLink != null && !strHomeLink.isEmpty()) {
                    String strHomeLinkText2 = strHomeLinkText.replace(strHomeLink, "");
                    findViewById(R.id.homepageUrlLayout).setVisibility(0);
                    ((TextView) findViewById(R.id.homepageText)).setText(strHomeLinkText2);
                    ((TextView) findViewById(R.id.homepageUrl)).setText(strHomeLink);
                }
            }
            ((TextView) findViewById(R.id.storeInfoLabel)).setText(strTrafficInfo);
        }
        String dcTypeText = model.getTiker(getContext());
        if (model.getCouponGroupSno() == null || model.getCouponGroupSno().equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            findViewById(R.id.couponLayout).setVisibility(8);
        } else {
            findViewById(R.id.couponLayout).setVisibility(0);
            ((TextView) findViewById(R.id.couponNameLabel)).setText(model.getCouponName());
            View findViewById2 = findViewById(R.id.couponLayout);
            AnonymousClass3 r03 = new OnClickListener() {
                public void onClick(View v) {
                    if (!SessionManager.getInstance().hasSession()) {
                        ((BaseActivity) StoreDetailView.this.getContext()).showLoginDialog();
                        return;
                    }
                    StoreDetailView.this.onStoreCustomDimention();
                    GAEvent.onGaEvent((Activity) (BaseActivity) StoreDetailView.this.getContext(), (int) R.string.ga_store_detail, (int) R.string.select_coupon, (int) R.string.select_coupon);
                    CouponDialog dialog = new CouponDialog(StoreDetailView.this.getContext(), StoreDetailView.this.mModel.getCouponName(), StoreDetailView.this.mModel.getCouponGroupSno());
                    dialog.setOnClickDialogListener(new onClickDialog() {
                        public void onClickDownload() {
                            StoreDetailView.this.onStoreCustomDimention();
                            GAEvent.onGaEvent((Activity) (BaseActivity) StoreDetailView.this.getContext(), (int) R.string.ga_store_detail, (int) R.string.download_coupon, (int) R.string.download_coupon);
                        }
                    });
                    dialog.show();
                }
            };
            findViewById2.setOnClickListener(r03);
        }
        ((TextView) findViewById(R.id.dcTypeLabel)).setText(dcTypeText);
        ((TextView) findViewById(R.id.totalPayCountLabel)).setText("Total " + model.getPayCount());
        requestStoreMenuApi();
    }

    public void setTabData(int type) {
        LinearLayout reviewTabLayout = (LinearLayout) findViewById(R.id.reviewHeaderTabLayout);
        LinearLayout instaTabLayout = (LinearLayout) findViewById(R.id.instaHeaderTabLayout);
        LinearLayout blogTabLayout = (LinearLayout) findViewById(R.id.blogHeaderTabLayout);
        reviewTabLayout.setSelected(false);
        instaTabLayout.setSelected(false);
        blogTabLayout.setSelected(false);
        switch (type) {
            case 1:
                reviewTabLayout.setSelected(true);
                return;
            case 2:
                instaTabLayout.setSelected(true);
                return;
            case 3:
                blogTabLayout.setSelected(true);
                return;
            default:
                return;
        }
    }

    public void clearData() {
        ((TextView) findViewById(R.id.menuButtonLabel)).setText("");
        ((TextView) findViewById(R.id.dcTypeLabel)).setText("");
        ((TextView) findViewById(R.id.storeTagLabel)).setText("");
        ((TextView) findViewById(R.id.storeDescriptionLabel)).setText("");
        ((TextView) findViewById(R.id.payCountLabel)).setText("");
        ((TextView) findViewById(R.id.distanceLabel)).setText("");
        ((TextView) findViewById(R.id.reviewButtonCountLabel)).setText("");
        ((TextView) findViewById(R.id.callNumLabel)).setText("");
        ((TextView) findViewById(R.id.timeLabel)).setText("");
        ((TextView) findViewById(R.id.timeFormatLabel)).setText("");
        ((TextView) findViewById(R.id.salesTimeLabel)).setText("");
        ((TextView) findViewById(R.id.addressLabel)).setText("");
        ((TextView) findViewById(R.id.reviewCountLabel)).setText("");
        ((TextView) findViewById(R.id.payDescriptionLabel)).setText("");
        this.mModel = null;
    }

    private void init() {
        View.inflate(getContext(), R.layout.header_store_detail, this);
        ((LinearLayout) findViewById(R.id.reviewHeaderTabLayout)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreDetailView.this.onStoreCustomDimention();
                GAEvent.onGaEvent((Activity) (BaseActivity) StoreDetailView.this.getContext(), (int) R.string.ga_store_detail, (int) R.string.ga_ev_click, (int) R.string.StoreDetail_Review_Tab);
                EventBus.getDefault().post(new TabClickEvent(1));
            }
        });
        ((LinearLayout) findViewById(R.id.instaHeaderTabLayout)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreDetailView.this.onStoreCustomDimention();
                GAEvent.onGaEvent((Activity) (BaseActivity) StoreDetailView.this.getContext(), (int) R.string.ga_store_detail, (int) R.string.ga_ev_click, (int) R.string.StoreDetail_Insta_Tab);
                EventBus.getDefault().post(new TabClickEvent(2));
            }
        });
        ((LinearLayout) findViewById(R.id.blogHeaderTabLayout)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreDetailView.this.onStoreCustomDimention();
                GAEvent.onGaEvent((Activity) (BaseActivity) StoreDetailView.this.getContext(), (int) R.string.ga_store_detail, (int) R.string.ga_ev_click, (int) R.string.StoreDetail_Blog_Tab);
                EventBus.getDefault().post(new TabClickEvent(3));
            }
        });
        findViewById(R.id.address_copy_btn).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreDetailView.setClipBoardLink(StoreDetailView.this.getContext(), ((TextView) StoreDetailView.this.findViewById(R.id.addressLabel)).getText().toString());
            }
        });
    }

    public static void setClipBoardLink(Context context, String link) {
        ((ClipboardManager) context.getSystemService("clipboard")).setPrimaryClip(ClipData.newPlainText("label", link));
        Toast.makeText(context, "\uc8fc\uc18c\uac00 \ud074\ub9bd\ubcf4\ub4dc\uc5d0 \ubcf5\uc0ac\ub418\uc5c8\uc2b5\ub2c8\ub2e4.", 0).show();
    }

    public void onMapReady(@NonNull NaverMap naverMap) {
        naverMap.getUiSettings().setZoomControlEnabled(false);
        this.mNaverMap = naverMap;
        setMapPoint();
    }

    public void updateMap(LatLng latLng) {
        Marker marker = new Marker();
        marker.setPosition(latLng);
        marker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_01));
        marker.setMap(this.mNaverMap);
        this.cameraPosition = new CameraPosition(latLng, this.mNaverMap.getMaxZoom() - 2.0d);
        this.mNaverMap.setCameraPosition(this.cameraPosition);
    }

    public void setMapPoint() {
        if (this.mModel != null) {
            updateMap(new LatLng(Double.valueOf(this.mModel.getMap_y()).doubleValue(), Double.valueOf(this.mModel.getMap_x()).doubleValue()));
        }
    }

    /* access modifiers changed from: private */
    public void setMenu() {
        int size;
        ViewGroup menuLayout = (ViewGroup) findViewById(R.id.menuRanklayout);
        menuLayout.removeAllViews();
        int i = 0;
        while (true) {
            if (10 < this.mMenuModels.size()) {
                size = 10;
            } else {
                size = this.mMenuModels.size();
            }
            if (i >= size) {
                break;
            }
            View view = View.inflate(getContext(), R.layout.cell_menu, null);
            ((TextView) view.findViewById(R.id.menuNameLabel)).setText(this.mMenuModels.get(i).getMenu_name());
            ((TextView) view.findViewById(R.id.menuPriceLabel)).setText(this.mMenuModels.get(i).getPrice());
            if (!this.mMenuType.equals("ES")) {
                view.findViewById(R.id.rankIconLayout).setVisibility(8);
                view.findViewById(R.id.menuRankLabel).setVisibility(8);
            } else {
                if (this.mMenuModels.get(i).getMenu_rank() == null || this.mMenuModels.get(i).getMenu_rank().equals(AppEventsConstants.EVENT_PARAM_VALUE_NO) || this.mMenuModels.get(i).getMenu_rank().equals("-")) {
                    view.findViewById(R.id.rankIconLayout).setVisibility(4);
                    view.findViewById(R.id.menuRankLabel).setBackgroundResource(R.drawable.menu_rank_bg_disable);
                    ((TextView) view.findViewById(R.id.menuRankLabel)).setText("-");
                } else {
                    ((TextView) view.findViewById(R.id.menuRankLabel)).setText(this.mMenuModels.get(i).getMenu_rank() + "\uc704");
                }
                int resourceId = R.drawable.menu_rank_new;
                if (this.mMenuModels.get(i).getMenu_change().equals("U")) {
                    resourceId = R.drawable.menu_rank_up;
                } else if (this.mMenuModels.get(i).getMenu_change().equals("D")) {
                    resourceId = R.drawable.menu_rank_down;
                } else if (this.mMenuModels.get(i).getMenu_change().equals("K")) {
                    resourceId = R.drawable.menu_rank_fix;
                }
                ((ImageView) view.findViewById(R.id.rankIconView)).setImageResource(resourceId);
            }
            menuLayout.addView(view);
            i++;
        }
        if (menuLayout.getChildCount() == 0) {
            findViewById(R.id.menu_layout).setVisibility(8);
            findViewById(R.id.menuMoreLayout).setVisibility(8);
            return;
        }
        findViewById(R.id.menu_layout).setVisibility(0);
        findViewById(R.id.menuMoreLayout).setVisibility(0);
        findViewById(R.id.menuMoreLayout).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent(StoreDetailView.this.getResources().getString(R.string.ga_store_detail), StoreDetailView.this.getResources().getString(R.string.ga_ev_click), StoreDetailView.this.getResources().getString(R.string.ga_store_detail_menu_more));
                if (!SessionManager.getInstance().hasSession()) {
                    ((BaseActivity) StoreDetailView.this.getContext()).showLoginDialog();
                    return;
                }
                Intent intent = new Intent(StoreDetailView.this.getContext(), MenuActivity.class);
                intent.putExtra("title", StoreDetailView.this.mModel.getPartner_name1());
                intent.putExtra("partnerSno", StoreDetailView.this.mModel.getPartner_sno());
                intent.putExtra("menuResultSet", StoreDetailView.this.mMenuType);
                ((BaseActivity) StoreDetailView.this.getContext()).pushActivity(intent);
            }
        });
    }

    /* access modifiers changed from: private */
    public void setGraph(ArrayList<ChartModel> models) {
        if (models == null || models.size() <= 0) {
            findViewById(R.id.graphLayout).setVisibility(8);
            findViewById(R.id.graphHideLine).setVisibility(0);
        } else {
            findViewById(R.id.graphLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.abc_fade_in));
            findViewById(R.id.graphLayout).setVisibility(0);
            findViewById(R.id.graphHideLine).setVisibility(8);
        }
        findViewById(R.id.graphView_01).setVisibility(8);
        findViewById(R.id.graphView_02).setVisibility(8);
        findViewById(R.id.graphView_03).setVisibility(8);
        int i = 0;
        while (true) {
            if (i < (models.size() > 3 ? 3 : models.size())) {
                if (i == 0) {
                    try {
                        ((GraphView) findViewById(R.id.graphView_01)).setModel(models.get(i), i);
                        findViewById(R.id.graphView_01).setVisibility(0);
                    } catch (IndexOutOfBoundsException e) {
                        e.printStackTrace();
                        if (i == 0) {
                            findViewById(R.id.graphView_01).setVisibility(8);
                        } else if (i == 1) {
                            findViewById(R.id.graphView_02).setVisibility(8);
                        } else {
                            findViewById(R.id.graphView_03).setVisibility(8);
                        }
                    }
                } else if (i == 1) {
                    ((GraphView) findViewById(R.id.graphView_02)).setModel(models.get(i), i);
                    findViewById(R.id.graphView_02).setVisibility(0);
                } else {
                    ((GraphView) findViewById(R.id.graphView_03)).setModel(models.get(i), i);
                    findViewById(R.id.graphView_03).setVisibility(0);
                }
                i++;
            } else {
                return;
            }
        }
    }

    private void addPageIndicator() {
        ViewGroup indicatorGroup = (ViewGroup) findViewById(R.id.indicatorLayout);
        indicatorGroup.removeAllViews();
        if (this.mPagerAdapter.getCount() != 0) {
            this.mPageIndicator = new ImageView[this.mPagerAdapter.getCount()];
            for (int i = 0; i < this.mPagerAdapter.getCount(); i++) {
                this.mPageIndicator[i] = new ImageView(getContext());
                this.mPageIndicator[i].setImageResource(R.drawable.selector_page_indicator);
                indicatorGroup.addView(this.mPageIndicator[i]);
                if (i == 0) {
                    this.mPageIndicator[i].setSelected(true);
                } else {
                    ((LinearLayout.LayoutParams) this.mPageIndicator[i].getLayoutParams()).leftMargin = getResources().getDimensionPixelOffset(R.dimen.STORE_PAGE_INDICATOR_MARGIN);
                }
            }
        }
    }

    /* access modifiers changed from: private */
    public void setPageIndicator(int position) {
        for (ImageView selected : this.mPageIndicator) {
            selected.setSelected(false);
        }
        this.mPageIndicator[position].setSelected(true);
    }

    public ImagePagerAdapter getImagePagerAdapter() {
        return this.mPagerAdapter;
    }

    public void setViewPager(ArrayList<StoreImageModel> models) {
        this.mPagerAdapter = new ImagePagerAdapter(getContext(), models, this.mModel);
        if (this.mPagerAdapter != null) {
            ViewPager viewPager = (ViewPager) findViewById(R.id.viewPager);
            viewPager.setAdapter(this.mPagerAdapter);
            viewPager.setOffscreenPageLimit(this.mPagerAdapter.getCount());
            viewPager.setCurrentItem(0);
            viewPager.addOnPageChangeListener(new OnPageChangeListener() {
                public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                }

                public void onPageSelected(int position) {
                    StoreDetailView.this.setPageIndicator(((ViewPager) StoreDetailView.this.findViewById(R.id.viewPager)).getCurrentItem());
                }

                public void onPageScrollStateChanged(int state) {
                }
            });
            addPageIndicator();
        }
    }

    public void setReviewCount(ReviewCountModel model) {
        ((TextView) findViewById(R.id.reviewHeaderCountLabel)).setText("(" + model.getShareat_count() + ")");
        ((TextView) findViewById(R.id.instaHeaderCountLabel)).setText("(" + model.getInsta_count() + ")");
        ((TextView) findViewById(R.id.blogHeaderCountLabel)).setText("(" + model.getNaver_count() + ")");
    }

    /* access modifiers changed from: private */
    public void requestStoreMenuApi() {
        String params = String.format("?partner_sno=%s", new Object[]{Integer.valueOf(this.mModel.getPartner_sno())});
        StoreMenuApi request = new StoreMenuApi(getContext());
        request.addGetParam(params);
        request.request(new RequestHandler() {
            public void onStart() {
                ((BaseActivity) StoreDetailView.this.getContext()).showCircleDialog(true);
            }

            public void onResult(Object result) {
                ((BaseActivity) StoreDetailView.this.getContext()).showCircleDialog(false);
                StoreMenuResultModel model = (StoreMenuResultModel) result;
                if (model.getResult().equals("Y")) {
                    StoreDetailView.this.mMenuModels = model.getResult_list();
                    StoreDetailView.this.mMenuType = model.getResult_set();
                    StoreDetailView.this.setMenu();
                    ((TextView) StoreDetailView.this.findViewById(R.id.currentPayCountLabel)).setText(model.getRecent_cnt_pay());
                    StoreDetailView.this.setGraph(model.getChartList());
                    if (StoreDetailView.this.findViewById(R.id.menu_layout).getVisibility() == 8) {
                        StoreDetailView.this.findViewById(R.id.graphHideLine).setVisibility(8);
                    }
                }
            }

            public void onFailure(Exception exception) {
                ((BaseActivity) StoreDetailView.this.getContext()).showCircleDialog(false);
                exception.printStackTrace();
                ((BaseActivity) StoreDetailView.this.getContext()).handleException(exception, new Runnable() {
                    public void run() {
                        StoreDetailView.this.requestStoreMenuApi();
                    }
                }, null);
            }
        });
    }

    /* access modifiers changed from: private */
    public void onStoreCustomDimention() {
        if (this.mModel != null) {
            Map<Integer, String> dimensions = new HashMap<>();
            dimensions.put(Integer.valueOf(1), this.mModel.partner_name1 == null ? "" : this.mModel.partner_name1);
            dimensions.put(Integer.valueOf(2), this.mModel.service_type_name == null ? "" : this.mModel.service_type_name);
            dimensions.put(Integer.valueOf(3), this.mModel.dongName == null ? "" : this.mModel.dongName);
            dimensions.put(Integer.valueOf(8), "");
            dimensions.put(Integer.valueOf(14), "");
            dimensions.put(Integer.valueOf(15), "");
            GAEvent.onGACustomDimensions((BaseActivity) getContext(), getContext().getString(R.string.ga_store_detail), dimensions);
        }
    }
}