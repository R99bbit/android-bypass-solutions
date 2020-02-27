package com.nuvent.shareat.fragment;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.graphics.drawable.BitmapDrawable;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Environment;
import android.os.Parcelable;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.view.ViewPager;
import android.support.v4.widget.SwipeRefreshLayout.OnRefreshListener;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnTouchListener;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.TextView;
import com.crashlytics.android.answers.Answers;
import com.crashlytics.android.answers.ShareEvent;
import com.facebook.internal.FacebookRequestErrorClassification;
import com.igaworks.adbrix.IgawAdbrix;
import com.kakao.auth.Session;
import com.kakao.kakaolink.AppActionBuilder;
import com.kakao.kakaolink.AppActionInfoBuilder;
import com.kakao.kakaolink.KakaoLink;
import com.kakao.kakaolink.KakaoTalkLinkMessageBuilder;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.kakao.util.KakaoParameterException;
import com.naver.maps.map.MapFragment;
import com.nostra13.universalimageloader.core.ImageLoader;
import com.nostra13.universalimageloader.core.assist.FailReason;
import com.nostra13.universalimageloader.core.listener.ImageLoadingListener;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.common.InstagramShareActivity;
import com.nuvent.shareat.activity.common.NMapActivity;
import com.nuvent.shareat.activity.common.ViewerActivity;
import com.nuvent.shareat.activity.crop.CropActivity;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.activity.main.ReviewActivity;
import com.nuvent.shareat.adapter.store.StoreDetailListAdapter;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.store.ReviewCountApi;
import com.nuvent.shareat.api.store.StoreApi;
import com.nuvent.shareat.api.store.StoreFavoriteApi;
import com.nuvent.shareat.api.store.StoreImageApi;
import com.nuvent.shareat.api.store.StoreInstaApi;
import com.nuvent.shareat.api.store.StoreNaverBlogApi;
import com.nuvent.shareat.api.store.StoreReviewListApi;
import com.nuvent.shareat.dialog.ReviewTypeDialog;
import com.nuvent.shareat.dialog.ReviewTypeDialog.DialogClickListener;
import com.nuvent.shareat.event.CardSlideEvent;
import com.nuvent.shareat.event.CardUpdateEvent;
import com.nuvent.shareat.event.PaySuccessEvent;
import com.nuvent.shareat.event.ReviewCountUpdateEvent;
import com.nuvent.shareat.event.ReviewEvent;
import com.nuvent.shareat.event.StoreSelectedEvent;
import com.nuvent.shareat.event.TabClickEvent;
import com.nuvent.shareat.manager.app.ParamManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.InstagramModel;
import com.nuvent.shareat.model.ReviewTagModel;
import com.nuvent.shareat.model.store.ReviewCountModel;
import com.nuvent.shareat.model.store.ReviewModel;
import com.nuvent.shareat.model.store.StoreBlogModel;
import com.nuvent.shareat.model.store.StoreDetailModel;
import com.nuvent.shareat.model.store.StoreDetailResultModel;
import com.nuvent.shareat.model.store.StoreImageModel;
import com.nuvent.shareat.model.store.StoreImageResultModel;
import com.nuvent.shareat.model.store.StoreInstaModel;
import com.nuvent.shareat.model.store.StoreInstaResultModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.model.store.StoreResultBlogModel;
import com.nuvent.shareat.model.store.StoreReviewResultModel;
import com.nuvent.shareat.util.ExternalApp;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.StoryLink;
import com.nuvent.shareat.util.crop.CropImageIntentBuilder;
import com.nuvent.shareat.widget.view.CustomSwipeToRefresh;
import com.nuvent.shareat.widget.view.StoreDetailView;
import com.nuvent.shareat.widget.view.StoreDetailView.ImagePagerAdapter.ImageViewerClickListener;
import de.greenrobot.event.EventBus;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import net.xenix.util.ImageDisplay;

public class StoreDetailFragment extends Fragment implements OnTouchListener, OnClickListener {
    private static final int REQUEST_CODE_MAP = 1;
    private static final int REVIEW_ITEM_LIMIT_COUNT = 10;
    public static final String SUB_TAB_NAME_IMAGE_LIST = "imagelist";
    public static final String SUB_TAB_NAME_MAP = "map";
    public static final String SUB_TAB_NAME_MENU = "menu";
    public static final String SUB_TAB_NAME_MENU_DETAIL = "menudetail";
    public static final String SUB_TAB_NAME_PAYMENT = "payment";
    public static final String SUB_TAB_NAME_REVIEW = "review";
    public static final String SUB_TAB_NAME_REVIEW_WRITE = "reviewwrite";
    private final long THRESHOLD = 50;
    /* access modifiers changed from: private */
    public boolean isFirstLoad = false;
    /* access modifiers changed from: private */
    public boolean isLoadComplete;
    /* access modifiers changed from: private */
    public boolean isReviewTop;
    /* access modifiers changed from: private */
    public boolean isScrollBottom;
    /* access modifiers changed from: private */
    public boolean isScrollMoveUp = false;
    private long lastTime;
    /* access modifiers changed from: private */
    public StoreDetailListAdapter mAdapter;
    /* access modifiers changed from: private */
    public boolean mApiRequesting;
    private int mDownY;
    /* access modifiers changed from: private */
    public StoreDetailView mHeaderView;
    /* access modifiers changed from: private */
    public ArrayList<StoreImageModel> mImageModels;
    /* access modifiers changed from: private */
    public int mListType;
    /* access modifiers changed from: private */
    public ListView mListView;
    /* access modifiers changed from: private */
    public View mLoadingView;
    private int mMoveY;
    /* access modifiers changed from: private */
    public int mPage = 1;
    /* access modifiers changed from: private */
    public PopupWindow mPopupWindow;
    /* access modifiers changed from: private */
    public CustomSwipeToRefresh mRefreshLayout;
    /* access modifiers changed from: private */
    public ArrayList<ReviewModel> mReviewModels;
    /* access modifiers changed from: private */
    public View mRootView;
    /* access modifiers changed from: private */
    public Bundle mSchemeParams;
    /* access modifiers changed from: private */
    public String mSchemeSubTabName;
    /* access modifiers changed from: private */
    public ArrayList<StoreBlogModel> mStoreBlogModels;
    /* access modifiers changed from: private */
    public StoreDetailModel mStoreDetailModel;
    /* access modifiers changed from: private */
    public ArrayList<StoreInstaModel> mStoreInstaModels;
    /* access modifiers changed from: private */
    public StoreModel mStoreModel;
    /* access modifiers changed from: private */
    public LinearLayout mTabLayout;
    /* access modifiers changed from: private */
    public Typeface mTagTypeface;
    /* access modifiers changed from: private */
    public long sTime;

    static class NameAscCompare implements Comparator<Intent> {
        NameAscCompare() {
        }

        public int compare(Intent lhs, Intent rhs) {
            return lhs.getStringExtra("name").compareTo(rhs.getStringExtra("name"));
        }
    }

    public void setSchemeParams(Bundle value) {
        this.mSchemeParams = value;
    }

    public void setSubTab(String name) {
        this.mSchemeSubTabName = name;
    }

    public void postSubTab() {
        if (this.mSchemeSubTabName != null) {
            this.mListView.postDelayed(new Runnable() {
                public void run() {
                    if (StoreDetailFragment.this.mSchemeSubTabName.equals(StoreDetailFragment.SUB_TAB_NAME_MAP)) {
                        StoreDetailFragment.this.mHeaderView.findViewById(R.id.nmapClickView).performClick();
                    } else if (StoreDetailFragment.this.mSchemeSubTabName.equals(StoreDetailFragment.SUB_TAB_NAME_REVIEW)) {
                        if (StoreDetailFragment.this.mImageModels != null) {
                            FragmentManager fm = StoreDetailFragment.this.getActivity().getSupportFragmentManager();
                            MapFragment mMapView = (MapFragment) fm.findFragmentById(R.id.mapViewLayout);
                            if (mMapView != null) {
                                fm.beginTransaction().remove(mMapView).commit();
                                StoreDetailFragment.this.isScrollMoveUp = true;
                            }
                        }
                        StoreDetailFragment.this.mListView.setSelectionFromTop(1, StoreDetailFragment.this.getResources().getDimensionPixelOffset(R.dimen.DETAIL_TAB_HEIGHT) + StoreDetailFragment.this.getResources().getDimensionPixelSize(R.dimen.TAB_MARGIN));
                    } else if (StoreDetailFragment.this.mSchemeSubTabName.equals(StoreDetailFragment.SUB_TAB_NAME_MENU)) {
                        GAEvent.onGaEvent((Activity) StoreDetailFragment.this.getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_move, (int) R.string.ga_store_detail_menu);
                        StoreDetailFragment.this.onStoreCustomDimention();
                        StoreDetailFragment.this.mListView.setSelectionFromTop(0, -(StoreDetailFragment.this.mHeaderView.findViewById(R.id.menu_layout).getTop() - StoreDetailFragment.this.getResources().getDimensionPixelOffset(R.dimen.STORE_MENU_SCROLL_MARGIN)));
                    } else if (!StoreDetailFragment.this.mSchemeSubTabName.equals(StoreDetailFragment.SUB_TAB_NAME_MENU_DETAIL)) {
                        if (StoreDetailFragment.this.mSchemeSubTabName.equals(StoreDetailFragment.SUB_TAB_NAME_REVIEW_WRITE)) {
                            if (!StoreDetailFragment.this.mStoreDetailModel.chk_review.booleanValue()) {
                                StoreDetailFragment.this.showReviewPopup();
                                StoreDetailFragment.this.mSchemeSubTabName = null;
                                return;
                            }
                            StoreDetailFragment.this.showReviewTypePopup();
                        } else if (StoreDetailFragment.this.mSchemeSubTabName.equals(StoreDetailFragment.SUB_TAB_NAME_PAYMENT)) {
                            StoreDetailFragment.this.mHeaderView.findViewById(R.id.payButton).performClick();
                        } else if (StoreDetailFragment.this.mSchemeSubTabName.equals(StoreDetailFragment.SUB_TAB_NAME_IMAGE_LIST)) {
                            String type = null;
                            if (StoreDetailFragment.this.mSchemeParams != null) {
                                type = StoreDetailFragment.this.mSchemeParams.getString(KakaoTalkLinkProtocol.ACTION_TYPE, "main");
                            }
                            if (type == null || type.equals("main")) {
                                Intent intent = new Intent(StoreDetailFragment.this.getActivity(), ViewerActivity.class);
                                intent.putExtra("model", StoreDetailFragment.this.mStoreDetailModel);
                                intent.putExtra("index", 0);
                                ((BaseActivity) StoreDetailFragment.this.getActivity()).pushActivity(intent);
                            } else if (type.equals(StoreDetailFragment.SUB_TAB_NAME_REVIEW)) {
                                String partnerSno = StoreDetailFragment.this.mSchemeParams.getString("partner_sno", "");
                                String feedSno = StoreDetailFragment.this.mSchemeParams.getString("review_sno", "");
                                if (partnerSno != null && !partnerSno.isEmpty() && feedSno != null && !feedSno.isEmpty()) {
                                    Intent intent2 = new Intent(StoreDetailFragment.this.getActivity(), ViewerActivity.class);
                                    intent2.putExtra("partnerSno", partnerSno);
                                    intent2.putExtra("feedSno", feedSno);
                                    intent2.putExtra("index", 0);
                                    ((BaseActivity) StoreDetailFragment.this.getActivity()).pushActivity(intent2);
                                } else {
                                    return;
                                }
                            }
                        }
                    }
                    StoreDetailFragment.this.mSchemeSubTabName = null;
                }
            }, 500);
        }
    }

    public void hideGuideView() {
        if (this.mPopupWindow != null) {
            this.mPopupWindow.dismiss();
        }
    }

    private void showGuideView() {
        if (this.mStoreModel != null && getScrollY() <= 0) {
            try {
                if (((ViewPager) ((MainActivity) getActivity()).findViewById(R.id.viewPager)).getCurrentItem() == 0) {
                    return;
                }
            } catch (ClassCastException e) {
                e.printStackTrace();
            }
            View guideView = View.inflate(getActivity(), R.layout.popup_new_sns, null);
            this.mPopupWindow = new PopupWindow(guideView, -2, -2);
            this.mPopupWindow.setBackgroundDrawable(new BitmapDrawable());
            guideView.findViewById(R.id.closeButton).setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    StoreDetailFragment.this.mPopupWindow.dismiss();
                }
            });
            guideView.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    StoreDetailFragment.this.onStoreCustomDimention();
                    GAEvent.onGaEvent((Activity) StoreDetailFragment.this.getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_move, (int) R.string.ga_store_detail_review);
                    if (StoreDetailFragment.this.mAdapter.getCount() > 0) {
                        StoreDetailFragment.this.mListView.setSelectionFromTop(1, StoreDetailFragment.this.mHeaderView.findViewById(R.id.headerTabLayout).getHeight());
                    }
                    StoreDetailFragment.this.mPopupWindow.dismiss();
                }
            });
            int viewY = 0;
            if (VERSION.SDK_INT >= 19) {
                viewY = 0 + ((BaseActivity) getActivity()).getStatusBarHeight();
            }
            try {
                this.mPopupWindow.showAtLocation(this.mHeaderView, 0, ((this.mHeaderView.getWidth() / 2) - (getActivity().getResources().getDimensionPixelOffset(R.dimen.STORE_REVIEW_POPUP_WIDTH) / 2)) - getActivity().getResources().getDimensionPixelOffset(R.dimen.STORE_REVIEW_POPUP_MARGIN), viewY + ((int) (this.mHeaderView.findViewById(R.id.navigationButtonLayout).getY() + ((float) this.mHeaderView.findViewById(R.id.navigationButtonLayout).getHeight()) + ((float) getActivity().getResources().getDimensionPixelOffset(R.dimen.ACTIONBAR_HEIGHT)))));
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    public void onEventMainThread(CardSlideEvent event) {
        if (event.isOpen()) {
            hideGuideView();
        }
    }

    public void onEventMainThread(ReviewCountUpdateEvent event) {
        if (this.mStoreModel != null) {
            requestReviewCountApi(this.mStoreModel.getPartnerSno());
            requestisReviewWriteApi();
        }
    }

    public void onEventMainThread(CardUpdateEvent event) {
        ((MainActionBarActivity) getActivity()).setCardInfo();
    }

    public void onEventMainThread(ReviewEvent event) {
        if (((MainActionBarActivity) getActivity()).isOpenCardView()) {
            ((MainActionBarActivity) getActivity()).clearBillingView();
        }
        requestReviewCountApi(this.mStoreModel.getPartnerSno());
        if (this.mListType == 1) {
            clearData();
            this.mListView.removeFooterView(this.mLoadingView);
            selectTab(this.mRootView, this.mRootView.findViewById(R.id.instaTabLayout));
            selectTab(this.mRootView, this.mRootView.findViewById(R.id.reviewTabLayout));
            requestReviewListApi(this.mStoreModel.getPartnerSno(), true);
            return;
        }
        clearData();
        this.mListType = 1;
        requestReviewListApi(this.mStoreModel.getPartnerSno(), true);
        selectTab(this.mRootView, this.mRootView.findViewById(R.id.reviewTabLayout));
        this.mHeaderView.setTabData(this.mListType);
    }

    public void onEventMainThread(TabClickEvent event) {
        if (this.mListType != event.getmType() && !this.mApiRequesting && event != null) {
            switch (event.getmType()) {
                case 1:
                    clearData();
                    this.mListType = 1;
                    requestReviewListApi(this.mStoreModel.getPartnerSno(), false);
                    selectTab(this.mRootView, this.mRootView.findViewById(R.id.reviewTabLayout));
                    break;
                case 2:
                    clearData();
                    this.mListType = 2;
                    requestInstagramListApi(this.mStoreModel.getPartnerSno());
                    selectTab(this.mRootView, this.mRootView.findViewById(R.id.instaTabLayout));
                    break;
                case 3:
                    clearData();
                    this.mListType = 3;
                    requestBlogListApi(this.mStoreModel.getPartnerSno());
                    selectTab(this.mRootView, this.mRootView.findViewById(R.id.blogTabLayout));
                    break;
            }
            this.mHeaderView.setTabData(this.mListType);
        }
    }

    public void onEventMainThread(PaySuccessEvent event) {
        this.mListView.setSelectionFromTop(0, 0);
        double lat = 37.4986366d;
        double lng = 127.027021d;
        if (ShareatApp.getInstance().getGpsManager() != null) {
            lat = ShareatApp.getInstance().getGpsManager().getLatitude();
            lng = ShareatApp.getInstance().getGpsManager().getLongitude();
        }
        postStoreData(String.valueOf(lng), String.valueOf(lat));
        if (true == event.isDeliveryCardViewFinish) {
        }
    }

    public boolean isSetModel() {
        return this.mStoreModel != null;
    }

    public void setStoreModel(StoreModel model) {
        if (model != null) {
            this.isFirstLoad = false;
            this.mStoreModel = model;
            Map<Integer, String> dimensions = new HashMap<>();
            dimensions.put(Integer.valueOf(13), getResources().getString((ShareatApp.getInstance().getGpsManager() == null || !ShareatApp.getInstance().getGpsManager().isGetLocation()) ? R.string.ga_gps_off : R.string.ga_gps_on));
            GAEvent.onGACustomDimensions(getActivity(), getString(R.string.ga_store_detail), dimensions);
            updateFragmentView();
        }
    }

    private void updateFragmentView() {
        if (this.mStoreModel != null && getActivity() != null) {
            this.isFirstLoad = true;
            ((MainActionBarActivity) getActivity()).animateCardLayout(true);
            ((BaseActivity) getActivity()).showCircleDialog(true);
            ((MainActionBarActivity) getActivity()).showFavoriteButton(false);
            this.mPage = 1;
            clearData();
            this.mListView.setAdapter(this.mAdapter);
            this.mListType = 1;
            this.mListView.post(new Runnable() {
                public void run() {
                    StoreDetailFragment.this.selectTab(StoreDetailFragment.this.mRootView, (LinearLayout) StoreDetailFragment.this.mRootView.findViewById(R.id.reviewTabLayout));
                    StoreDetailFragment.this.mHeaderView.setTabData(1);
                }
            });
            this.mAdapter.setPartnerSno(this.mStoreModel.getPartnerSno());
            this.sTime = System.currentTimeMillis();
        }
    }

    public void postStoreData(String userX, String userY) {
        if (this.mStoreModel != null && getActivity() != null) {
            GAEvent.onGAScreenView(getActivity(), R.string.ga_store_detail);
            requestDetailApi(this.mStoreModel.getPartnerSno(), userX, userY);
            this.mPage = 1;
            clearData();
            this.mListType = 1;
            selectTab(this.mRootView, this.mRootView.findViewById(R.id.reviewTabLayout));
            this.mHeaderView.setTabData(this.mListType);
        }
    }

    public void setReviewTop(boolean value) {
        this.isReviewTop = value;
    }

    public void clearPopupWindow() {
        if (this.mPopupWindow != null) {
            this.mPopupWindow.dismiss();
        }
    }

    public void clearHeader() {
        if (this.mPopupWindow != null) {
            this.mPopupWindow.dismiss();
        }
        clearData();
        this.mListView.removeHeaderView(this.mHeaderView);
        setAdapter();
    }

    public void clearData() {
        this.mPage = 1;
        this.mApiRequesting = false;
        this.isLoadComplete = false;
        if (this.mReviewModels != null) {
            this.mReviewModels.clear();
        }
        if (this.mStoreBlogModels != null) {
            this.mStoreBlogModels.clear();
        }
        if (this.mStoreInstaModels != null) {
            this.mStoreInstaModels.clear();
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (1 == requestCode) {
        }
        if (5858 == requestCode) {
            getActivity();
            if (-1 == resultCode) {
                InstagramModel model = new InstagramModel(this.mStoreDetailModel.getIntroduce(), this.mStoreDetailModel.getPartner_name1(), String.valueOf(this.mStoreDetailModel.getPartner_sno()), Environment.getExternalStorageDirectory() + ImageDisplay.SHARE_FILE_NAME);
                Intent intent = new Intent(getActivity(), InstagramShareActivity.class);
                intent.putExtra("model", model);
                ((BaseActivity) getActivity()).pushActivity(intent);
            }
        }
        ((BaseActivity) getActivity()).showCircleDialog(false);
    }

    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
    }

    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        if (savedInstanceState != null && savedInstanceState.containsKey("MODEL")) {
            this.mStoreModel = (StoreModel) savedInstanceState.getSerializable("MODEL");
            updateFragmentView();
            postStoreData(String.valueOf(127.027021d), String.valueOf(37.4986366d));
        }
    }

    public void onSaveInstanceState(Bundle outState) {
        outState.putSerializable("MODEL", this.mStoreModel);
        super.onSaveInstanceState(outState);
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    public void onStart() {
        super.onStart();
    }

    public void onResume() {
        super.onResume();
    }

    public void onPause() {
        super.onPause();
    }

    public void onStop() {
        super.onStop();
    }

    public void onDestroy() {
        super.onDestroy();
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        EventBus.getDefault().register(this);
        this.mRootView = inflater.inflate(R.layout.fragment_store_detail, null);
        this.mReviewModels = new ArrayList<>();
        this.mStoreBlogModels = new ArrayList<>();
        this.mStoreInstaModels = new ArrayList<>();
        this.mListType = 1;
        this.mLoadingView = View.inflate(getActivity(), R.layout.footer_list_loading, null);
        this.mRefreshLayout = (CustomSwipeToRefresh) this.mRootView.findViewById(R.id.swipeRefreshLayout);
        this.mListView = (ListView) this.mRootView.findViewById(R.id.listView);
        this.mListView.setOnTouchListener(this);
        this.mTagTypeface = Typeface.createFromAsset(getActivity().getAssets(), "NanumBarunGothicBold.ttf");
        setAdapter();
        this.mRefreshLayout.setOnRefreshListener(new OnRefreshListener() {
            public void onRefresh() {
                double lat = 37.4986366d;
                double lng = 127.027021d;
                if (ShareatApp.getInstance().getGpsManager() != null) {
                    lat = ShareatApp.getInstance().getGpsManager().getLatitude();
                    lng = ShareatApp.getInstance().getGpsManager().getLongitude();
                }
                StoreDetailFragment.this.postStoreData(String.valueOf(lng), String.valueOf(lat));
            }
        });
        this.mRefreshLayout.setColorSchemeResources(R.color.main_list_pay_cnt_color, R.color.green, R.color.blue, R.color.yellow);
        LinearLayout reviewTabLayout = (LinearLayout) this.mRootView.findViewById(R.id.reviewTabLayout);
        reviewTabLayout.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreDetailFragment.this.onStoreCustomDimention();
                GAEvent.onGaEvent((Activity) StoreDetailFragment.this.getActivity(), (int) R.string.ga_store_detail, (int) R.string.ga_ev_click, (int) R.string.StoreDetail_Review_Tab);
                if (!StoreDetailFragment.this.mApiRequesting) {
                    StoreDetailFragment.this.mPage = 1;
                    StoreDetailFragment.this.clearData();
                    StoreDetailFragment.this.mListType = 1;
                    StoreDetailFragment.this.requestReviewListApi(StoreDetailFragment.this.mStoreModel.getPartnerSno(), false);
                    StoreDetailFragment.this.selectTab(StoreDetailFragment.this.mRootView, v);
                    StoreDetailFragment.this.mHeaderView.setTabData(StoreDetailFragment.this.mListType);
                }
            }
        });
        ((LinearLayout) this.mRootView.findViewById(R.id.instaTabLayout)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreDetailFragment.this.onStoreCustomDimention();
                GAEvent.onGaEvent((Activity) StoreDetailFragment.this.getActivity(), (int) R.string.ga_store_detail, (int) R.string.ga_ev_click, (int) R.string.StoreDetail_Insta_Tab);
                if (!StoreDetailFragment.this.mApiRequesting) {
                    StoreDetailFragment.this.selectTab(StoreDetailFragment.this.mRootView, v);
                    StoreDetailFragment.this.clearData();
                    StoreDetailFragment.this.mListType = 2;
                    StoreDetailFragment.this.requestInstagramListApi(StoreDetailFragment.this.mStoreModel.getPartnerSno());
                    StoreDetailFragment.this.selectTab(StoreDetailFragment.this.mRootView, v);
                    StoreDetailFragment.this.mHeaderView.setTabData(StoreDetailFragment.this.mListType);
                }
            }
        });
        ((LinearLayout) this.mRootView.findViewById(R.id.blogTabLayout)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreDetailFragment.this.onStoreCustomDimention();
                GAEvent.onGaEvent((Activity) StoreDetailFragment.this.getActivity(), (int) R.string.ga_store_detail, (int) R.string.ga_ev_click, (int) R.string.StoreDetail_Blog_Tab);
                if (!StoreDetailFragment.this.mApiRequesting) {
                    StoreDetailFragment.this.mPage = 1;
                    StoreDetailFragment.this.clearData();
                    StoreDetailFragment.this.mListType = 3;
                    StoreDetailFragment.this.requestBlogListApi(StoreDetailFragment.this.mStoreModel.getPartnerSno());
                    StoreDetailFragment.this.selectTab(StoreDetailFragment.this.mRootView, v);
                    StoreDetailFragment.this.mHeaderView.setTabData(StoreDetailFragment.this.mListType);
                }
            }
        });
        this.mTabLayout = (LinearLayout) this.mRootView.findViewById(R.id.tabLayout);
        selectTab(this.mRootView, reviewTabLayout);
        this.mHeaderView.setTabData(this.mListType);
        return this.mRootView;
    }

    /* access modifiers changed from: private */
    public void selectTab(View view, View selectView) {
        ((LinearLayout) view.findViewById(R.id.reviewTabLayout)).setSelected(false);
        ((LinearLayout) view.findViewById(R.id.instaTabLayout)).setSelected(false);
        ((LinearLayout) view.findViewById(R.id.blogTabLayout)).setSelected(false);
        selectView.setSelected(true);
    }

    public void onDestroyView() {
        super.onDestroyView();
        EventBus.getDefault().unregister(this);
    }

    public boolean onTouch(View v, MotionEvent event) {
        if (event.getActionIndex() <= 1) {
            long now = System.currentTimeMillis();
            if (this.lastTime <= -1 || now - this.lastTime >= 50) {
                this.lastTime = now;
                switch (event.getActionMasked()) {
                    case 0:
                    case 5:
                        this.mDownY = (int) event.getRawY();
                        break;
                    case 2:
                        this.mMoveY = (int) event.getRawY();
                        int movePos = this.mMoveY - this.mDownY;
                        if (movePos >= 0 || this.isScrollBottom) {
                            if (movePos >= 0) {
                                ((MainActionBarActivity) getActivity()).animateCardLayout(true);
                                break;
                            }
                        } else {
                            ((MainActionBarActivity) getActivity()).animateCardLayout(false);
                            break;
                        }
                        break;
                }
            }
        }
        return false;
    }

    private void setHeaderView() {
        this.mHeaderView = new StoreDetailView(getActivity());
        this.mHeaderView.findViewById(R.id.payButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.mapButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.reviewButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.menuButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.callButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.kasButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.facebookButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.instaButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.smsButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.moreShareButton).setOnClickListener(this);
        this.mHeaderView.findViewById(R.id.writeReviewButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (!SessionManager.getInstance().hasSession()) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showLoginDialog();
                } else if (!StoreDetailFragment.this.mStoreDetailModel.chk_review.booleanValue()) {
                    StoreDetailFragment.this.showReviewPopup();
                } else {
                    StoreDetailFragment.this.showReviewTypePopup();
                }
            }
        });
        setMapView();
    }

    /* access modifiers changed from: private */
    public void showReviewTypePopup() {
        GAEvent.onGAScreenView(getActivity(), R.string.ga_review_popup);
        ReviewTypeDialog dialog = new ReviewTypeDialog(getActivity());
        dialog.setOnDialogClickListener(new DialogClickListener() {
            public void onClickNext(ArrayList<ReviewTagModel> tags) {
                StoreDetailFragment.this.onStoreCustomDimention();
                GAEvent.onGaEvent((Activity) StoreDetailFragment.this.getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_review_write, (int) R.string.ga_store_detail_review_write);
                Intent intent = new Intent(StoreDetailFragment.this.getActivity(), ReviewActivity.class);
                intent.putExtra("partnerSno", StoreDetailFragment.this.mStoreModel.getPartnerSno());
                intent.putExtra("tags", tags);
                ((BaseActivity) StoreDetailFragment.this.getActivity()).pushActivity(intent);
            }
        });
        dialog.show();
    }

    private void setMapView() {
        ((ViewGroup) this.mHeaderView.findViewById(R.id.mapViewLayout)).removeAllViews();
        this.mHeaderView.findViewById(R.id.nmapClickView).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreDetailFragment.this.onStoreCustomDimention();
                GAEvent.onGaEvent((Activity) StoreDetailFragment.this.getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_map, (int) R.string.ga_store_detail_map);
                Intent intent = new Intent(StoreDetailFragment.this.getActivity(), NMapActivity.class);
                intent.putExtra("model", StoreDetailFragment.this.mStoreDetailModel);
                StoreDetailFragment.this.startActivityForResult(intent, 1);
                StoreDetailFragment.this.getActivity().overridePendingTransition(R.anim.modal_animation, R.anim.scale_down);
            }
        });
    }

    private void setAdapter() {
        setHeaderView();
        this.mListView.addHeaderView(this.mHeaderView);
        this.mAdapter = new StoreDetailListAdapter(getActivity(), this.mTagTypeface);
        this.mListView.setAdapter(this.mAdapter);
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (StoreDetailFragment.this.getScrollY() > 0 && StoreDetailFragment.this.mPopupWindow != null) {
                    StoreDetailFragment.this.mPopupWindow.dismiss();
                }
                if (firstVisibleItem == 0) {
                    View c = StoreDetailFragment.this.mListView.getChildAt(0);
                    if (c != null) {
                        if ((-c.getTop()) + (c.getHeight() * firstVisibleItem) >= (StoreDetailFragment.this.mHeaderView.getHeight() - StoreDetailFragment.this.getResources().getDimensionPixelOffset(R.dimen.DETAIL_TAB_HEIGHT)) - StoreDetailFragment.this.getResources().getDimensionPixelSize(R.dimen.TAB_MARGIN)) {
                            StoreDetailFragment.this.mTabLayout.setVisibility(0);
                        } else {
                            StoreDetailFragment.this.mTabLayout.setVisibility(8);
                            if (StoreDetailFragment.this.mImageModels != null) {
                                FragmentManager fm = StoreDetailFragment.this.getActivity().getSupportFragmentManager();
                                if (((MapFragment) fm.findFragmentById(R.id.mapViewLayout)) == null) {
                                    MapFragment mMapView = MapFragment.newInstance();
                                    fm.beginTransaction().add((int) R.id.mapViewLayout, (Fragment) mMapView).commit();
                                    mMapView.getMapAsync(StoreDetailFragment.this.mHeaderView);
                                }
                            }
                        }
                    }
                } else {
                    StoreDetailFragment.this.mTabLayout.setVisibility(0);
                    if (StoreDetailFragment.this.mImageModels != null) {
                        FragmentManager fm2 = StoreDetailFragment.this.getActivity().getSupportFragmentManager();
                        MapFragment mMapView2 = (MapFragment) fm2.findFragmentById(R.id.mapViewLayout);
                        if (mMapView2 != null) {
                            fm2.beginTransaction().remove(mMapView2).commit();
                        }
                    }
                }
                if (!StoreDetailFragment.this.isLoadComplete || StoreDetailFragment.this.mAdapter == null || StoreDetailFragment.this.mAdapter.getCount() != 0 || StoreDetailFragment.this.mListView.getFooterViewsCount() != 0) {
                    if (StoreDetailFragment.this.getScrollY() != 0 && (!StoreDetailFragment.this.isLoadComplete || StoreDetailFragment.this.mAdapter == null || firstVisibleItem + visibleItemCount != totalItemCount || StoreDetailFragment.this.mListView.getFooterViewsCount() != 0)) {
                        StoreDetailFragment.this.isScrollBottom = false;
                    } else if (StoreDetailFragment.this.getActivity() != null) {
                        if (!(StoreDetailFragment.this.getActivity() instanceof MainActivity)) {
                            ((MainActionBarActivity) StoreDetailFragment.this.getActivity()).animateCardLayout(true);
                        } else if (4 != ((ViewPager) StoreDetailFragment.this.getActivity().findViewById(R.id.viewPager)).getCurrentItem() && true == StoreDetailFragment.this.getUserVisibleHint()) {
                            ((MainActionBarActivity) StoreDetailFragment.this.getActivity()).animateCardLayout(true);
                        }
                        StoreDetailFragment.this.isScrollBottom = true;
                    } else {
                        return;
                    }
                } else if (StoreDetailFragment.this.getScrollY() == 0 || StoreDetailFragment.this.getScrollY() > StoreDetailFragment.this.mHeaderView.getHeight() - StoreDetailFragment.this.mListView.getHeight()) {
                    ((MainActionBarActivity) StoreDetailFragment.this.getActivity()).animateCardLayout(true);
                    StoreDetailFragment.this.isScrollBottom = true;
                } else {
                    StoreDetailFragment.this.isScrollBottom = false;
                }
                if (StoreDetailFragment.this.mAdapter != null && StoreDetailFragment.this.mAdapter.getCount() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !StoreDetailFragment.this.mApiRequesting && StoreDetailFragment.this.mLoadingView.isShown()) {
                    switch (StoreDetailFragment.this.mListType) {
                        case 1:
                            StoreDetailFragment.this.requestReviewListApi(StoreDetailFragment.this.mStoreModel.getPartnerSno(), false);
                            return;
                        case 2:
                            StoreDetailFragment.this.requestInstagramListApi(StoreDetailFragment.this.mStoreModel.getPartnerSno());
                            return;
                        case 3:
                            StoreDetailFragment.this.requestBlogListApi(StoreDetailFragment.this.mStoreModel.getPartnerSno());
                            return;
                        default:
                            return;
                    }
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public int getScrollY() {
        if (this.mListView == null) {
            return 0;
        }
        View c = this.mListView.getChildAt(0);
        if (c == null) {
            return 0;
        }
        int firstVisiblePosition = this.mListView.getFirstVisiblePosition();
        int top = c.getTop();
        int headerHeight = 0;
        if (firstVisiblePosition >= 1 && this.mHeaderView != null) {
            headerHeight = this.mHeaderView.getHeight();
        }
        return (-top) + (c.getHeight() * firstVisiblePosition) + headerHeight;
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.callButton /*2131296408*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_tel, (int) R.string.ga_store_detail_phone);
                if (this.mStoreDetailModel != null && this.mStoreDetailModel.getCouponName() != null) {
                    onStoreCustomDimention();
                    startActivity(new Intent("android.intent.action.DIAL", Uri.parse("tel:" + this.mStoreDetailModel.getCallNumber())));
                    return;
                }
                return;
            case R.id.facebookButton /*2131296648*/:
            case R.id.instaButton /*2131296750*/:
            case R.id.kasButton /*2131296772*/:
            case R.id.moreShareButton /*2131296875*/:
            case R.id.smsButton /*2131297318*/:
                if (!SessionManager.getInstance().hasSession()) {
                    ((BaseActivity) getActivity()).showLoginDialog();
                    return;
                }
                onStoreCustomDimention();
                onClickShare(v.getId());
                return;
            case R.id.mapButton /*2131296816*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_move, (int) R.string.ga_store_detail_location);
                onStoreCustomDimention();
                this.mListView.setSelectionFromTop(0, -(this.mHeaderView.findViewById(R.id.addressLayout).getTop() - getResources().getDimensionPixelOffset(R.dimen.STORE_MENU_SCROLL_MARGIN)));
                return;
            case R.id.menuButton /*2131296826*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_move, (int) R.string.ga_store_detail_menu);
                onStoreCustomDimention();
                this.mListView.setSelectionFromTop(0, -(this.mHeaderView.findViewById(R.id.menuGroupLayout).getTop() - getResources().getDimensionPixelOffset(R.dimen.STORE_MENU_SCROLL_MARGIN)));
                return;
            case R.id.payButton /*2131297025*/:
                if (!SessionManager.getInstance().hasSession()) {
                    ((BaseActivity) getActivity()).showLoginDialog();
                    return;
                }
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_move, (int) R.string.ga_store_detail_quick_pay);
                onStoreCustomDimention();
                ((MainActionBarActivity) getActivity()).animateCardLayout(true);
                ((MainActionBarActivity) getActivity()).openCardView();
                return;
            case R.id.reviewButton /*2131297192*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_move, (int) R.string.ga_store_detail_review);
                onStoreCustomDimention();
                if (this.mAdapter.getCount() > 0) {
                    if (this.mImageModels != null) {
                        FragmentManager fm = getActivity().getSupportFragmentManager();
                        MapFragment mMapView = (MapFragment) fm.findFragmentById(R.id.mapViewLayout);
                        if (mMapView != null) {
                            fm.beginTransaction().remove(mMapView).commit();
                        }
                    }
                    this.mListView.setSelectionFromTop(0, -this.mHeaderView.findViewById(R.id.writeReviewButtonLayout).getBottom());
                    return;
                }
                return;
            default:
                return;
        }
    }

    private void onClickShare(int resourceId) {
        switch (resourceId) {
            case R.id.facebookButton /*2131296648*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_share, (int) R.string.ga_store_detail_facebook);
                Intent intent = sharedToFacebook();
                if (!ExternalApp.onInstallApp(getActivity(), (int) R.string.FACEBOOK_INSTALL_CONFIRM_MSG, intent, (String) ExternalApp.FACEBOOK)) {
                    getActivity().startActivity(intent);
                    return;
                }
                return;
            case R.id.instaButton /*2131296750*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_share, (int) R.string.ga_store_detail_instagram);
                shareToInstagram();
                return;
            case R.id.kakaoButton /*2131296767*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_share, (int) R.string.ga_store_detail_kakaotalk);
                String shareUrl = String.format(ApiUrl.SHARE_URL, new Object[]{Integer.valueOf(this.mStoreDetailModel.getPartner_sno()), "kakaotalk"});
                String shareText = getString(R.string.SHARE_MESSAGE_TITLE_FORMAT, this.mStoreDetailModel.getPartner_name1(), this.mStoreDetailModel.getDongName()) + "\n" + this.mStoreDetailModel.shareMsg();
                try {
                    KakaoLink kakaoLink = KakaoLink.getKakaoLink(getActivity());
                    KakaoTalkLinkMessageBuilder messageBuilder = kakaoLink.createKakaoTalkLinkMessageBuilder();
                    messageBuilder.addText(shareText).addImage(this.mStoreDetailModel.getImg_path(), ImageDisplay.THUMBNAIL_IMAGE_SIZE, 382).addWebLink(shareUrl, shareUrl).addAppButton(getString(R.string.SHARE_SHOW_FORMAT, getString(R.string.app_name)), new AppActionBuilder().addActionInfo(AppActionInfoBuilder.createAndroidActionInfoBuilder().setExecuteParam("store=" + this.mStoreDetailModel.toLink()).setMarketParam("referrer=utm_source%3Dkakaolink%26utm_medium%3Dapp_android%26utm_campaign%3Dshare").build()).addActionInfo(AppActionInfoBuilder.createiOSActionInfoBuilder().setExecuteParam("store=" + this.mStoreDetailModel.toLink()).build()).build());
                    kakaoLink.sendMessage(messageBuilder.build(), getActivity());
                    Answers.getInstance().logShare(new ShareEvent().putMethod(Session.REDIRECT_URL_PREFIX).putContentName(this.mStoreDetailModel.getPartner_name1()).putContentType("kakaotalk"));
                    IgawAdbrix.retention("share", "kakaotalk");
                    return;
                } catch (KakaoParameterException e) {
                    e.printStackTrace();
                    return;
                }
            case R.id.kasButton /*2131296772*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_share, (int) R.string.ga_store_detail_kakaostory);
                Intent intent2 = sharedtToKakaoStory();
                if (!ExternalApp.onInstallApp(getActivity(), (int) R.string.KAS_INSTALL_CONFIRM_MSG, intent2, (String) ExternalApp.KAKAOSTORY)) {
                    getActivity().startActivity(intent2);
                    return;
                }
                return;
            case R.id.moreShareButton /*2131296875*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_share, (int) R.string.ga_store_detail_more);
                shareToOther();
                return;
            case R.id.smsButton /*2131297318*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_share, (int) R.string.ga_store_detail_sms);
                String shareText2 = getString(R.string.SHARE_MESSAGE_SMS_TITLE_FORMAT, this.mStoreDetailModel.getPartner_name1(), this.mStoreDetailModel.getDongName()) + "\n" + String.format(ApiUrl.SHARE_URL, new Object[]{Integer.valueOf(this.mStoreDetailModel.getPartner_sno()), "sms"});
                Answers.getInstance().logShare(new ShareEvent().putMethod("sms").putContentName(this.mStoreDetailModel.getPartner_name1()).putContentType("sms"));
                IgawAdbrix.retention("share", "sms");
                Intent intent3 = new Intent("android.intent.action.SENDTO");
                intent3.setData(Uri.parse("sms:"));
                intent3.putExtra("sms_body", shareText2);
                startActivity(intent3);
                return;
            default:
                return;
        }
    }

    /* access modifiers changed from: private */
    public void showReviewPopup() {
        if (getActivity() != null && this.mHeaderView.findViewById(R.id.reviewPopup).getVisibility() != 0) {
            this.mHeaderView.findViewById(R.id.reviewPopup).startAnimation(AnimationUtils.loadAnimation(getActivity(), R.anim.fade_in));
            this.mHeaderView.findViewById(R.id.reviewPopup).setVisibility(0);
            this.mHeaderView.findViewById(R.id.reviewPopup).postDelayed(new Runnable() {
                public void run() {
                    if (StoreDetailFragment.this.mHeaderView != null && StoreDetailFragment.this.getActivity() != null) {
                        StoreDetailFragment.this.mHeaderView.findViewById(R.id.reviewPopup).startAnimation(AnimationUtils.loadAnimation(StoreDetailFragment.this.getActivity(), R.anim.fade_out));
                        StoreDetailFragment.this.mHeaderView.findViewById(R.id.reviewPopup).setVisibility(8);
                    }
                }
            }, 2000);
        }
    }

    private Intent sharedtToKakaoStory() {
        String shareUrl = String.format(ApiUrl.SHARE_URL, new Object[]{Integer.valueOf(this.mStoreDetailModel.getPartner_sno()), "kakaostory"});
        String shareTitle = getString(R.string.SHARE_MESSAGE_TITLE_FORMAT, this.mStoreDetailModel.getPartner_name1(), this.mStoreDetailModel.getDongName());
        String imageUrl = this.mStoreDetailModel.getImg_path().replace("save_", "");
        Map<String, Object> urlInfoAndroid = new Hashtable<>(1);
        urlInfoAndroid.put("title", shareTitle);
        urlInfoAndroid.put("desc", getString(R.string.SHARE_MESSAGE_KAS_DESC));
        urlInfoAndroid.put("imageurl", new String[]{imageUrl});
        String openKakaoLink = StoryLink.getLink(getActivity().getApplicationContext()).openKakaoLink(getActivity(), shareUrl, getActivity().getPackageName(), ShareatApp.getInstance().getAppVersionName(), getString(R.string.app_name), "UTF-8", urlInfoAndroid);
        Answers.getInstance().logShare(new ShareEvent().putMethod(Session.REDIRECT_URL_PREFIX).putContentName(this.mStoreDetailModel.getPartner_name1()).putContentType("kakao story"));
        IgawAdbrix.retention("share", "kakaostory");
        return new Intent("android.intent.action.SEND", Uri.parse(openKakaoLink));
    }

    private Intent sharedToFacebook() {
        String shareUrl = String.format(ApiUrl.SHARE_URL, new Object[]{Integer.valueOf(this.mStoreDetailModel.getPartner_sno()), "facebook"});
        Answers.getInstance().logShare(new ShareEvent().putMethod("facebook").putContentName(this.mStoreDetailModel.getPartner_name1()).putContentType("facebook"));
        IgawAdbrix.retention("share", "facebook");
        Intent intent = new Intent("android.intent.action.SEND");
        intent.setType("text/plain");
        intent.setPackage(ExternalApp.FACEBOOK);
        intent.putExtra("android.intent.extra.TEXT", shareUrl);
        return intent;
    }

    private void shareToOther() {
        String name = getString(R.string.app_name);
        StringBuilder subject = new StringBuilder();
        subject.append(name + "\n");
        subject.append(getString(R.string.SHARE_SHOW_FORMAT, this.mStoreDetailModel.getPartner_name1()));
        List<Intent> targets = new ArrayList<>();
        List<ResolveInfo> queryIntentActivities = getActivity().getPackageManager().queryIntentActivities(new Intent("android.intent.action.SEND").setType("text/plain"), 0);
        PackageManager packageManager = getActivity().getPackageManager();
        for (ResolveInfo candidate : queryIntentActivities) {
            String packageName = candidate.activityInfo.packageName;
            String appName = candidate.activityInfo.loadLabel(packageManager).toString();
            if (packageName.equals(ExternalApp.FACEBOOK)) {
                Intent sharedtToFacebook = sharedToFacebook();
                sharedtToFacebook.putExtra("name", appName);
                targets.add(sharedtToFacebook);
            } else if (packageName.equals(ExternalApp.KAKAOSTORY)) {
                Intent target = sharedtToKakaoStory();
                target.setPackage(packageName);
                target.putExtra("name", appName);
                targets.add(target);
            } else {
                Intent target2 = new Intent("android.intent.action.SEND");
                target2.setType("text/plain");
                Intent target3 = getOtherIntent(target2);
                target3.setPackage(packageName);
                target3.putExtra("name", appName);
                target3.setPackage(packageName);
                if (!"\ub4dc\ub77c\uc774\ube0c \ud074\ub9bd\ubcf4\ub4dc\uc5d0 \ubcf5\uc0ac".contains(appName)) {
                    targets.add(target3);
                }
            }
        }
        Collections.sort(targets, new NameAscCompare());
        Intent i = targets.remove(0);
        Answers.getInstance().logShare(new ShareEvent().putMethod("etc").putContentName(this.mStoreDetailModel.getPartner_name1()).putContentType(i.getPackage()));
        IgawAdbrix.retention("share", "etc");
        Intent chooser = Intent.createChooser(i, name + " \uacf5\uc720\ud558\uae30");
        chooser.putExtra("android.intent.extra.INITIAL_INTENTS", (Parcelable[]) targets.toArray(new Parcelable[0]));
        startActivity(chooser);
    }

    private void shareToInstagram() {
        if (this.mImageModels != null && this.mImageModels.size() != 0) {
            String url = this.mImageModels.get(0).getImg_path() != null ? this.mImageModels.get(0).getImg_path() : this.mImageModels.get(0).getImg_save();
            Answers.getInstance().logShare(new ShareEvent().putMethod("instagram").putContentName(this.mStoreDetailModel.getPartner_name1()).putContentType("instagram"));
            IgawAdbrix.retention("share", "instagram");
            ImageLoader.getInstance().loadImage(url.replace("save_", ""), new ImageLoadingListener() {
                public void onLoadingStarted(String imageUri, View view) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(true);
                }

                public void onLoadingFailed(String imageUri, View view, FailReason failReason) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }

                public void onLoadingComplete(String imageUri, View view, Bitmap loadedImage) {
                    int size = ImageDisplay.THUMBNAIL_IMAGE_SIZE;
                    ImageDisplay.getInstance();
                    Uri croppedImage = Uri.fromFile(new File(ImageDisplay.saveBitmapToPNG(loadedImage, "")));
                    if (loadedImage.getWidth() < 640 && loadedImage.getHeight() < 640) {
                        size = 306;
                    }
                    CropImageIntentBuilder cropImage = new CropImageIntentBuilder(size, size, croppedImage);
                    cropImage.setOutlineColor(-16537100);
                    cropImage.setScale(false);
                    cropImage.setScaleUpIfNeeded(false);
                    cropImage.setSourceImage(croppedImage);
                    StoreDetailFragment.this.getActivity().startActivityForResult(cropImage.getIntent(StoreDetailFragment.this.getActivity()), CropActivity.CROP_FROM_STORE_DETAIL);
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }

                public void onLoadingCancelled(String imageUri, View view) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }
            });
        }
    }

    private Intent getOtherIntent(Intent target) {
        target.putExtra("android.intent.extra.TEXT", getString(R.string.SHARE_MESSAGE_TITLE_FORMAT, this.mStoreDetailModel.getPartner_name1(), this.mStoreDetailModel.getDongName()) + "\n" + this.mStoreDetailModel.shareMsg() + "\n" + String.format(ApiUrl.SHARE_URL, new Object[]{Integer.valueOf(this.mStoreDetailModel.getPartner_sno()), FacebookRequestErrorClassification.KEY_OTHER}));
        return target;
    }

    /* access modifiers changed from: private */
    public void onStoreCustomDimention() {
        if (this.mStoreDetailModel != null) {
            Map<Integer, String> dimensions = new HashMap<>();
            dimensions.put(Integer.valueOf(1), this.mStoreDetailModel.partner_name1 == null ? "" : this.mStoreDetailModel.partner_name1);
            dimensions.put(Integer.valueOf(2), this.mStoreDetailModel.service_type_name == null ? "" : this.mStoreDetailModel.service_type_name);
            dimensions.put(Integer.valueOf(3), ParamManager.getInstance().getRecentSetModel().getAreaName());
            dimensions.put(Integer.valueOf(8), this.mStoreDetailModel.dongName == null ? "" : this.mStoreDetailModel.dongName);
            GAEvent.onGACustomDimensions(getActivity(), getString(R.string.ga_store_detail), dimensions);
        }
    }

    /* access modifiers changed from: private */
    public void requestDetailApi(final String partnerSno, final String userX, final String userY) {
        String parameter = String.format("?partner_sno=%s&user_X=%s&user_Y=%s", new Object[]{partnerSno, userX, userY});
        StoreApi request = new StoreApi(getActivity());
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                StoreDetailFragment.this.mStoreDetailModel = ((StoreDetailResultModel) result).getStore_detail();
                StoreDetailFragment.this.mStoreDetailModel.chk_review = Boolean.valueOf(false);
                StoreDetailFragment.this.mStoreModel.setFavorite(StoreDetailFragment.this.mStoreDetailModel.getFavoriteYn().booleanValue());
                ((MainActionBarActivity) StoreDetailFragment.this.getActivity()).setFavoriteButton(StoreDetailFragment.this.mStoreDetailModel.getFavoriteYn().booleanValue());
                ((MainActionBarActivity) StoreDetailFragment.this.getActivity()).showFavoriteButton(true);
                StoreDetailFragment.this.onStoreCustomDimention();
            }

            public void onFailure(Exception exception) {
                if (((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            StoreDetailFragment.this.requestDetailApi(partnerSno, userX, userY);
                        }
                    }, new Runnable() {
                        public void run() {
                            if (StoreDetailFragment.this.getActivity() instanceof MainActivity) {
                                StoreDetailFragment.this.getActivity().onBackPressed();
                            } else {
                                StoreDetailFragment.this.getActivity().finish();
                            }
                        }
                    });
                }
            }

            public void onFinish() {
                if (StoreDetailFragment.this.sTime != -1) {
                    r5 = R.string.app_storeDetail_loading_time;
                    GAEvent.onUserTimings(StoreDetailFragment.this.getActivity(), R.string.app_loading_time, System.currentTimeMillis() - StoreDetailFragment.this.sTime, R.string.app_storeDetail_loading_time, R.string.app_storeDetail_loading_time);
                    StoreDetailFragment.this.sTime = -1;
                }
                if (StoreDetailFragment.this.isFirstLoad) {
                    StoreDetailFragment.this.isFirstLoad = false;
                    EventBus.getDefault().post(new StoreSelectedEvent());
                }
                StoreDetailFragment.this.isLoadComplete = true;
                StoreDetailFragment.this.requestStoreImageApi();
                StoreDetailFragment.this.requestReviewListApi(StoreDetailFragment.this.mStoreModel.getPartnerSno(), StoreDetailFragment.this.isReviewTop);
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestStoreImageApi() {
        String params = String.format("?partner_sno=%s", new Object[]{this.mStoreModel.getPartnerSno()});
        StoreImageApi request = new StoreImageApi(getActivity());
        request.addGetParam(params);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                StoreImageResultModel model = (StoreImageResultModel) result;
                if (StoreDetailFragment.this.mImageModels == null) {
                    StoreDetailFragment.this.mImageModels = new ArrayList();
                }
                StoreDetailFragment.this.mImageModels.clear();
                StoreDetailFragment.this.mImageModels.addAll(model.getResult_list());
                FragmentManager fm = StoreDetailFragment.this.getActivity().getSupportFragmentManager();
                MapFragment mMapView = (MapFragment) fm.findFragmentById(R.id.mapViewLayout);
                if (mMapView != null) {
                    fm.beginTransaction().remove(mMapView).commit();
                }
                MapFragment mMapView2 = MapFragment.newInstance();
                fm.beginTransaction().add((int) R.id.mapViewLayout, (Fragment) mMapView2).commit();
                mMapView2.getMapAsync(StoreDetailFragment.this.mHeaderView);
                StoreDetailFragment.this.mHeaderView.setData(StoreDetailFragment.this.mStoreDetailModel, StoreDetailFragment.this.mImageModels, StoreDetailFragment.this.mTagTypeface);
                if (StoreDetailFragment.this.mHeaderView.getImagePagerAdapter() != null) {
                    StoreDetailFragment.this.mHeaderView.getImagePagerAdapter().addImageViewrClickListener(new ImageViewerClickListener() {
                        public void onViewerClick(int position, StoreDetailModel model) {
                            Intent intent = new Intent(StoreDetailFragment.this.getContext(), ViewerActivity.class);
                            intent.putExtra("model", model);
                            intent.putExtra("index", position);
                            StoreDetailFragment.this.startActivityForResult(intent, 1);
                            StoreDetailFragment.this.getActivity().overridePendingTransition(R.anim.slide_from_right, R.anim.slide_out_to_left);
                        }
                    });
                }
            }
        });
    }

    private void requestisReviewWriteApi() {
        String parameter = String.format("?partner_sno=%s&page=%d&view_cnt=%d", new Object[]{this.mStoreModel.getPartnerSno(), Integer.valueOf(1), Integer.valueOf(10)});
        StoreReviewListApi request = new StoreReviewListApi(getActivity());
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                if (((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }
                StoreDetailFragment.this.mStoreDetailModel.chk_review = Boolean.valueOf(((StoreReviewResultModel) result).isChkReview());
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestReviewListApi(String partnerSno, final boolean isTopScroll) {
        if (isAdded()) {
            this.mApiRequesting = true;
            String parameter = String.format("?partner_sno=%s&page=%d&view_cnt=%d", new Object[]{partnerSno, Integer.valueOf(this.mPage), Integer.valueOf(10)});
            StoreReviewListApi request = new StoreReviewListApi(getActivity());
            request.addGetParam(parameter);
            request.request(new RequestHandler() {
                public void onStart() {
                    if (StoreDetailFragment.this.mPage == 1 && ((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                        ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(true);
                    }
                }

                public void onResult(Object result) {
                    if (StoreDetailFragment.this.isAdded()) {
                        if (((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                            ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                        }
                        StoreReviewResultModel model = (StoreReviewResultModel) result;
                        StoreDetailFragment.this.mStoreDetailModel.chk_review = Boolean.valueOf(model.isChkReview());
                        if (model.getResult().equals("Y")) {
                            if (StoreDetailFragment.this.mPage == 1 && StoreDetailFragment.this.mListView.getFooterViewsCount() == 0) {
                                StoreDetailFragment.this.mListView.addFooterView(StoreDetailFragment.this.mLoadingView);
                            }
                            StoreDetailFragment.this.mReviewModels.addAll(model.getResult_list());
                            if (StoreDetailFragment.this.mPage == 1) {
                                StoreDetailFragment.this.mAdapter.setList(StoreDetailFragment.this.mListType, StoreDetailFragment.this.mReviewModels);
                            } else {
                                StoreDetailFragment.this.mAdapter.setData(StoreDetailFragment.this.mReviewModels);
                            }
                            StoreDetailFragment.this.mListView.post(new Runnable() {
                                public void run() {
                                    if (StoreDetailFragment.this.mListView.getFirstVisiblePosition() > 0 && StoreDetailFragment.this.mPage == 1) {
                                        StoreDetailFragment.this.mListView.setSelectionFromTop(1, StoreDetailFragment.this.getResources().getDimensionPixelOffset(R.dimen.DETAIL_TAB_HEIGHT) + StoreDetailFragment.this.getResources().getDimensionPixelSize(R.dimen.TAB_MARGIN));
                                    }
                                }
                            });
                            if (10 > model.getResult_list().size()) {
                                StoreDetailFragment.this.mListView.removeFooterView(StoreDetailFragment.this.mLoadingView);
                            } else {
                                StoreDetailFragment.this.mPage = StoreDetailFragment.this.mPage + 1;
                            }
                        }
                        StoreDetailFragment.this.mRefreshLayout.setRefreshing(false);
                    }
                }

                public void onFailure(Exception exception) {
                    if (((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                        ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                    }
                }

                public void onFinish() {
                    if (StoreDetailFragment.this.isAdded()) {
                        StoreDetailFragment.this.isLoadComplete = true;
                        StoreDetailFragment.this.mApiRequesting = false;
                        if (StoreDetailFragment.this.getActivity() != null && StoreDetailFragment.this.mReviewModels.size() == 0) {
                            StoreDetailFragment.this.mAdapter.setSize((StoreDetailFragment.this.mListView.getHeight() - StoreDetailFragment.this.getResources().getDimensionPixelSize(R.dimen.DETAIL_TAB_HEIGHT)) - StoreDetailFragment.this.getResources().getDimensionPixelSize(R.dimen.CARD_VIEW_HEIGHT));
                        }
                        if (isTopScroll) {
                            StoreDetailFragment.this.mListView.postDelayed(new Runnable() {
                                public void run() {
                                    if (StoreDetailFragment.this.isAdded()) {
                                        StoreDetailFragment.this.mListView.setSelectionFromTop(0, -StoreDetailFragment.this.mHeaderView.findViewById(R.id.writeReviewButtonLayout).getBottom());
                                    }
                                }
                            }, 500);
                        }
                        StoreDetailFragment.this.requestReviewCountApi(StoreDetailFragment.this.mStoreModel.getPartnerSno());
                        StoreDetailFragment.this.postSubTab();
                    }
                }
            });
        }
    }

    public void requestFavoriteStoreApi(final View view) {
        StoreFavoriteApi request = new StoreFavoriteApi(getActivity(), view.isSelected() ? 1 : 2);
        request.addParam("partner_sno", this.mStoreModel.getPartnerSno());
        request.request(new RequestHandler() {
            public void onStart() {
                if (((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(true);
                }
            }

            public void onResult(Object result) {
                if (((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }
                if (!((BaseResultModel) result).getResult().equals("Y")) {
                    view.setSelected(!view.isSelected());
                } else {
                    StoreDetailFragment.this.mStoreModel.setFavorite(view.isSelected());
                }
            }

            public void onFailure(Exception exception) {
                if (((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestBlogListApi(String partnerSno) {
        this.mApiRequesting = true;
        new StoreNaverBlogApi(getActivity(), ApiUrl.STORE_NAVER_BLOG + "?partner_sno=" + partnerSno + "&page=" + this.mPage + "&view_cnt=" + 10).request(new RequestHandler() {
            public void onStart() {
                if (StoreDetailFragment.this.mPage == 1 && ((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(true);
                }
            }

            public void onResult(Object result) {
                if (((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }
                StoreResultBlogModel model = (StoreResultBlogModel) result;
                if (StoreDetailFragment.this.mListView.getFooterViewsCount() == 0) {
                    StoreDetailFragment.this.mListView.addFooterView(StoreDetailFragment.this.mLoadingView);
                }
                StoreDetailFragment.this.mStoreBlogModels.addAll(model.getResult_list());
                if (StoreDetailFragment.this.mPage == 1) {
                    StoreDetailFragment.this.mAdapter.setList(StoreDetailFragment.this.mListType, StoreDetailFragment.this.mStoreBlogModels);
                } else {
                    StoreDetailFragment.this.mAdapter.setData(StoreDetailFragment.this.mStoreBlogModels);
                }
                StoreDetailFragment.this.mListView.post(new Runnable() {
                    public void run() {
                        if (StoreDetailFragment.this.mListView.getFirstVisiblePosition() > 0 && StoreDetailFragment.this.mPage == 1) {
                            StoreDetailFragment.this.mListView.setSelectionFromTop(1, StoreDetailFragment.this.getResources().getDimensionPixelOffset(R.dimen.DETAIL_TAB_HEIGHT) + StoreDetailFragment.this.getResources().getDimensionPixelSize(R.dimen.TAB_MARGIN));
                        }
                    }
                });
                if (10 > model.getResult_list().size()) {
                    StoreDetailFragment.this.mListView.removeFooterView(StoreDetailFragment.this.mLoadingView);
                } else {
                    StoreDetailFragment.this.mPage = StoreDetailFragment.this.mPage + 1;
                }
                StoreDetailFragment.this.mRefreshLayout.setRefreshing(false);
            }

            public void onFailure(Exception exception) {
                if (((BaseActivity) StoreDetailFragment.this.getActivity()) != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }
            }

            public void onFinish() {
                StoreDetailFragment.this.isLoadComplete = true;
                StoreDetailFragment.this.mApiRequesting = false;
                if (StoreDetailFragment.this.mStoreBlogModels.size() == 0) {
                    StoreDetailFragment.this.mAdapter.setSize((StoreDetailFragment.this.mListView.getHeight() - StoreDetailFragment.this.getActivity().getResources().getDimensionPixelSize(R.dimen.DETAIL_TAB_HEIGHT)) - StoreDetailFragment.this.getActivity().getResources().getDimensionPixelSize(R.dimen.CARD_VIEW_HEIGHT));
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestInstagramListApi(String partnerSno) {
        this.mApiRequesting = true;
        new StoreInstaApi(getActivity(), ApiUrl.STORE_INSTAGRAM + "?partner_sno=" + partnerSno + "&page=" + this.mPage + "&view_cnt=" + 10).request(new RequestHandler() {
            public void onStart() {
                if (StoreDetailFragment.this.mPage == 1 && StoreDetailFragment.this.getActivity() != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(true);
                }
            }

            public void onResult(Object result) {
                if (StoreDetailFragment.this.getActivity() != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }
                StoreInstaResultModel model = (StoreInstaResultModel) result;
                if (StoreDetailFragment.this.mListView.getFooterViewsCount() == 0) {
                    StoreDetailFragment.this.mListView.addFooterView(StoreDetailFragment.this.mLoadingView);
                }
                StoreDetailFragment.this.mStoreInstaModels.addAll(model.getResult_list());
                if (StoreDetailFragment.this.mPage == 1) {
                    StoreDetailFragment.this.mAdapter.setList(StoreDetailFragment.this.mListType, StoreDetailFragment.this.mStoreInstaModels);
                } else {
                    StoreDetailFragment.this.mAdapter.setData(StoreDetailFragment.this.mStoreInstaModels);
                }
                StoreDetailFragment.this.mListView.post(new Runnable() {
                    public void run() {
                        if (StoreDetailFragment.this.mListView.getFirstVisiblePosition() > 0 && StoreDetailFragment.this.mPage == 1) {
                            StoreDetailFragment.this.mListView.setSelectionFromTop(1, StoreDetailFragment.this.getResources().getDimensionPixelOffset(R.dimen.DETAIL_TAB_HEIGHT) + StoreDetailFragment.this.getResources().getDimensionPixelSize(R.dimen.TAB_MARGIN));
                        }
                    }
                });
                if (10 > model.getResult_list().size()) {
                    StoreDetailFragment.this.mListView.removeFooterView(StoreDetailFragment.this.mLoadingView);
                } else {
                    StoreDetailFragment.this.mPage = StoreDetailFragment.this.mPage + 1;
                }
                StoreDetailFragment.this.mRefreshLayout.setRefreshing(false);
            }

            public void onFailure(Exception exception) {
                if (StoreDetailFragment.this.getActivity() != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }
            }

            public void onFinish() {
                StoreDetailFragment.this.isLoadComplete = true;
                StoreDetailFragment.this.mApiRequesting = false;
                if (StoreDetailFragment.this.mStoreInstaModels.size() == 0) {
                    StoreDetailFragment.this.mAdapter.setSize((StoreDetailFragment.this.mListView.getHeight() - StoreDetailFragment.this.getActivity().getResources().getDimensionPixelSize(R.dimen.DETAIL_TAB_HEIGHT)) - StoreDetailFragment.this.getActivity().getResources().getDimensionPixelSize(R.dimen.CARD_VIEW_HEIGHT));
                }
            }
        });
    }

    public void requestReviewCountApi(String partnerSno) {
        new ReviewCountApi(getActivity(), ApiUrl.STORE_REVIEW_COUNT + "?partner_sno=" + partnerSno).request(new RequestHandler() {
            public void onResult(Object result) {
                ReviewCountModel model = (ReviewCountModel) result;
                ((TextView) StoreDetailFragment.this.mRootView.findViewById(R.id.reviewTabCountLabel)).setText("(" + model.getShareat_count() + ")");
                ((TextView) StoreDetailFragment.this.mRootView.findViewById(R.id.instaCountLabel)).setText("(" + model.getInsta_count() + ")");
                ((TextView) StoreDetailFragment.this.mRootView.findViewById(R.id.blogCountLabel)).setText("(" + model.getNaver_count() + ")");
                ((TextView) StoreDetailFragment.this.mHeaderView.findViewById(R.id.reviewCountLabel)).setText(String.valueOf(model.getShareat_count() + model.getInsta_count() + model.getNaver_count()));
                StoreDetailFragment.this.mHeaderView.setReviewCount(model);
            }

            public void onFailure(Exception exception) {
                if (StoreDetailFragment.this.getActivity() != null) {
                    ((BaseActivity) StoreDetailFragment.this.getActivity()).showCircleDialog(false);
                }
            }

            public void onStart() {
                super.onStart();
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }
}