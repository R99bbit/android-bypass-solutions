package com.nuvent.shareat.fragment;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.graphics.drawable.BitmapDrawable;
import android.location.LocationManager;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.content.ContextCompat;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.support.v4.widget.SwipeRefreshLayout;
import android.support.v4.widget.SwipeRefreshLayout.OnRefreshListener;
import android.util.DisplayMetrics;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.animation.AnimationUtils;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.PopupWindow.OnDismissListener;
import android.widget.RelativeLayout;
import android.widget.RelativeLayout.LayoutParams;
import android.widget.TextView;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import com.nostra13.universalimageloader.core.ImageLoader;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.activity.menu.InterestActivity;
import com.nuvent.shareat.adapter.store.StoreListAdapter;
import com.nuvent.shareat.adapter.store.StoreListAdapter.OnClickStoreItem;
import com.nuvent.shareat.adapter.store.StoreListEmptyAdapter;
import com.nuvent.shareat.adapter.store.StoreListEmptyAdapter.OnStoreListEmptyAdapterListener;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.RecommendLookAroundApi;
import com.nuvent.shareat.api.store.EventBannerApi;
import com.nuvent.shareat.api.store.StoreListApi;
import com.nuvent.shareat.event.BannerRollingEvent;
import com.nuvent.shareat.event.GpsRefreshEvent;
import com.nuvent.shareat.event.GpsRegistEvent;
import com.nuvent.shareat.event.LogoClickEvent;
import com.nuvent.shareat.event.MainOnEvent;
import com.nuvent.shareat.event.PaySuccessEvent;
import com.nuvent.shareat.event.PostGnbOptionEvent;
import com.nuvent.shareat.event.SchemeMainlistEvent;
import com.nuvent.shareat.event.StoreSelectedEvent;
import com.nuvent.shareat.event.SuccessProfileUpdateEvent;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.ParamManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.BannerModel;
import com.nuvent.shareat.model.EventBannerResultModel;
import com.nuvent.shareat.model.RecommendLookAroundModel;
import com.nuvent.shareat.model.store.LocationModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.model.store.StoreParamsModel;
import com.nuvent.shareat.model.store.StoreResultModel;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import net.xenix.android.widget.InfinitePagerAdapter;
import net.xenix.android.widget.InfiniteViewPager;
import net.xenix.android.widget.InfiniteViewPager.OnSwipeOutListener;
import net.xenix.util.ImageDisplay;

public class MainFragment extends Fragment {
    private static final int BANNER_PAGE_LIMIT = 10;
    /* access modifiers changed from: private */
    public int lastPosition = 0;
    /* access modifiers changed from: private */
    public StoreListAdapter mAdapter;
    /* access modifiers changed from: private */
    public boolean mApiRequesting;
    /* access modifiers changed from: private */
    public Runnable mAutoRolling;
    /* access modifiers changed from: private */
    public ArrayList<BannerModel> mBannerModels = new ArrayList<>();
    private StoreListEmptyAdapter mEmptyAdapter;
    /* access modifiers changed from: private */
    public Bundle mExternalParams;
    /* access modifiers changed from: private */
    public Handler mHandler = new Handler();
    /* access modifiers changed from: private */
    public View mHeaderView;
    /* access modifiers changed from: private */
    public int mLastFirstVisibleItem;
    /* access modifiers changed from: private */
    public TextView mListTypeLabel;
    /* access modifiers changed from: private */
    public View mListTypeView;
    /* access modifiers changed from: private */
    public ListView mListView;
    /* access modifiers changed from: private */
    public View mLoadingView;
    /* access modifiers changed from: private */
    public ImageButton mMapBtn;
    /* access modifiers changed from: private */
    public ArrayList<StoreModel> mModels = new ArrayList<>();
    /* access modifiers changed from: private */
    public int mPage = 1;
    private StoreParamsModel mParamsModel;
    /* access modifiers changed from: private */
    public PopupWindow mPopupWindow;
    /* access modifiers changed from: private */
    public int mPrevScrollY;
    /* access modifiers changed from: private */
    public RecommendLookAroundModel mRecommendLookAroundModel;
    /* access modifiers changed from: private */
    public SwipeRefreshLayout mRefreshLayout;
    private Handler mResetHandler = new Handler();
    private View mTopView;
    /* access modifiers changed from: private */
    public int mTopViewHeight;
    /* access modifiers changed from: private */
    public InfiniteViewPager mViewPager;

    public class BannerAdapter extends PagerAdapter {
        private final int MAX_BANNER_COUNT = 10;
        private Context mContext;
        /* access modifiers changed from: private */
        public ArrayList<BannerModel> mModels = new ArrayList<>();

        public BannerAdapter(Context context, ArrayList<BannerModel> models) {
            this.mContext = context;
            this.mModels = models;
        }

        public int getCount() {
            if (this.mModels.size() > 10) {
                return 10;
            }
            return this.mModels.size();
        }

        public boolean isViewFromObject(View view, Object object) {
            return view == object;
        }

        public Object instantiateItem(ViewGroup container, int position) {
            View view = View.inflate(this.mContext, R.layout.page_banner, null);
            if (VERSION.SDK_INT >= 24) {
                DisplayMetrics outMetrics = new DisplayMetrics();
                ((WindowManager) MainFragment.this.getContext().getSystemService("window")).getDefaultDisplay().getMetrics(outMetrics);
                float f = MainFragment.this.getResources().getDisplayMetrics().density;
                float defaultScale = (float) (outMetrics.densityDpi / 160);
                if ((480 < outMetrics.densityDpi && 640 > outMetrics.densityDpi) || 640 < outMetrics.densityDpi) {
                    defaultScale = 4.0f;
                } else if ((320 < outMetrics.densityDpi && 480 > outMetrics.densityDpi) || (480 < outMetrics.densityDpi && 640 > outMetrics.densityDpi)) {
                    defaultScale = 3.0f;
                }
                ImageView bannerImage = (ImageView) view.findViewById(R.id.bannerImageView);
                ImageView bgImage = (ImageView) view.findViewById(R.id.bannerBGView);
                float scaleValue = defaultScale / outMetrics.density;
                LayoutParams layoutParams1 = (LayoutParams) bannerImage.getLayoutParams();
                LayoutParams layoutParams2 = (LayoutParams) bgImage.getLayoutParams();
                layoutParams1.width = (int) (((float) layoutParams1.width) * scaleValue);
                layoutParams1.height = (int) (((float) layoutParams1.height) * scaleValue);
                layoutParams2.width = (int) (((float) layoutParams2.width) * scaleValue);
                layoutParams2.height = (int) (((float) layoutParams2.height) * scaleValue);
                bannerImage.setLayoutParams(layoutParams1);
                bgImage.setLayoutParams(layoutParams2);
            }
            if (this.mModels.get(position).getBanner_kind().equals("10")) {
                String title = "";
                try {
                    title = URLDecoder.decode(this.mModels.get(position).getTitle(), "UTF-8");
                } catch (Exception e) {
                    e.printStackTrace();
                }
                ((TextView) view.findViewById(R.id.bannerTitleLabel)).setText(title);
            } else {
                view.findViewById(R.id.bannerImageView).setVisibility(0);
                view.findViewById(R.id.bannerTitleLabel).setVisibility(8);
                if (ImageLoader.getInstance().getDiskCache().get(this.mModels.get(position).getImage_url()) != null) {
                    ImageLoader.getInstance().getDiskCache().remove(this.mModels.get(position).getImage_url());
                }
                if (ImageLoader.getInstance().getMemoryCache().get(this.mModels.get(position).getImage_url()) != null) {
                    ImageLoader.getInstance().getMemoryCache().remove(this.mModels.get(position).getImage_url());
                }
                ImageDisplay.getInstance().displayImageLoad(this.mModels.get(position).getImage_url(), (ImageView) view.findViewById(R.id.bannerImageView));
            }
            final int i = position;
            view.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    try {
                        String title = ((BannerModel) BannerAdapter.this.mModels.get(i)).getTitle();
                        if (title == null) {
                            title = "";
                        } else {
                            try {
                                title = URLDecoder.decode(title, "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                e.printStackTrace();
                            }
                        }
                        String string = MainFragment.this.getResources().getString(R.string.ga_storelist);
                        String string2 = MainFragment.this.getResources().getString(R.string.ga_ev_click);
                        if ((MainFragment.this.getResources().getString(R.string.ga_storelist_banner) + title) == null) {
                            title = "";
                        }
                        GAEvent.onGaEvent(string, string2, title);
                        CustomSchemeManager.postSchemeAction(MainFragment.this.getActivity(), ((BannerModel) BannerAdapter.this.mModels.get(i)).getLink_url());
                    } catch (NullPointerException e2) {
                        e2.printStackTrace();
                    }
                }
            });
            container.addView(view);
            return view;
        }

        public void destroyItem(ViewGroup container, int position, Object object) {
            container.removeView((View) object);
        }
    }

    public void onEventMainThread(SchemeMainlistEvent event) {
        Bundle params = event.getParams();
        this.mExternalParams = params;
        if (params != null) {
            this.mPage = 1;
            postStoreApiExternalParam();
        }
    }

    private boolean isUseExternalStoreList(boolean isChangeListType) {
        if (this.mExternalParams == null) {
            return false;
        }
        String externalTitle = this.mExternalParams.getString("title", "");
        if (externalTitle == null || true == externalTitle.isEmpty()) {
            return false;
        }
        if (true == isChangeListType) {
            return true;
        }
        if (externalTitle.equals(ParamManager.getInstance().getRecentSetModel().getAreaName())) {
            return true;
        }
        return false;
    }

    public void onEventMainThread(PostGnbOptionEvent event) {
        showHeaderView();
        this.mPage = 1;
        this.mExternalParams = null;
        postStoreApi(false);
    }

    public void onEventMainThread(GpsRefreshEvent event) {
        if (this.mExternalParams == null) {
            this.mPage = 1;
            postStoreApi(true);
        }
    }

    public void onEventMainThread(MainOnEvent event) {
        showHeaderView();
    }

    public void onEventMainThread(SuccessProfileUpdateEvent event) {
        this.mAdapter.notifyDataSetChanged();
    }

    public void onEventMainThread(LogoClickEvent event) {
        if (this.mModels != null && this.mModels.size() > 0) {
            this.mListView.smoothScrollToPosition(0);
        }
    }

    public void onEventMainThread(GpsRegistEvent event) {
        if (ShareatApp.getInstance().getGpsManager() != null && event.getData() != null) {
            if (this.mParamsModel != null && this.mParamsModel.getAreaName().equals("\ub0b4\uc8fc\ubcc0")) {
                ((TextView) this.mTopView.findViewById(R.id.locationName)).setText("");
            }
            Map<Integer, String> dimensions = new HashMap<>();
            dimensions.put(Integer.valueOf(4), ShareatApp.getInstance().getUserNum());
            dimensions.put(Integer.valueOf(8), "");
            dimensions.put(Integer.valueOf(14), "");
            dimensions.put(Integer.valueOf(15), "");
            GAEvent.onGACustomDimensions(getActivity(), getString(R.string.ga_storelist), dimensions);
        }
    }

    public void onEventMainThread(PaySuccessEvent event) {
        showHeaderView();
        this.mExternalParams = null;
        this.mPage = 1;
        postStoreApi(false);
    }

    private void setScaleBanner() {
        if (VERSION.SDK_INT >= 24) {
            DisplayMetrics outMetrics = new DisplayMetrics();
            ((WindowManager) getContext().getSystemService("window")).getDefaultDisplay().getMetrics(outMetrics);
            float defaultScale = (float) (outMetrics.densityDpi / 160);
            if ((480 < outMetrics.densityDpi && 640 > outMetrics.densityDpi) || 640 < outMetrics.densityDpi) {
                defaultScale = 4.0f;
            } else if ((320 < outMetrics.densityDpi && 480 > outMetrics.densityDpi) || (480 < outMetrics.densityDpi && 640 > outMetrics.densityDpi)) {
                defaultScale = 3.0f;
            }
            RelativeLayout relativeLayout = (RelativeLayout) this.mHeaderView.findViewById(R.id.root_header_banner);
            ViewGroup.LayoutParams layoutParams = relativeLayout.getLayoutParams();
            layoutParams.height = (int) (((float) layoutParams.height) * (defaultScale / outMetrics.density));
            relativeLayout.setLayoutParams(layoutParams);
        }
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = View.inflate(getActivity(), R.layout.fragment_main, null);
        EventBus.getDefault().register(this);
        this.mExternalParams = ((MainActivity) getActivity()).getExternalParams();
        this.mListTypeLabel = (TextView) view.findViewById(R.id.listTypeLable);
        this.mHeaderView = View.inflate(getActivity(), R.layout.header_banner, null);
        setScaleBanner();
        this.mListView = (ListView) view.findViewById(R.id.listView);
        this.mListView.addHeaderView(this.mHeaderView);
        this.mTopView = view.findViewById(R.id.topView);
        this.mTopView.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                ((MainActivity) MainFragment.this.getActivity()).onClickLocation(null);
            }
        });
        this.mLoadingView = View.inflate(getActivity(), R.layout.footer_list_loading, null);
        this.mRefreshLayout = (SwipeRefreshLayout) view.findViewById(R.id.swipeRefreshLayout);
        this.mRefreshLayout.setOnRefreshListener(new OnRefreshListener() {
            public void onRefresh() {
                MainFragment.this.lastPosition = 0;
                MainFragment.this.mPage = 1;
                if (MainFragment.this.mExternalParams != null) {
                    MainFragment.this.postStoreApiExternalParam();
                } else {
                    MainFragment.this.postStoreApi(false);
                }
                MainFragment.this.requestEventBannerList();
            }
        });
        this.mRefreshLayout.setColorSchemeResources(R.color.main_list_pay_cnt_color, R.color.green, R.color.blue, R.color.yellow);
        requestEventBannerList();
        setListTypePopup();
        setAdapter();
        boolean isAvailable = isGpsAvailable();
        if (this.mExternalParams != null) {
            postStoreApiExternalParam();
        } else if (!isAvailable) {
            postStoreApi(true);
        }
        Map<Integer, String> dimensions = new HashMap<>();
        dimensions.put(Integer.valueOf(13), getResources().getString((ShareatApp.getInstance().getGpsManager() == null || !ShareatApp.getInstance().getGpsManager().isGetLocation()) ? R.string.ga_gps_off : R.string.ga_gps_on));
        GAEvent.onGACustomDimensions(getActivity(), getString(R.string.ga_storelist), dimensions);
        this.mMapBtn = (ImageButton) view.findViewById(R.id.map_btn);
        this.mMapBtn.getBackground().setAlpha(229);
        this.mMapBtn.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) MainFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.ga_nmap_floating_click, (int) R.string.ga_storelist_nmapbtn);
                ((MainActivity) MainFragment.this.getActivity()).showNMapFragment();
            }
        });
        return view;
    }

    private boolean isGpsAvailable() {
        int permission1 = ContextCompat.checkSelfPermission(getActivity(), "android.permission.ACCESS_NETWORK_STATE");
        int permission2 = ContextCompat.checkSelfPermission(getActivity(), "android.permission.ACCESS_FINE_LOCATION");
        int permission3 = ContextCompat.checkSelfPermission(getActivity(), "android.permission.READ_PHONE_STATE");
        if (permission1 == -1 || permission2 == -1 || permission3 == -1) {
            return false;
        }
        FragmentActivity activity = getActivity();
        getActivity();
        if (!((LocationManager) activity.getSystemService(Param.LOCATION)).isProviderEnabled("gps")) {
            return false;
        }
        if (SessionManager.getInstance().hasSession() || AppSettingManager.getInstance().isLocationInfoAgreed()) {
            return true;
        }
        return false;
    }

    /* access modifiers changed from: private */
    public void requestEventBannerList() {
        LocationModel recentSetModel = ParamManager.getInstance().getRecentSetModel();
        Object[] objArr = new Object[4];
        objArr[0] = "Android";
        objArr[1] = ShareatApp.getInstance().getAppVersionName();
        objArr[2] = String.valueOf(ShareatApp.getInstance().getGpsManager() == null ? 37.4986366d : ShareatApp.getInstance().getGpsManager().getLatitude());
        objArr[3] = String.valueOf(ShareatApp.getInstance().getGpsManager() == null ? 127.027021d : ShareatApp.getInstance().getGpsManager().getLongitude());
        String params = String.format("?area=main_top&os=%s&app_version=%s&user_Y=%s&user_X=%s", objArr);
        EventBannerApi request = new EventBannerApi(getActivity());
        request.addGetParam(params);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                MainFragment.this.mBannerModels = ((EventBannerResultModel) result).getResult_list();
                if (MainFragment.this.mBannerModels == null || MainFragment.this.mBannerModels.isEmpty()) {
                    MainFragment.this.mListView.removeHeaderView(MainFragment.this.mHeaderView);
                } else {
                    MainFragment.this.setHeaderView();
                }
            }
        });
    }

    public void onDestroyView() {
        super.onDestroyView();
        EventBus.getDefault().unregister(this);
    }

    private float dpToPx(Context context, int dp) {
        return (float) ((context.getResources().getDisplayMetrics().densityDpi / 160) * dp);
    }

    public void onEventMainThread(BannerRollingEvent event) {
        if (this.mHandler == null) {
            this.mResetHandler.removeCallbacksAndMessages(null);
            this.mResetHandler.postDelayed(new Runnable() {
                public void run() {
                    MainFragment.this.mHandler = new Handler();
                    MainFragment.this.lastPosition = MainFragment.this.mViewPager.getCurrentItem();
                    MainFragment.this.setHeaderView();
                }
            }, 5000);
            return;
        }
        this.mHandler.removeCallbacksAndMessages(null);
        this.mHandler.removeCallbacks(this.mAutoRolling);
        this.mHandler = null;
        this.mResetHandler.postDelayed(new Runnable() {
            public void run() {
                MainFragment.this.mHandler = new Handler();
                MainFragment.this.setHeaderView();
            }
        }, 3000);
    }

    /* access modifiers changed from: private */
    public void setHeaderView() {
        int size;
        long j;
        final int bannerSize = 10;
        if (this.mViewPager == null) {
            this.mViewPager = (InfiniteViewPager) this.mHeaderView.findViewById(R.id.viewPager);
        }
        BannerAdapter adapter = new BannerAdapter(getActivity(), this.mBannerModels);
        ViewGroup viewGroup = (ViewGroup) this.mHeaderView.findViewById(R.id.indicatorLayout);
        viewGroup.removeAllViews();
        int i = 0;
        while (true) {
            try {
                if (this.mBannerModels.size() > 10) {
                    size = 10;
                } else {
                    size = this.mBannerModels.size();
                }
                if (i >= size) {
                    break;
                }
                LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(getResources().getDimensionPixelOffset(R.dimen.BANNER_INDICATOR_SIZE), getResources().getDimensionPixelOffset(R.dimen.BANNER_INDICATOR_SIZE));
                if (i > 0) {
                    params.leftMargin = getResources().getDimensionPixelOffset(R.dimen.BANNER_INDICATOR_MARGIN);
                }
                ImageView view = new ImageView(getActivity());
                view.setImageResource(R.drawable.selector_banner_indicator);
                view.setLayoutParams(params);
                viewGroup.addView(view);
                i++;
            } catch (IllegalStateException e) {
                e.printStackTrace();
                return;
            }
        }
        this.mViewPager.setAdapter(new InfinitePagerAdapter(adapter));
        this.mViewPager.addOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
                MainFragment.this.setIndicator(MainFragment.this.mViewPager.getCurrentItem());
            }

            public void onPageScrollStateChanged(int state) {
                if (state != 0) {
                    MainFragment.this.mRefreshLayout.setEnabled(false);
                } else if (MainFragment.this.mModels != null && MainFragment.this.mModels.size() > 0) {
                    MainFragment.this.mRefreshLayout.setEnabled(true);
                }
            }
        });
        this.mViewPager.setOnSwipeOutListener(new OnSwipeOutListener() {
            public void onSwipeOutAtStart() {
                EventBus.getDefault().post(new BannerRollingEvent());
            }
        });
        if (this.mBannerModels.size() <= 10) {
            bannerSize = this.mBannerModels.size();
        }
        setIndicator(this.lastPosition);
        this.mViewPager.setCurrentItem(this.lastPosition);
        this.mViewPager.setOffscreenPageLimit(bannerSize);
        this.mAutoRolling = new Runnable() {
            public void run() {
                int index;
                if (MainFragment.this.mHandler != null) {
                    int index2 = MainFragment.this.mViewPager.getCurrentItem();
                    if (index2 == bannerSize - 1) {
                        index = 0;
                    } else {
                        index = index2 + 1;
                    }
                    MainFragment.this.mViewPager.setCurrentItem(index, true);
                    MainFragment.this.mHandler.postDelayed(MainFragment.this.mAutoRolling, 3000);
                }
            }
        };
        if (this.mHandler != null) {
            this.mHandler.removeCallbacksAndMessages(null);
            this.mHandler.removeCallbacks(this.mAutoRolling);
            this.mHandler = null;
            this.mHandler = new Handler();
        }
        Handler handler = this.mHandler;
        Runnable runnable = this.mAutoRolling;
        if (this.lastPosition > 0) {
            j = 100;
        } else {
            j = 3000;
        }
        handler.postDelayed(runnable, j);
    }

    /* access modifiers changed from: private */
    public void setIndicator(int index) {
        ViewGroup viewGroup = (ViewGroup) this.mHeaderView.findViewById(R.id.indicatorLayout);
        for (int i = 0; i < viewGroup.getChildCount(); i++) {
            ImageView view = (ImageView) viewGroup.getChildAt(i);
            if (i == index) {
                view.setSelected(true);
            } else {
                view.setSelected(false);
            }
        }
    }

    public void onEventMainThread(StoreSelectedEvent event) {
        if (this.mPopupWindow != null) {
            this.mPopupWindow.dismiss();
        }
    }

    private void setListTypePopup() {
        if (this.mListTypeView == null) {
            this.mListTypeView = View.inflate(getActivity(), R.layout.popup_main_list_type, null);
        }
        this.mPopupWindow = new PopupWindow(this.mListTypeView, -2, -2);
        this.mPopupWindow.setOutsideTouchable(true);
        this.mPopupWindow.setFocusable(true);
        this.mPopupWindow.setBackgroundDrawable(new BitmapDrawable());
        this.mListTypeLabel.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (MainFragment.this.getActivity() != null && ((MainActivity) MainFragment.this.getActivity()).isStoreClick()) {
                    return;
                }
                if (MainFragment.this.mPopupWindow.isShowing()) {
                    MainFragment.this.mPopupWindow.dismiss();
                } else {
                    MainFragment.this.mListTypeLabel.postDelayed(new Runnable() {
                        public void run() {
                            if (MainFragment.this.getActivity() == null || !((MainActivity) MainFragment.this.getActivity()).isStoreClick()) {
                                MainFragment.this.mPopupWindow.showAsDropDown(MainFragment.this.mListTypeLabel);
                                MainFragment.this.mListTypeLabel.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.menu_arrow_up, 0);
                            }
                        }
                    }, 100);
                }
            }
        });
        this.mListTypeView.findViewById(R.id.eventType).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                v.setSelected(true);
                MainFragment.this.mListTypeView.findViewById(R.id.distanceType).setSelected(false);
                MainFragment.this.mListTypeView.findViewById(R.id.popularType).setSelected(false);
                MainFragment.this.mListTypeView.findViewById(R.id.payCountType).setSelected(false);
                GAEvent.onGaEvent((Activity) MainFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.quickSort, (int) R.string.quickSort_event);
                ParamManager.getInstance().setSortType(0);
                EventBus.getDefault().post(new PostGnbOptionEvent(true));
                MainFragment.this.mPopupWindow.dismiss();
                MainFragment.this.mListTypeLabel.setText(((TextView) v).getText().toString());
            }
        });
        this.mListTypeView.findViewById(R.id.distanceType).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                v.setSelected(true);
                MainFragment.this.mListTypeView.findViewById(R.id.eventType).setSelected(false);
                MainFragment.this.mListTypeView.findViewById(R.id.popularType).setSelected(false);
                MainFragment.this.mListTypeView.findViewById(R.id.payCountType).setSelected(false);
                GAEvent.onGaEvent((Activity) MainFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.quickSort, (int) R.string.quickSort_distance);
                ParamManager.getInstance().setSortType(1);
                EventBus.getDefault().post(new PostGnbOptionEvent(true));
                MainFragment.this.mPopupWindow.dismiss();
                MainFragment.this.mListTypeLabel.setText(((TextView) v).getText().toString());
            }
        });
        this.mListTypeView.findViewById(R.id.payCountType).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                v.setSelected(true);
                MainFragment.this.mListTypeView.findViewById(R.id.eventType).setSelected(false);
                MainFragment.this.mListTypeView.findViewById(R.id.distanceType).setSelected(false);
                MainFragment.this.mListTypeView.findViewById(R.id.popularType).setSelected(false);
                GAEvent.onGaEvent((Activity) MainFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.quickSort, (int) R.string.quickSort_paycount);
                ParamManager.getInstance().setSortType(7);
                EventBus.getDefault().post(new PostGnbOptionEvent(true));
                MainFragment.this.mPopupWindow.dismiss();
                MainFragment.this.mListTypeLabel.setText(((TextView) v).getText().toString());
            }
        });
        this.mListTypeView.findViewById(R.id.popularType).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                v.setSelected(true);
                MainFragment.this.mListTypeView.findViewById(R.id.eventType).setSelected(false);
                MainFragment.this.mListTypeView.findViewById(R.id.distanceType).setSelected(false);
                MainFragment.this.mListTypeView.findViewById(R.id.payCountType).setSelected(false);
                GAEvent.onGaEvent((Activity) MainFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.quickSort, (int) R.string.quickSort_review);
                ParamManager.getInstance().setSortType(6);
                EventBus.getDefault().post(new PostGnbOptionEvent(true));
                MainFragment.this.mPopupWindow.dismiss();
                MainFragment.this.mListTypeLabel.setText(((TextView) v).getText().toString());
            }
        });
        this.mPopupWindow.setOnDismissListener(new OnDismissListener() {
            public void onDismiss() {
                MainFragment.this.mListTypeLabel.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.menu_arrow_down, 0);
            }
        });
    }

    /* access modifiers changed from: private */
    public void setEmptyAdapter() {
        GAEvent.onGAScreenView(getActivity(), R.string.ga_empty_store);
        if (this.mEmptyAdapter == null) {
            this.mEmptyAdapter = new StoreListEmptyAdapter(getContext(), this.mRecommendLookAroundModel);
        } else {
            this.mEmptyAdapter.setRecommendLookAroundModel(this.mRecommendLookAroundModel);
            this.mEmptyAdapter.notifyDataSetChanged();
        }
        this.mListView.setAdapter(this.mEmptyAdapter);
        this.mEmptyAdapter.setListener(new OnStoreListEmptyAdapterListener() {
            public void otherRegionBtnClick() {
                GAEvent.onGaEvent(MainFragment.this.getResources().getString(R.string.ga_empty_store), MainFragment.this.getResources().getString(R.string.ga_ev_click), MainFragment.this.getResources().getString(R.string.ga_other_region));
                ((MainActivity) MainFragment.this.getActivity()).onClickLocation(null);
            }
        });
        this.mRefreshLayout.setRefreshing(false);
        this.mRefreshLayout.setEnabled(false);
    }

    private void setAdapter() {
        this.mAdapter = new StoreListAdapter(getActivity(), Typeface.createFromAsset(getActivity().getAssets(), "NanumBarunGothicBold.ttf"), this.mModels);
        this.mAdapter.setOnClickStoreItemListener(new OnClickStoreItem() {
            public void onClickUser(StoreModel model) {
                GAEvent.onGaEvent(MainFragment.this.getResources().getString(R.string.ga_storelist), MainFragment.this.getResources().getString(R.string.ga_ev_click), MainFragment.this.getResources().getString(R.string.ga_storelist_ticker));
                if (model.getHeadListKind() == null || model.getHeadListKind().equals("M") || model.getLastName().equals("\ube44\uacf5\uac1c")) {
                    if (model.getHeadListKind().equals("M")) {
                        ((MainActivity) MainFragment.this.getActivity()).onClickStoreItem(model);
                    }
                } else if (MainFragment.this.getActivity() == null || SessionManager.getInstance().hasSession()) {
                    Intent intent = new Intent(MainFragment.this.getActivity(), InterestActivity.class);
                    if (ShareatApp.getInstance().getUserNum() == null || !ShareatApp.getInstance().getUserNum().equals(model.getLastuserSno())) {
                        intent.putExtra("targetUserSno", model.getLastuserSno());
                    }
                    if (model.getHeadListKind().equals("S")) {
                        intent.putExtra("isReview", "");
                    }
                    ((BaseActivity) MainFragment.this.getActivity()).pushActivity(intent);
                    GAEvent.onGaEvent((Activity) MainFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.ga_ev_click, (int) R.string.ga_storelist_profile);
                } else {
                    ((BaseActivity) MainFragment.this.getActivity()).showLoginDialog();
                }
            }

            public void onClickStore(StoreModel model) {
                ((MainActivity) MainFragment.this.getActivity()).onClickStoreItem(model);
            }
        });
        this.mListView.setAdapter(this.mAdapter);
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                boolean enable;
                if (MainFragment.this.mModels != null && MainFragment.this.mModels.size() > 0) {
                    MainFragment.this.mTopViewHeight = MainFragment.this.getResources().getDimensionPixelOffset(R.dimen.MAIN_HEADER_HEIGHT);
                    MainFragment.this.mPrevScrollY = MainFragment.this.getScrollY() + MainFragment.this.mTopViewHeight;
                    if (MainFragment.this.mPrevScrollY <= 0) {
                        enable = true;
                    } else {
                        enable = false;
                    }
                    MainFragment.this.mRefreshLayout.setEnabled(enable);
                    if (view.getId() == MainFragment.this.mListView.getId()) {
                        int currentFirstVisibleItem = MainFragment.this.mListView.getFirstVisiblePosition();
                        if (currentFirstVisibleItem > MainFragment.this.mLastFirstVisibleItem && firstVisibleItem + visibleItemCount != totalItemCount) {
                            ((MainActionBarActivity) MainFragment.this.getActivity()).animateCardLayout(false);
                            MainFragment.this.animateHeaderView(false);
                            MainFragment.this.mListTypeLabel.setOnClickListener(null);
                        } else if (currentFirstVisibleItem < MainFragment.this.mLastFirstVisibleItem) {
                            if (true != ((MainActionBarActivity) MainFragment.this.getActivity()).isMapMode()) {
                                ((MainActionBarActivity) MainFragment.this.getActivity()).animateCardLayout(true);
                                MainFragment.this.animateHeaderView(true);
                                MainFragment.this.mListTypeLabel.setOnClickListener(new OnClickListener() {
                                    public void onClick(View v) {
                                        if (MainFragment.this.mPopupWindow.isShowing()) {
                                            MainFragment.this.mPopupWindow.dismiss();
                                            return;
                                        }
                                        MainFragment.this.mPopupWindow.showAsDropDown(MainFragment.this.mListTypeLabel);
                                        MainFragment.this.mListTypeLabel.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.menu_arrow_up, 0);
                                    }
                                });
                            } else {
                                return;
                            }
                        }
                        MainFragment.this.mLastFirstVisibleItem = currentFirstVisibleItem;
                    }
                    if (MainFragment.this.mModels != null && MainFragment.this.mModels.size() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !MainFragment.this.mApiRequesting && MainFragment.this.mLoadingView.isShown()) {
                        if (MainFragment.this.mExternalParams != null) {
                            MainFragment.this.postStoreApiExternalParam();
                        } else {
                            MainFragment.this.postStoreApi(false);
                        }
                    }
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public int getScrollY() {
        View c = this.mListView.getChildAt(0);
        if (c == null) {
            return 0;
        }
        int firstVisiblePosition = this.mListView.getFirstVisiblePosition();
        int top = c.getTop();
        int headerHeight = 0;
        if (firstVisiblePosition >= 1) {
            headerHeight = this.mTopView.getHeight();
        }
        return (-top) + (c.getHeight() * firstVisiblePosition) + headerHeight;
    }

    /* access modifiers changed from: private */
    public void animateHeaderView(boolean isVisible) {
        if (isVisible) {
            if (this.mTopView.getVisibility() != 0) {
                this.mTopView.startAnimation(AnimationUtils.loadAnimation(getActivity(), R.anim.abc_slide_in_top));
                this.mTopView.setVisibility(0);
            }
        } else if (8 != this.mTopView.getVisibility()) {
            this.mTopView.startAnimation(AnimationUtils.loadAnimation(getActivity(), R.anim.abc_slide_out_top));
            this.mTopView.setVisibility(8);
        }
    }

    private void showHeaderView() {
        if (this.mTopView.getVisibility() != 0) {
            this.mTopView.startAnimation(AnimationUtils.loadAnimation(getActivity(), R.anim.abc_slide_in_top));
            this.mTopView.setVisibility(0);
        }
    }

    private String getQueryString(Bundle bundle) {
        String parameter = "?";
        for (String key : bundle.keySet()) {
            if (!key.equals("title")) {
                parameter = parameter + key + "=" + bundle.getString(key) + "&";
            }
        }
        if (parameter.endsWith("&")) {
            return parameter.substring(0, parameter.length() - 1);
        }
        return parameter;
    }

    public void postStoreApiExternalParam() {
        if (this.mExternalParams.getString("user_X") != null && this.mExternalParams.getString("user_X").equals("$user_X")) {
            double lat = 37.4986366d;
            double lng = 127.027021d;
            try {
                if (ShareatApp.getInstance().getGpsManager() != null) {
                    lat = ShareatApp.getInstance().getGpsManager().getLatitude();
                    lng = ShareatApp.getInstance().getGpsManager().getLongitude();
                }
                this.mExternalParams.putString("user_X", String.valueOf(lng));
                this.mExternalParams.putString("user_Y", String.valueOf(lat));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        this.mExternalParams.putString("page", String.valueOf(this.mPage));
        ((TextView) this.mTopView.findViewById(R.id.locationName)).setText(this.mExternalParams.getString("title", ""));
        ((TextView) this.mTopView.findViewById(R.id.locationType)).setText("");
        requestStoreListApi(getQueryString(this.mExternalParams), Integer.parseInt(this.mExternalParams.getString("view_cnt", "10")));
    }

    /* access modifiers changed from: private */
    public void postStoreApi(boolean isFirstLoad) {
        if (this.mParamsModel == null) {
            this.mParamsModel = new StoreParamsModel();
        }
        double lat = 37.4986366d;
        double lng = 127.027021d;
        try {
            if (ShareatApp.getInstance().getGpsManager() != null) {
                lat = ShareatApp.getInstance().getGpsManager().getLatitude();
                lng = ShareatApp.getInstance().getGpsManager().getLongitude();
            }
            this.mParamsModel.setUserX(String.valueOf(lng));
            this.mParamsModel.setUserY(String.valueOf(lat));
        } catch (Exception e) {
            e.printStackTrace();
        }
        LocationModel model = ParamManager.getInstance().getRecentSetModel();
        this.mParamsModel.setlType(ParamManager.getInstance().getSortType());
        this.mParamsModel.setAreaName(model.getAreaName());
        this.mParamsModel.setSearchAreaId(model.getAreaId());
        this.mParamsModel.setSearchCategoryId(ParamManager.getInstance().getCategory());
        ((TextView) this.mTopView.findViewById(R.id.locationType)).setText(model.getAreaName());
        if (model.getAreaName().equals("\ub0b4\uc8fc\ubcc0")) {
            ((TextView) this.mTopView.findViewById(R.id.locationName)).setText("");
            this.mParamsModel.setLimitDistance(ParamManager.getInstance().getLimitDistance());
        } else {
            ((TextView) this.mTopView.findViewById(R.id.locationName)).setText("");
            this.mParamsModel.setLimitDistance(0);
        }
        requestStoreListApi(this.mParamsModel);
    }

    /* access modifiers changed from: private */
    public void requestStoreListApi(final String parameter, final int viewCount) {
        this.mApiRequesting = true;
        StoreListApi request = new StoreListApi(getActivity());
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                StoreResultModel resultModel = (StoreResultModel) result;
                ((MainActivity) MainFragment.this.getActivity()).showMainListLoading(false);
                if (MainFragment.this.mPage == 1) {
                    MainFragment.this.mModels.clear();
                    MainFragment.this.mModels.addAll(resultModel.getResultList());
                    MainFragment.this.mAdapter.setHeadPeriodText(resultModel.getHead_period_text());
                    if (MainFragment.this.mListView.getFooterViewsCount() == 0) {
                        MainFragment.this.mListView.addFooterView(MainFragment.this.mLoadingView);
                    }
                    MainFragment.this.mListView.setAdapter(MainFragment.this.mAdapter);
                } else if (resultModel.getResultList().size() > 0) {
                    MainFragment.this.mModels.addAll(resultModel.getResultList());
                    MainFragment.this.mAdapter.notifyDataSetChanged();
                }
                if (viewCount <= resultModel.getResultList().size() || MainFragment.this.mListView.getFooterViewsCount() <= 0) {
                    MainFragment.this.mPage = MainFragment.this.mPage + 1;
                } else {
                    MainFragment.this.mListView.removeFooterView(MainFragment.this.mLoadingView);
                }
                MainFragment.this.mRefreshLayout.setRefreshing(false);
                MainFragment.this.setSubTitle(ParamManager.getInstance().getSortType());
                if (MainFragment.this.mModels.size() != 0) {
                    MainFragment.this.mMapBtn.setVisibility(0);
                    if (((MainActivity) MainFragment.this.getActivity()) != null) {
                        ((MainActivity) MainFragment.this.getActivity()).hideLocationGuideView();
                        ((MainActivity) MainFragment.this.getActivity()).showCardViewAnimation();
                    }
                } else if (true != ((MainActivity) MainFragment.this.getActivity()).isMapMode()) {
                    MainFragment.this.mMapBtn.setVisibility(8);
                    MainFragment.this.requestRecommendLookAround();
                }
            }

            public void onFailure(Exception exception) {
                if (MainFragment.this.getActivity() != null) {
                    ((BaseActivity) MainFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            MainFragment.this.requestStoreListApi(parameter, viewCount);
                        }
                    }, null);
                }
            }

            public void onFinish() {
                MainFragment.this.mApiRequesting = false;
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestRecommendLookAround() {
        RecommendLookAroundApi request = new RecommendLookAroundApi(getActivity());
        Object[] objArr = new Object[3];
        objArr[0] = ShareatApp.getInstance().getAppVersionName();
        objArr[1] = String.valueOf(ShareatApp.getInstance().getGpsManager() == null ? 127.027021d : ShareatApp.getInstance().getGpsManager().getLatitude());
        objArr[2] = String.valueOf(ShareatApp.getInstance().getGpsManager() == null ? 37.4986366d : ShareatApp.getInstance().getGpsManager().getLongitude());
        request.addGetParam(String.format("?os=A&app_version=%s&user_X=%s&user_Y=%s", objArr));
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                if (MainFragment.this.mRecommendLookAroundModel != null) {
                    MainFragment.this.mRecommendLookAroundModel = null;
                }
                MainFragment.this.mRecommendLookAroundModel = (RecommendLookAroundModel) result;
                MainFragment.this.setEmptyAdapter();
                if (MainFragment.this.getActivity() != null) {
                    MainFragment.this.getActivity().findViewById(R.id.cardView).setVisibility(8);
                }
            }

            public void onFailure(Exception exception) {
                super.onFailure(exception);
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestStoreListApi(final StoreParamsModel model) {
        this.mApiRequesting = true;
        String parameter = ((((((("" + String.format("?list_type=%s", new Object[]{model.getListType(model.getlType())})) + String.format("&order_type=%s", new Object[]{model.getOrder_Type()})) + String.format("&user_X=%s", new Object[]{model.getUserX()})) + String.format("&user_Y=%s", new Object[]{model.getUserY()})) + String.format("&page=%d", new Object[]{Integer.valueOf(this.mPage)})) + String.format("&view_cnt=%d", new Object[]{Integer.valueOf(model.getViewCount())})) + String.format("&search_name=%s", new Object[]{model.getSearchName()})) + String.format("&search_category_id=%s", new Object[]{model.getSearchCategoryId()});
        if (model.getLimitDistance() > 0) {
            parameter = parameter + String.format("&limit_distance=%d", new Object[]{Integer.valueOf(model.getLimitDistance())});
        }
        String parameter2 = parameter + String.format("&search_area_id=%s", new Object[]{model.getSearchAreaId()});
        StoreListApi request = new StoreListApi(getActivity());
        request.addGetParam(parameter2);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                StoreResultModel resultModel = (StoreResultModel) result;
                ((MainActivity) MainFragment.this.getActivity()).showMainListLoading(false);
                if (MainFragment.this.mPage == 1) {
                    MainFragment.this.mModels.clear();
                    MainFragment.this.mModels.addAll(resultModel.getResultList());
                    MainFragment.this.mAdapter.setHeadPeriodText(resultModel.getHead_period_text());
                    if (MainFragment.this.mListView.getFooterViewsCount() == 0) {
                        MainFragment.this.mListView.addFooterView(MainFragment.this.mLoadingView);
                    }
                    MainFragment.this.mListView.setAdapter(MainFragment.this.mAdapter);
                } else if (resultModel.getResultList().size() > 0) {
                    MainFragment.this.mModels.addAll(resultModel.getResultList());
                    MainFragment.this.mAdapter.notifyDataSetChanged();
                }
                if (model.getViewCount() <= resultModel.getResultList().size() || MainFragment.this.mListView.getFooterViewsCount() <= 0) {
                    MainFragment.this.mPage = MainFragment.this.mPage + 1;
                } else {
                    MainFragment.this.mListView.removeFooterView(MainFragment.this.mLoadingView);
                }
                MainFragment.this.mRefreshLayout.setRefreshing(false);
                MainFragment.this.setSubTitle(model.getlType());
                if (MainFragment.this.mModels.size() != 0) {
                    MainFragment.this.mMapBtn.setVisibility(0);
                    if (((MainActivity) MainFragment.this.getActivity()) != null) {
                        ((MainActivity) MainFragment.this.getActivity()).hideLocationGuideView();
                        ((MainActivity) MainFragment.this.getActivity()).showCardViewAnimation();
                    }
                } else if (true != ((MainActivity) MainFragment.this.getActivity()).isMapMode()) {
                    MainFragment.this.mMapBtn.setVisibility(8);
                    MainFragment.this.requestRecommendLookAround();
                }
            }

            public void onFailure(Exception exception) {
                if (MainFragment.this.getActivity() != null) {
                    ((BaseActivity) MainFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            MainFragment.this.requestStoreListApi(model);
                        }
                    }, null);
                }
            }

            public void onFinish() {
                MainFragment.this.mApiRequesting = false;
                if (ShareatApp.getInstance().getAppStartTime() != -1) {
                    r4 = R.string.app_loading_time;
                    r5 = R.string.app_loading_time;
                    GAEvent.onUserTimings(MainFragment.this.getActivity(), R.string.app_loading_time, System.currentTimeMillis() - ShareatApp.getInstance().getAppStartTime(), R.string.app_loading_time, R.string.app_loading_time);
                    ShareatApp.getInstance().setAppStartTime(-1);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void setSubTitle(int listType) {
        String subTitle;
        this.mListTypeView.findViewById(R.id.distanceType).setSelected(false);
        this.mListTypeView.findViewById(R.id.eventType).setSelected(false);
        this.mListTypeView.findViewById(R.id.popularType).setSelected(false);
        this.mListTypeView.findViewById(R.id.payCountType).setSelected(false);
        switch (listType) {
            case 0:
                subTitle = "\ucd5c\uadfc \uc5c5\ub370\uc774\ud2b8\uc21c";
                this.mListTypeView.findViewById(R.id.eventType).setSelected(true);
                break;
            case 6:
                subTitle = "\ub9ac\ubdf0 \ub9ce\uc740\uc21c";
                this.mListTypeView.findViewById(R.id.popularType).setSelected(true);
                break;
            case 7:
                subTitle = "\uacb0\uc81c \ub9ce\uc740 \uc21c";
                this.mListTypeView.findViewById(R.id.payCountType).setSelected(true);
                break;
            default:
                subTitle = "\uac00\uae4c\uc6b4 \uac70\ub9ac\uc21c";
                this.mListTypeView.findViewById(R.id.distanceType).setSelected(true);
                break;
        }
        ((TextView) this.mTopView.findViewById(R.id.listTypeLable)).setText(subTitle);
    }

    public int getStoreListCount() {
        if (this.mAdapter == null) {
            return 0;
        }
        return this.mAdapter.getCount();
    }

    public void setUserVisibleHint(boolean isVisibleToUser) {
        super.setUserVisibleHint(isVisibleToUser);
    }
}