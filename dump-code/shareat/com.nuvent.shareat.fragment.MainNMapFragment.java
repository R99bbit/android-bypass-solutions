package com.nuvent.shareat.fragment;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.BitmapDrawable;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.content.ContextCompat;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.view.animation.AnimationUtils;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.PopupWindow;
import android.widget.PopupWindow.OnDismissListener;
import android.widget.TextView;
import android.widget.Toast;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import com.naver.maps.geometry.LatLng;
import com.naver.maps.map.CameraAnimation;
import com.naver.maps.map.CameraPosition;
import com.naver.maps.map.CameraUpdate;
import com.naver.maps.map.MapFragment;
import com.naver.maps.map.NaverMap;
import com.naver.maps.map.OnMapReadyCallback;
import com.naver.maps.map.overlay.InfoWindow;
import com.naver.maps.map.overlay.InfoWindow.DefaultTextAdapter;
import com.naver.maps.map.overlay.Marker;
import com.naver.maps.map.overlay.Overlay;
import com.naver.maps.map.overlay.OverlayImage;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.MapDataApi;
import com.nuvent.shareat.dialog.CouponMapDialog;
import com.nuvent.shareat.dialog.CouponMapDialog.onClickDialog;
import com.nuvent.shareat.event.GpsRefreshEvent;
import com.nuvent.shareat.event.GpsRegistEvent;
import com.nuvent.shareat.event.PaySuccessEvent;
import com.nuvent.shareat.event.PostGnbOptionEvent;
import com.nuvent.shareat.event.SchemeMainlistEvent;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.ParamManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.MapDataDetailModel;
import com.nuvent.shareat.model.MapDataModel;
import com.nuvent.shareat.model.store.LocationModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.model.store.StoreParamsModel;
import com.nuvent.shareat.util.ExternalApp;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.ShareAtUtil;
import com.nuvent.shareat.widget.view.CardView;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import net.xenix.util.ImageDisplay;

public class MainNMapFragment extends Fragment implements OnMapReadyCallback {
    private static final boolean DEBUG = false;
    private static final String LOG_TAG = "NMapViewer";
    private CameraPosition mCameraPosition;
    private Bundle mExternalParams;
    /* access modifiers changed from: private */
    public InfoWindow mInfoWindow = new InfoWindow();
    private boolean mInitMapLogoPosition = false;
    /* access modifiers changed from: private */
    public boolean mIsCurrentPositionClicked = false;
    private ImageButton mListBtn;
    /* access modifiers changed from: private */
    public TextView mListTypeLabel;
    /* access modifiers changed from: private */
    public View mListTypeView;
    /* access modifiers changed from: private */
    public ArrayList<Marker> mMakerManager = new ArrayList<>();
    /* access modifiers changed from: private */
    public MapDataModel mMapDataModel;
    private MapDataPagerAdapter mMapDataPagerAdapter;
    /* access modifiers changed from: private */
    public ViewPager mMapTickerViewPager;
    /* access modifiers changed from: private */
    public NMapHideListener mNMapHideListener;
    /* access modifiers changed from: private */
    public NaverMap mNaverMap;
    /* access modifiers changed from: private */
    public int mOldMarkerIndex = -1;
    private StoreParamsModel mParamsModel;
    /* access modifiers changed from: private */
    public PopupWindow mPopupWindow;
    /* access modifiers changed from: private */
    public View mTopView;
    /* access modifiers changed from: private */
    public View mView;
    private Marker myPosition;

    public class MapDataPagerAdapter extends PagerAdapter {
        private Context mContext;
        private ArrayList<MapDataDetailModel> mMapDataDetailModel = new ArrayList<>();

        public MapDataPagerAdapter(Context context, ArrayList<MapDataDetailModel> model) {
            this.mContext = context;
            this.mMapDataDetailModel = model;
        }

        public void notifyDataSetChanged(Context context, ArrayList<MapDataDetailModel> model) {
            this.mContext = context;
            this.mMapDataDetailModel = model;
            super.notifyDataSetChanged();
        }

        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
        }

        public int getItemPosition(Object object) {
            return -2;
        }

        public float getPageWidth(int position) {
            return 0.94f;
        }

        public int getCount() {
            if (this.mMapDataDetailModel == null) {
                return 0;
            }
            return this.mMapDataDetailModel.size();
        }

        public boolean isViewFromObject(View view, Object object) {
            return view == object;
        }

        public Object instantiateItem(ViewGroup container, int position) {
            View view = View.inflate(this.mContext, R.layout.main_map_bottom_ticker, null);
            final MapDataDetailModel mapDataDetailModel = this.mMapDataDetailModel.get(position);
            if (mapDataDetailModel != null) {
                ImageDisplay.getInstance().displayImageLoad(mapDataDetailModel.getImgPath(), (ImageView) view.findViewById(R.id.tickerBranchImg));
                ((TextView) view.findViewById(R.id.partnerName1)).setText(mapDataDetailModel.getPartnerName1());
                ((TextView) view.findViewById(R.id.categoryName)).setText(mapDataDetailModel.getCategoryName());
                ((TextView) view.findViewById(R.id.addressAndDistance)).setText(mapDataDetailModel.getDongName() + " " + ShareAtUtil.getDistanceMark(mapDataDetailModel.getDistance()));
                int discount = mapDataDetailModel.getDcRate();
                if (discount <= 0) {
                    view.findViewById(R.id.discountLayout).setVisibility(8);
                } else {
                    view.findViewById(R.id.discountLayout).setVisibility(0);
                    ((TextView) view.findViewById(R.id.branchDiscount)).setText(discount + "%");
                }
                String couponName = mapDataDetailModel.getCouponName();
                if (true == couponName.isEmpty() || true == "-".equals(couponName)) {
                    view.findViewById(R.id.branchCoupon).setVisibility(8);
                } else {
                    view.findViewById(R.id.branchCoupon).setVisibility(0);
                    ((TextView) view.findViewById(R.id.branchCoupon)).setText(couponName);
                }
                view.findViewById(R.id.tickerLayout).setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_nmap_name, (int) R.string.ga_nmap_list_item_click, (int) R.string.ga_nmap_store_detail);
                        MainNMapFragment.this.storeDetail(mapDataDetailModel.getPartnerSno());
                    }
                });
                view.findViewById(R.id.callBtn).setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_nmap_name, (int) R.string.ga_nmap_list_item_click, (int) R.string.ga_nmap_branch_call);
                        if (true == mapDataDetailModel.getTel01().isEmpty()) {
                            Toast.makeText(MainNMapFragment.this.getActivity(), MainNMapFragment.this.getResources().getString(R.string.branch_call_number_not_exist), 1).show();
                            return;
                        }
                        MainNMapFragment.this.startActivity(new Intent("android.intent.action.DIAL", Uri.parse("tel:" + mapDataDetailModel.getTel01())));
                    }
                });
                view.findViewById(R.id.searchRoadBtn).setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_nmap_name, (int) R.string.ga_nmap_list_item_click, (int) R.string.ga_nmap_search_road);
                        MainNMapFragment.this.searchRoadMap(mapDataDetailModel);
                    }
                });
                view.findViewById(R.id.quickPay).setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_nmap_name, (int) R.string.ga_nmap_list_item_click, (int) R.string.ga_nmap_quick_payment);
                        if (true != mapDataDetailModel.getCouponName().isEmpty() && true != "-".equals(mapDataDetailModel.getCouponName())) {
                            CouponMapDialog dialog = new CouponMapDialog(MainNMapFragment.this.getContext(), mapDataDetailModel.getCouponName(), mapDataDetailModel.getCouponGroupSno());
                            dialog.setOnClickDialogListener(new onClickDialog() {
                                public void onClickDownload() {
                                    GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_nmap_coupon_download_name, (int) R.string.ga_nmap_coupon_download_name, (int) R.string.ga_nmap_coupon_download);
                                    new Handler().postDelayed(new Runnable() {
                                        public void run() {
                                            if (SessionManager.getInstance().hasSession()) {
                                                MainNMapFragment.this.quickPay(mapDataDetailModel);
                                            } else if (((MainActivity) MainNMapFragment.this.getActivity()) != null) {
                                                ((MainActivity) MainNMapFragment.this.getActivity()).showLoginDialog();
                                            }
                                        }
                                    }, 1000);
                                }

                                public void onClickDownloadSkip() {
                                    GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_nmap_coupon_download_name, (int) R.string.ga_nmap_coupon_download_name, (int) R.string.ga_nmap_coupon_download_skip);
                                    MainNMapFragment.this.quickPay(mapDataDetailModel);
                                }
                            });
                            dialog.show();
                        } else if (SessionManager.getInstance().hasSession()) {
                            MainNMapFragment.this.quickPay(mapDataDetailModel);
                        } else if (((MainActivity) MainNMapFragment.this.getActivity()) != null) {
                            ((MainActivity) MainNMapFragment.this.getActivity()).showLoginDialog();
                        }
                    }
                });
                container.addView(view);
            }
            return view;
        }

        public void destroyItem(ViewGroup container, int position, Object object) {
            container.removeView((View) object);
        }

        public MapDataDetailModel getItem(int position) {
            return this.mMapDataDetailModel.get(position);
        }
    }

    public interface NMapHideListener {
        void onNMapHide();
    }

    public void addNMapHideListener(NMapHideListener listener) {
        if (this.mNMapHideListener == null || this.mNMapHideListener != listener) {
            this.mNMapHideListener = listener;
        }
    }

    public void removeNMapHideListener() {
        this.mNMapHideListener = null;
    }

    public void onMapReady(@NonNull NaverMap naverMap) {
        naverMap.getUiSettings().setZoomControlEnabled(false);
        this.mInfoWindow.setAdapter(new DefaultTextAdapter(getContext()) {
            @NonNull
            public CharSequence getText(@NonNull InfoWindow infoWindow) {
                return (CharSequence) infoWindow.getMarker().getTag();
            }
        });
        this.mInfoWindow.setOnClickListener(new Overlay.OnClickListener() {
            public boolean onClick(@NonNull Overlay overlay) {
                if (MainNMapFragment.this.mMakerManager == null || MainNMapFragment.this.mMapDataModel == null || MainNMapFragment.this.mMapDataModel.getResult_list() == null) {
                    return false;
                }
                MainNMapFragment.this.storeDetail(MainNMapFragment.this.mMapDataModel.getResult_list().get(MainNMapFragment.this.mMakerManager.indexOf(((InfoWindow) overlay).getMarker())).getPartnerSno());
                return true;
            }
        });
        this.mNaverMap = naverMap;
    }

    public void updateMap() {
        if (this.mMakerManager != null) {
            Marker marker = this.mMakerManager.get(0);
            if (this.mMapDataModel != null) {
                String eventType = this.mMapDataModel.getResult_list().get(0).getEventType();
                char c = 65535;
                switch (eventType.hashCode()) {
                    case 67:
                        if (eventType.equals("C")) {
                            c = 1;
                            break;
                        }
                        break;
                    case 69:
                        if (eventType.equals("E")) {
                            c = 0;
                            break;
                        }
                        break;
                }
                switch (c) {
                    case 0:
                        marker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_e_02));
                        break;
                    case 1:
                        marker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_c_02));
                        break;
                    default:
                        marker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_02));
                        break;
                }
            }
            marker.setZIndex(this.mMakerManager.size());
            marker.setMap(null);
            marker.setMap(this.mNaverMap);
            this.mCameraPosition = new CameraPosition(marker.getPosition(), this.mNaverMap.getMinZoom() + 11.0d);
            this.mNaverMap.setCameraPosition(this.mCameraPosition);
            this.mInfoWindow.open(marker);
            this.mOldMarkerIndex = 0;
        }
    }

    public void setSelectMarker(int index) {
        boolean z;
        boolean z2;
        if (this.mMakerManager != null) {
            Marker marker = this.mMakerManager.get(index);
            if (this.mMapDataModel != null) {
                String eventType = this.mMapDataModel.getResult_list().get(index).getEventType();
                switch (eventType.hashCode()) {
                    case 67:
                        if (eventType.equals("C")) {
                            z2 = true;
                            break;
                        }
                    case 69:
                        if (eventType.equals("E")) {
                            z2 = false;
                            break;
                        }
                    default:
                        z2 = true;
                        break;
                }
                switch (z2) {
                    case false:
                        marker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_e_02));
                        break;
                    case true:
                        marker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_c_02));
                        break;
                    default:
                        marker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_02));
                        break;
                }
            }
            marker.setZIndex(this.mMakerManager.size());
            if (!(this.mOldMarkerIndex == -1 || this.mOldMarkerIndex == index)) {
                Marker oldMarker = this.mMakerManager.get(this.mOldMarkerIndex);
                if (this.mMapDataModel != null) {
                    String eventType2 = this.mMapDataModel.getResult_list().get(this.mOldMarkerIndex).getEventType();
                    switch (eventType2.hashCode()) {
                        case 67:
                            if (eventType2.equals("C")) {
                                z = true;
                                break;
                            }
                        case 69:
                            if (eventType2.equals("E")) {
                                z = false;
                                break;
                            }
                        default:
                            z = true;
                            break;
                    }
                    switch (z) {
                        case false:
                            oldMarker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_e_01));
                            break;
                        case true:
                            oldMarker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_c_01));
                            break;
                        default:
                            oldMarker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_01));
                            break;
                    }
                }
                oldMarker.setZIndex(this.mOldMarkerIndex);
            }
            this.mNaverMap.moveCamera(CameraUpdate.scrollTo(marker.getPosition()).animate(CameraAnimation.Easing));
            this.mInfoWindow.open(marker);
        }
    }

    public void initMap() {
    }

    private void setWindowFocusChanged() {
        this.mView.getViewTreeObserver().addOnGlobalLayoutListener(new OnGlobalLayoutListener() {
            public void onGlobalLayout() {
                if (VERSION.SDK_INT >= 16) {
                    MainNMapFragment.this.mView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                } else {
                    MainNMapFragment.this.mView.getViewTreeObserver().removeGlobalOnLayoutListener(this);
                }
            }
        });
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        ShareatApp.getInstance();
        ShareatApp.LOG_INFO("MainNMapFragment onCreateView() Call");
        EventBus.getDefault().register(this);
        this.mView = inflater.inflate(R.layout.fragment_main_nmap, container, false);
        this.mExternalParams = ((MainActivity) getActivity()).getExternalParams();
        setWindowFocusChanged();
        return this.mView;
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        onLoadMap(this.mView);
        setHeader(this.mView);
        setListTypePopup();
        if (this.mExternalParams != null) {
            postStoreApiExternalParam(this.mExternalParams);
            requestExternalMapData(this.mExternalParams);
        } else if (!isGpsAvailable()) {
            postStoreApi(true);
            setSubTitle(this.mParamsModel.getlType());
            requestMapData(Double.parseDouble(this.mParamsModel.getUserX()), Double.parseDouble(this.mParamsModel.getUserY()));
        }
    }

    public void onStart() {
        ShareatApp.getInstance();
        ShareatApp.LOG_INFO("MainNMapFragment onStart() Call");
        super.onStart();
        MainActivity ma = (MainActivity) getActivity();
        if (ma != null && true == ma.isCurrentFragment(ma.getPagerAdapter().getStoreFragment())) {
        }
    }

    public void onResume() {
        ShareatApp.getInstance();
        ShareatApp.LOG_INFO("MainNMapFragment onResume() Call");
        super.onResume();
        MainActivity ma = (MainActivity) getActivity();
        if (ma != null && true == ma.isCurrentFragment(ma.getPagerAdapter().getStoreFragment())) {
        }
    }

    public void onPause() {
        super.onPause();
        MainActivity ma = (MainActivity) getActivity();
        if (ma != null && true == ma.isCurrentFragment(ma.getPagerAdapter().getStoreFragment())) {
        }
    }

    public void onStop() {
        MainActivity ma = (MainActivity) getActivity();
        if (ma == null && true == ma.isCurrentFragment(ma.getPagerAdapter().getStoreFragment())) {
            super.onStop();
        } else {
            super.onStop();
        }
    }

    public void onDestroyView() {
        super.onDestroyView();
        EventBus.getDefault().unregister(this);
    }

    public void onDestroy() {
        MainActivity ma = (MainActivity) getActivity();
        if (ma == null && true == ma.isCurrentFragment(ma.getPagerAdapter().getStoreFragment())) {
            super.onDestroy();
        } else {
            super.onDestroy();
        }
    }

    private void setHeader(View view) {
        this.mTopView = view.findViewById(R.id.topView);
        this.mTopView.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                MainNMapFragment.this.initMap();
                if (((MainActivity) MainNMapFragment.this.getActivity()) != null) {
                    ((MainActivity) MainNMapFragment.this.getActivity()).onClickLocation(null);
                }
            }
        });
        this.mListTypeLabel = (TextView) view.findViewById(R.id.listTypeLable);
    }

    /* access modifiers changed from: private */
    public void setTicker() {
        if (this.mView != null) {
            if (this.mMapTickerViewPager == null) {
                this.mMapTickerViewPager = (ViewPager) this.mView.findViewById(R.id.map_bottom_ticker_pager);
            }
            if (this.mMapTickerViewPager != null) {
                if (this.mMapDataPagerAdapter == null) {
                    this.mMapDataPagerAdapter = new MapDataPagerAdapter(getActivity(), this.mMapDataModel == null ? new ArrayList<>() : this.mMapDataModel.getResult_list());
                } else {
                    this.mMapDataPagerAdapter.notifyDataSetChanged(getActivity(), this.mMapDataModel == null ? new ArrayList<>() : this.mMapDataModel.getResult_list());
                }
                this.mMapTickerViewPager.setAdapter(this.mMapDataPagerAdapter);
                this.mMapTickerViewPager.addOnPageChangeListener(new OnPageChangeListener() {
                    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                    }

                    public void onPageSelected(int position) {
                        MainNMapFragment.this.setSelectMarker(position);
                        MainNMapFragment.this.mOldMarkerIndex = position;
                    }

                    public void onPageScrollStateChanged(int state) {
                    }
                });
            }
        }
    }

    /* access modifiers changed from: private */
    public void storeDetail(String partnerSno) {
        CustomSchemeManager.postSchemeAction(getActivity(), "shareat://shareat.me/store?" + "partner_sno=" + partnerSno);
    }

    /* access modifiers changed from: private */
    public void quickPay(MapDataDetailModel mapDataDetailModel) {
        StoreModel storeModel = new StoreModel();
        storeModel.partnerName1 = mapDataDetailModel.getPartnerName1();
        storeModel.partnerSno = String.valueOf(mapDataDetailModel.getPartnerSno());
        storeModel.setDcRate(mapDataDetailModel.getDcRate());
        storeModel.couponName = mapDataDetailModel.getCouponName();
        storeModel.couponGroupSno = mapDataDetailModel.getCouponGroupSno();
        storeModel.categoryName = mapDataDetailModel.getCategoryName();
        storeModel.setBarcode(!mapDataDetailModel.getPayMethod());
        storeModel.setAutoBranchYn("Y");
        try {
            storeModel.distance = String.valueOf(mapDataDetailModel.getDistance());
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (getActivity() != null) {
            ((CardView) getActivity().findViewById(R.id.cardView)).setOpenPasswordView(true);
            ((CardView) getActivity().findViewById(R.id.cardView)).setStoreModel(storeModel);
            ((CardView) getActivity().findViewById(R.id.cardView)).setQuickMode(true);
            getActivity().findViewById(R.id.cardView).startAnimation(AnimationUtils.loadAnimation(getActivity(), R.anim.abc_slide_in_bottom));
            getActivity().findViewById(R.id.cardView).setVisibility(0);
            ((MainActionBarActivity) getActivity()).openCardView();
        }
    }

    /* access modifiers changed from: private */
    public void searchRoadMap(MapDataDetailModel mapDataDetailModel) {
        HashMap<String, String> paramHashMap = new HashMap<>();
        paramHashMap.put("elat", String.valueOf(mapDataDetailModel.getMapY()));
        paramHashMap.put("elng", String.valueOf(mapDataDetailModel.getMapX()));
        paramHashMap.put("etitle", Uri.decode(mapDataDetailModel.getPartnerName1()));
        StringBuilder localStringBuilder = new StringBuilder("navermaps://?version=4&appname=nu");
        localStringBuilder.append("&menu=route");
        for (String key : paramHashMap.keySet()) {
            String value = paramHashMap.get(key);
            if (!TextUtils.isEmpty(value)) {
                localStringBuilder.append("&").append(key).append("=").append(value);
            }
        }
        Intent mapIntent = new Intent("android.intent.action.VIEW", Uri.parse(localStringBuilder.toString()));
        mapIntent.addCategory("android.intent.category.BROWSABLE");
        if (!ExternalApp.onInstallApp(getActivity(), (int) R.string.NAVER_MAP_INSTALL_CONFIRM_MSG, mapIntent, (String) ExternalApp.NAVER_MAP)) {
            startActivity(mapIntent);
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
            GAEvent.onGACustomDimensions(getActivity(), getString(R.string.ga_nmap_screen), dimensions);
            if (true == this.mIsCurrentPositionClicked) {
                this.mIsCurrentPositionClicked = false;
                if (ShareatApp.getInstance().getGpsManager() == null || true != ShareatApp.getInstance().getGpsManager().isGetLocation()) {
                    GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_enable_gps_name, (int) R.string.ga_enable_gps_result, getString(R.string.ga_enable_gps_result_value, "OFF"));
                    return;
                }
                setCurrentPOI();
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.ga_enable_gps_name, (int) R.string.ga_enable_gps_result, getString(R.string.ga_enable_gps_result_value, "ON"));
            }
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

    public void onEventMainThread(PaySuccessEvent event) {
        this.mExternalParams = null;
        postStoreApi(false);
        requestMapData(Double.parseDouble(this.mParamsModel.getUserX()), Double.parseDouble(this.mParamsModel.getUserY()));
        setSubTitle(ParamManager.getInstance().getSortType());
    }

    public void onEventMainThread(GpsRefreshEvent event) {
        if (this.mExternalParams == null) {
            postStoreApi(false);
            setSubTitle(this.mParamsModel.getlType());
            requestMapData(Double.parseDouble(this.mParamsModel.getUserX()), Double.parseDouble(this.mParamsModel.getUserY()));
        }
    }

    public void onEventMainThread(PostGnbOptionEvent event) {
        this.mExternalParams = null;
        postStoreApi(false);
        requestMapData(Double.parseDouble(this.mParamsModel.getUserX()), Double.parseDouble(this.mParamsModel.getUserY()));
        setSubTitle(ParamManager.getInstance().getSortType());
    }

    public void onEventMainThread(SchemeMainlistEvent event) {
        Bundle params = event.getParams();
        this.mExternalParams = params;
        if (params != null) {
            postStoreApiExternalParam(this.mExternalParams);
            requestExternalMapData(this.mExternalParams);
        }
    }

    public void postStoreApiExternalParam(Bundle externalBundle) {
        if (externalBundle.getString("user_X") != null && externalBundle.getString("user_X").equals("$user_X")) {
            double lat = 37.4986366d;
            double lng = 127.027021d;
            try {
                if (ShareatApp.getInstance().getGpsManager() != null) {
                    lat = ShareatApp.getInstance().getGpsManager().getLatitude();
                    lng = ShareatApp.getInstance().getGpsManager().getLongitude();
                }
                externalBundle.putString("user_X", String.valueOf(lng));
                externalBundle.putString("user_Y", String.valueOf(lat));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        ((TextView) this.mTopView.findViewById(R.id.locationName)).setText(externalBundle.getString("title", ""));
        ((TextView) this.mTopView.findViewById(R.id.locationType)).setText("");
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

    private void postStoreApi(boolean isFirstLoad) {
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
            return;
        }
        ((TextView) this.mTopView.findViewById(R.id.locationName)).setText("");
        this.mParamsModel.setLimitDistance(0);
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
                if (MainNMapFragment.this.getActivity() != null && ((MainActivity) MainNMapFragment.this.getActivity()).isStoreClick()) {
                    return;
                }
                if (MainNMapFragment.this.mPopupWindow.isShowing()) {
                    MainNMapFragment.this.mPopupWindow.dismiss();
                } else {
                    MainNMapFragment.this.mListTypeLabel.postDelayed(new Runnable() {
                        public void run() {
                            if (MainNMapFragment.this.getActivity() == null || !((MainActivity) MainNMapFragment.this.getActivity()).isStoreClick()) {
                                MainNMapFragment.this.mPopupWindow.showAsDropDown(MainNMapFragment.this.mListTypeLabel);
                                MainNMapFragment.this.mListTypeLabel.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.menu_arrow_up, 0);
                            }
                        }
                    }, 100);
                }
            }
        });
        this.mListTypeView.findViewById(R.id.eventType).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                v.setSelected(true);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.distanceType).setSelected(false);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.popularType).setSelected(false);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.payCountType).setSelected(false);
                GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.quickSort, (int) R.string.quickSort_event);
                ParamManager.getInstance().setSortType(0);
                EventBus.getDefault().post(new PostGnbOptionEvent(true));
                MainNMapFragment.this.mPopupWindow.dismiss();
                MainNMapFragment.this.mListTypeLabel.setText(((TextView) v).getText().toString());
            }
        });
        this.mListTypeView.findViewById(R.id.distanceType).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                v.setSelected(true);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.eventType).setSelected(false);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.popularType).setSelected(false);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.payCountType).setSelected(false);
                GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.quickSort, (int) R.string.quickSort_distance);
                ParamManager.getInstance().setSortType(1);
                EventBus.getDefault().post(new PostGnbOptionEvent(true));
                MainNMapFragment.this.mPopupWindow.dismiss();
                MainNMapFragment.this.mListTypeLabel.setText(((TextView) v).getText().toString());
            }
        });
        this.mListTypeView.findViewById(R.id.payCountType).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                v.setSelected(true);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.eventType).setSelected(false);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.distanceType).setSelected(false);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.popularType).setSelected(false);
                GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.quickSort, (int) R.string.quickSort_paycount);
                ParamManager.getInstance().setSortType(7);
                EventBus.getDefault().post(new PostGnbOptionEvent(true));
                MainNMapFragment.this.mPopupWindow.dismiss();
                MainNMapFragment.this.mListTypeLabel.setText(((TextView) v).getText().toString());
            }
        });
        this.mListTypeView.findViewById(R.id.popularType).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                v.setSelected(true);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.eventType).setSelected(false);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.distanceType).setSelected(false);
                MainNMapFragment.this.mListTypeView.findViewById(R.id.payCountType).setSelected(false);
                GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_storelist, (int) R.string.quickSort, (int) R.string.quickSort_review);
                ParamManager.getInstance().setSortType(6);
                EventBus.getDefault().post(new PostGnbOptionEvent(true));
                MainNMapFragment.this.mPopupWindow.dismiss();
                MainNMapFragment.this.mListTypeLabel.setText(((TextView) v).getText().toString());
            }
        });
        this.mPopupWindow.setOnDismissListener(new OnDismissListener() {
            public void onDismiss() {
                MainNMapFragment.this.mListTypeLabel.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.menu_arrow_down, 0);
            }
        });
    }

    private String getSubTitle() {
        switch (this.mParamsModel.getlType()) {
            case 0:
                return "event";
            case 6:
                return StoreDetailFragment.SUB_TAB_NAME_REVIEW;
            case 7:
                return "cnt_pay";
            default:
                return "distance";
        }
    }

    private void setSubTitle(int listType) {
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

    private float dpToPx(Context context, int dp) {
        DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
        return (float) ((context.getResources().getDisplayMetrics().densityDpi / 160) * dp);
    }

    public void onLoadMap(View view) {
        FragmentManager fm = getActivity().getSupportFragmentManager();
        MapFragment mMapView = (MapFragment) fm.findFragmentById(R.id.nmapView);
        if (mMapView != null) {
            fm.beginTransaction().remove(mMapView);
        }
        MapFragment mMapView2 = MapFragment.newInstance();
        fm.beginTransaction().add((int) R.id.nmapView, (Fragment) mMapView2).commit();
        mMapView2.getMapAsync(this);
        this.mListBtn = (ImageButton) view.findViewById(R.id.listBtn);
        this.mListBtn.getBackground().setAlpha(229);
        this.mListBtn.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (MainNMapFragment.this.mNMapHideListener != null) {
                    MainNMapFragment.this.mNMapHideListener.onNMapHide();
                }
                GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_nmap_name, (int) R.string.ga_nmap_floating_click, (int) R.string.ga_nmap_listbtn_click);
            }
        });
        view.findViewById(R.id.currentPositionBtn).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_nmap_name, (int) R.string.ga_nmap_menu, (int) R.string.ga_nmap_my_location);
                MainNMapFragment.this.setCurrentPOI();
            }
        });
        view.findViewById(R.id.researchBtn).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) MainNMapFragment.this.getActivity(), (int) R.string.ga_nmap_name, (int) R.string.ga_nmap_menu, (int) R.string.ga_nmap_research);
                if (MainNMapFragment.this.mNaverMap != null) {
                    CameraPosition cameraPosition = MainNMapFragment.this.mNaverMap.getCameraPosition();
                    MainNMapFragment.this.requestMapData(cameraPosition.target.longitude, cameraPosition.target.latitude);
                }
            }
        });
        this.mView.findViewById(R.id.currentPositionBtn).setSelected(false);
    }

    public void onHiddenChanged(boolean hidden) {
        super.onHiddenChanged(hidden);
    }

    public void setCurrentPOI() {
        if (ShareatApp.getInstance().getGpsManager() == null || !ShareatApp.getInstance().getGpsManager().isGetLocation()) {
            showGpsAlert();
            return;
        }
        double longitude = 127.027021d;
        double latitude = 37.4986366d;
        if (ShareatApp.getInstance().getGpsManager().isGetLocation()) {
            longitude = ShareatApp.getInstance().getGpsManager().getLongitude();
            latitude = ShareatApp.getInstance().getGpsManager().getLatitude();
        }
        if (this.myPosition == null) {
            this.myPosition = new Marker();
            this.myPosition.setIcon(OverlayImage.fromResource(R.drawable.my_location_pin));
        }
        this.myPosition.setPosition(new LatLng(latitude, longitude));
        this.myPosition.setMap(this.mNaverMap);
        this.mCameraPosition = new CameraPosition(this.myPosition.getPosition(), this.mNaverMap.getMaxZoom() - 5.0d);
        this.mNaverMap.setCameraPosition(this.mCameraPosition);
    }

    public void showGpsAlert() {
        String strGpsMsg = getResources().getString(R.string.GPS_MSG);
        if (VERSION.SDK_INT >= 23) {
            strGpsMsg = getResources().getString(R.string.GPS_MARSHMALLOW_MSG);
        }
        ShareatApp.getInstance().showGlobalAlert(strGpsMsg, new Runnable() {
            public void run() {
                MainNMapFragment.this.startActivity(new Intent("android.settings.LOCATION_SOURCE_SETTINGS"));
                MainNMapFragment.this.mIsCurrentPositionClicked = true;
            }
        });
        GAEvent.onGAScreenView(getActivity(), R.string.ga_enable_gps_screen);
    }

    /* access modifiers changed from: private */
    public void requestExternalMapData(final Bundle externalBundle) {
        MapDataApi request = new MapDataApi(getActivity());
        request.addGetParam(getQueryString(externalBundle));
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                MapDataModel mapDataModel = (MapDataModel) result;
                if ((MainNMapFragment.this.mMapDataModel != null && MainNMapFragment.this.mMapDataModel.getTotal_cnt() > 0) || mapDataModel == null || mapDataModel.getTotal_cnt() <= 0) {
                    if (MainNMapFragment.this.mMakerManager != null) {
                        for (int i = 0; i < MainNMapFragment.this.mMakerManager.size(); i++) {
                            ((Marker) MainNMapFragment.this.mMakerManager.get(i)).setMap(null);
                        }
                        MainNMapFragment.this.mMakerManager.clear();
                    }
                    if (MainNMapFragment.this.mMapTickerViewPager != null) {
                        MainNMapFragment.this.mMapTickerViewPager.removeAllViews();
                    }
                }
                MainNMapFragment.this.mMapDataModel = null;
                MainNMapFragment.this.mMapDataModel = mapDataModel;
                if (MainNMapFragment.this.mMapDataModel.getTotal_cnt() != 0) {
                    int total_cnt = mapDataModel.getTotal_cnt();
                    Iterator<MapDataDetailModel> it = mapDataModel.getResult_list().iterator();
                    while (it.hasNext()) {
                        MapDataDetailModel mapDataDetailModel = it.next();
                        Double mapX = Double.valueOf(Double.parseDouble(mapDataDetailModel.getMapX()));
                        Double mapY = Double.valueOf(Double.parseDouble(mapDataDetailModel.getMapY()));
                        Marker newMarker = new Marker();
                        newMarker.setPosition(new LatLng(mapY.doubleValue(), mapX.doubleValue()));
                        newMarker.setTag(mapDataDetailModel.getPartnerName1());
                        if (true == "E".equals(mapDataDetailModel.getEventType())) {
                            newMarker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_e_01));
                        } else if (true == "C".equals(mapDataDetailModel.getEventType())) {
                            newMarker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_c_01));
                        } else {
                            newMarker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_01));
                        }
                        newMarker.setOnClickListener(new Overlay.OnClickListener() {
                            public boolean onClick(@NonNull Overlay overlay) {
                                if (MainNMapFragment.this.mMakerManager == null) {
                                    MainNMapFragment.this.mInfoWindow.open((Marker) overlay);
                                } else {
                                    int index = MainNMapFragment.this.mMakerManager.indexOf((Marker) overlay);
                                    MainNMapFragment.this.setSelectMarker(index);
                                    MainNMapFragment.this.mOldMarkerIndex = index;
                                    MainNMapFragment.this.mMapTickerViewPager.setCurrentItem(index, false);
                                }
                                return true;
                            }
                        });
                        newMarker.setMap(MainNMapFragment.this.mNaverMap);
                        MainNMapFragment.this.mMakerManager.add(newMarker);
                    }
                    MainNMapFragment.this.updateMap();
                }
            }

            public void onFailure(Exception exception) {
                if (((BaseActivity) MainNMapFragment.this.getActivity()) != null) {
                    ((BaseActivity) MainNMapFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            MainNMapFragment.this.requestExternalMapData(externalBundle);
                        }
                    }, null);
                }
            }

            public void onFinish() {
                super.onFinish();
                MainNMapFragment.this.setTicker();
                if (MainNMapFragment.this.mMapTickerViewPager != null) {
                    if (MainNMapFragment.this.mMapDataModel == null || MainNMapFragment.this.mMapDataModel.getTotal_cnt() <= 0) {
                        MainNMapFragment.this.mMapTickerViewPager.setVisibility(8);
                        MainActivity mainActivity = (MainActivity) MainNMapFragment.this.getActivity();
                        if (mainActivity != null && mainActivity.isMapMode()) {
                            ((MainActivity) MainNMapFragment.this.getActivity()).showLocationGuideView(MainNMapFragment.this.mTopView);
                            Toast.makeText(MainNMapFragment.this.getActivity(), MainNMapFragment.this.getActivity().getString(R.string.nothing_poi_noti), 1).show();
                            return;
                        }
                        return;
                    }
                    MainNMapFragment.this.mMapTickerViewPager.setVisibility(0);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestMapData(double x, double y) {
        MapDataApi request = new MapDataApi(getActivity());
        request.addGetParam(String.format("?list_type=%s&order_type=ASC&user_X=%f&user_Y=%f&search_category_id=%s&search_area_id=%s&limit_distance=%s", new Object[]{getSubTitle(), Double.valueOf(x), Double.valueOf(y), this.mParamsModel.getSearchCategoryId(), this.mParamsModel.getSearchAreaId(), Integer.valueOf(this.mParamsModel.getLimitDistance())}));
        final double d = x;
        final double d2 = y;
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                MapDataModel mapDataModel = (MapDataModel) result;
                if ((MainNMapFragment.this.mMapDataModel != null && MainNMapFragment.this.mMapDataModel.getTotal_cnt() > 0) || mapDataModel == null || mapDataModel.getTotal_cnt() <= 0) {
                    if (MainNMapFragment.this.mMapTickerViewPager != null) {
                        MainNMapFragment.this.mMapTickerViewPager.removeAllViews();
                    }
                    if (MainNMapFragment.this.mMakerManager != null) {
                        for (int i = 0; i < MainNMapFragment.this.mMakerManager.size(); i++) {
                            ((Marker) MainNMapFragment.this.mMakerManager.get(i)).setMap(null);
                        }
                        MainNMapFragment.this.mMakerManager.clear();
                    }
                }
                MainNMapFragment.this.mMapDataModel = null;
                MainNMapFragment.this.mMapDataModel = mapDataModel;
                if (MainNMapFragment.this.mMapDataModel.getTotal_cnt() != 0) {
                    int total_cnt = mapDataModel.getTotal_cnt();
                    Iterator<MapDataDetailModel> it = mapDataModel.getResult_list().iterator();
                    while (it.hasNext()) {
                        MapDataDetailModel mapDataDetailModel = it.next();
                        Double mapX = Double.valueOf(Double.parseDouble(mapDataDetailModel.getMapX()));
                        Double mapY = Double.valueOf(Double.parseDouble(mapDataDetailModel.getMapY()));
                        Marker newMarker = new Marker();
                        newMarker.setPosition(new LatLng(mapY.doubleValue(), mapX.doubleValue()));
                        newMarker.setTag(mapDataDetailModel.getPartnerName1());
                        newMarker.setOnClickListener(new Overlay.OnClickListener() {
                            public boolean onClick(@NonNull Overlay overlay) {
                                if (MainNMapFragment.this.mMakerManager == null) {
                                    MainNMapFragment.this.mInfoWindow.open((Marker) overlay);
                                } else {
                                    int index = MainNMapFragment.this.mMakerManager.indexOf((Marker) overlay);
                                    MainNMapFragment.this.setSelectMarker(index);
                                    MainNMapFragment.this.mMapTickerViewPager.setCurrentItem(index, false);
                                }
                                return true;
                            }
                        });
                        if (true == "E".equals(mapDataDetailModel.getEventType())) {
                            newMarker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_e_01));
                        } else if (true == "C".equals(mapDataDetailModel.getEventType())) {
                            newMarker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_c_01));
                        } else {
                            newMarker.setIcon(OverlayImage.fromResource(R.drawable.ic_pin_01));
                        }
                        newMarker.setMap(MainNMapFragment.this.mNaverMap);
                        MainNMapFragment.this.mMakerManager.add(newMarker);
                        String pinText = mapDataDetailModel.getPinText();
                        if (true == mapDataDetailModel.getPinText().isEmpty()) {
                            String POIText = mapDataDetailModel.getPartnerName1();
                        }
                        Integer.parseInt(mapDataDetailModel.getPartnerSno());
                    }
                    MainNMapFragment.this.updateMap();
                }
            }

            public void onFailure(Exception exception) {
                if (((BaseActivity) MainNMapFragment.this.getActivity()) != null) {
                    ((BaseActivity) MainNMapFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            MainNMapFragment.this.requestMapData(d, d2);
                        }
                    }, null);
                }
            }

            public void onFinish() {
                super.onFinish();
                MainNMapFragment.this.setTicker();
                if (MainNMapFragment.this.mMapTickerViewPager != null) {
                    if (MainNMapFragment.this.mMapDataModel == null || MainNMapFragment.this.mMapDataModel.getTotal_cnt() <= 0) {
                        MainNMapFragment.this.mMapTickerViewPager.setVisibility(8);
                        MainActivity mainActivity = (MainActivity) MainNMapFragment.this.getActivity();
                        if (mainActivity != null && mainActivity.isMapMode()) {
                            ((MainActivity) MainNMapFragment.this.getActivity()).showLocationGuideView(MainNMapFragment.this.mTopView);
                            Toast.makeText(MainNMapFragment.this.getActivity(), MainNMapFragment.this.getActivity().getString(R.string.nothing_poi_noti), 1).show();
                            return;
                        }
                        return;
                    }
                    MainNMapFragment.this.mMapTickerViewPager.setVisibility(0);
                }
            }
        });
    }

    public void setUserVisibleHint(boolean isVisibleToUser) {
        ShareatApp.getInstance();
        ShareatApp.LOG_INFO("MainNMapFragment setUserVisibleHint() Call [" + isVisibleToUser + "]");
        super.setUserVisibleHint(isVisibleToUser);
        if (true == isVisibleToUser) {
            GAEvent.onGAScreenView(getActivity(), R.string.ga_nmap_screen);
        }
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
}