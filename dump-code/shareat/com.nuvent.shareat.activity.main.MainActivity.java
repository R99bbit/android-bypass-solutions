package com.nuvent.shareat.activity.main;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnKeyListener;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.ActivityCompat;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.app.FragmentTransaction;
import android.support.v4.content.ContextCompat;
import android.support.v4.view.GravityCompat;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.support.v4.view.ViewPager.PageTransformer;
import android.support.v4.widget.DrawerLayout;
import android.support.v4.widget.DrawerLayout.DrawerListener;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.TextView;
import android.widget.Toast;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import com.gun0912.tedpermission.PermissionListener;
import com.gun0912.tedpermission.TedPermission;
import com.gun0912.tedpermission.TedPermission.Builder;
import com.igaworks.adbrix.IgawAdbrix;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.MainActionBarActivity.OnAnimationListener;
import com.nuvent.shareat.activity.common.ConfirmPasswordActivity;
import com.nuvent.shareat.activity.common.CouponAndPointActivity;
import com.nuvent.shareat.activity.common.EventActivity;
import com.nuvent.shareat.activity.common.WebViewActivity;
import com.nuvent.shareat.activity.crop.CropActivity;
import com.nuvent.shareat.activity.intro.SigninActivity;
import com.nuvent.shareat.activity.intro.SignupActivity;
import com.nuvent.shareat.activity.menu.FriendGroupActivity;
import com.nuvent.shareat.activity.menu.GuideActivity;
import com.nuvent.shareat.activity.menu.InquiryActivity;
import com.nuvent.shareat.activity.menu.InterestActivity;
import com.nuvent.shareat.activity.menu.MyCardActivity;
import com.nuvent.shareat.activity.menu.MyPaymentActivity;
import com.nuvent.shareat.activity.menu.NotificationCenterActivity;
import com.nuvent.shareat.activity.menu.NotifySettingActivity;
import com.nuvent.shareat.activity.menu.PasswordSettingActivity;
import com.nuvent.shareat.activity.menu.ProfileActivity;
import com.nuvent.shareat.activity.menu.ProfileViewActivity;
import com.nuvent.shareat.activity.menu.ServiceInfoActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.AdvertiseApi;
import com.nuvent.shareat.api.common.EventPopupApi;
import com.nuvent.shareat.api.common.NotificationApi;
import com.nuvent.shareat.api.common.ReadPushApi;
import com.nuvent.shareat.api.external.ExternalLoplatConfigApi;
import com.nuvent.shareat.api.member.UserInfoApi;
import com.nuvent.shareat.api.store.StoreApi;
import com.nuvent.shareat.dialog.LoadingCircleDialog;
import com.nuvent.shareat.dialog.PhotoTypeDialog;
import com.nuvent.shareat.dialog.PhotoTypeDialog.DialogClickListener;
import com.nuvent.shareat.event.AdvertiseEvent;
import com.nuvent.shareat.event.AdvertiseEvent.AdvertiseType;
import com.nuvent.shareat.event.AutoBranchEvent;
import com.nuvent.shareat.event.CardSlideEvent;
import com.nuvent.shareat.event.CardUpdateEvent;
import com.nuvent.shareat.event.CardViewStatusEvent;
import com.nuvent.shareat.event.GpsRefreshEvent;
import com.nuvent.shareat.event.GuideCloseEvent;
import com.nuvent.shareat.event.LocationEvent;
import com.nuvent.shareat.event.LogoClickEvent;
import com.nuvent.shareat.event.MainActivityEvent;
import com.nuvent.shareat.event.MainActivityFinishEvent;
import com.nuvent.shareat.event.MainResumeEvent;
import com.nuvent.shareat.event.NotifySettingEvent;
import com.nuvent.shareat.event.PayingEvent;
import com.nuvent.shareat.event.PostGnbOptionEvent;
import com.nuvent.shareat.event.RefreshQuickPayListEvent;
import com.nuvent.shareat.event.RequestAutoBranchEvent;
import com.nuvent.shareat.event.RequestLoplatConfigEvent;
import com.nuvent.shareat.event.RequestProfileUpdateEvent;
import com.nuvent.shareat.event.SchemeMainlistEvent;
import com.nuvent.shareat.event.SocketReceiveEvent;
import com.nuvent.shareat.event.SocketSendEvent;
import com.nuvent.shareat.event.SuccessCheckSecureEvent;
import com.nuvent.shareat.event.SuccessProfileUpdateEvent;
import com.nuvent.shareat.fragment.CategoryFragment;
import com.nuvent.shareat.fragment.LocationFragment;
import com.nuvent.shareat.fragment.MainFragment;
import com.nuvent.shareat.fragment.MainNMapFragment;
import com.nuvent.shareat.fragment.MainNMapFragment.NMapHideListener;
import com.nuvent.shareat.fragment.StoreDetailFragment;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.LoplatManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.ParamManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.AdvertiseDetailModel;
import com.nuvent.shareat.model.AdvertiseModel;
import com.nuvent.shareat.model.BoardModel;
import com.nuvent.shareat.model.BoardResultModel;
import com.nuvent.shareat.model.NotificationModel;
import com.nuvent.shareat.model.NotificationResultModel;
import com.nuvent.shareat.model.PushModel;
import com.nuvent.shareat.model.external.LoplatConfigResultModel;
import com.nuvent.shareat.model.payment.PayResultModel;
import com.nuvent.shareat.model.store.StoreDetailModel;
import com.nuvent.shareat.model.store.StoreDetailResultModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.model.user.UserModel;
import com.nuvent.shareat.model.user.UserResultModel;
import com.nuvent.shareat.service.AddressService;
import com.nuvent.shareat.service.CommunicationService;
import com.nuvent.shareat.util.DistanceCalculator;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.ShareatLogger;
import com.nuvent.shareat.widget.view.CardView;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import net.xenix.android.widget.PagingEnableViewPager;
import net.xenix.util.ImageDisplay;

public class MainActivity extends MainActionBarActivity implements OnClickListener {
    private static final String EXTRA_SCHEME_PATH_MAINLIST = "mainlist";
    private static final String EXTRA_SCHEME_PATH_PAYMENT = "payment";
    public static final int POST_TYPE_PASSWORD_CHECK_MY_CARD = 18;
    public static final int POST_TYPE_PASSWORD_CHECK_MY_PAYMENT = 17;
    public static final int REQUEST_TYPE_PASSWORD_CHECK = 153;
    private static final String WEB_EXECUTE_IN_TYPE = "in";
    private static final String WEB_EXECUTE_OUT_TYPE = "out";
    DrawerListener drawerListener;
    private boolean isAppBackground;
    private boolean isCheckHack;
    /* access modifiers changed from: private */
    public boolean isCheckPermission;
    private boolean isFirstLocationAgreement = true;
    private boolean isFirstRun = true;
    /* access modifiers changed from: private */
    public boolean isStoreClick;
    /* access modifiers changed from: private */
    public boolean mAutoBranchBlock;
    private Handler mAutoBranchHandler;
    private Runnable mAutoBranchRunnable;
    /* access modifiers changed from: private */
    public BoardModel mBoardModel;
    /* access modifiers changed from: private */
    public DrawerLayout mDrawerLayout;
    private Bundle mExternalParams;
    private Handler mHandler;
    private LoadingCircleDialog mMainlistLoading;
    /* access modifiers changed from: private */
    public NotificationResultModel mModel;
    /* access modifiers changed from: private */
    public FragmentViewPagerAdapter mPagerAdapter;
    PermissionListener permissionlistener;

    public class FragmentViewPagerAdapter extends FragmentStatePagerAdapter {
        private final int FRAGMENT_ITEM_COUNT = 5;
        private CategoryFragment mCategoryFragment;
        private MainFragment mMainFragment;
        private MainNMapFragment mMainNMapFragment;
        private StoreDetailFragment mStoreFragment;

        public FragmentViewPagerAdapter(FragmentManager fragmentManager) {
            super(fragmentManager);
            if (fragmentManager.getFragments() != null) {
                int size = fragmentManager.getFragments().size();
                for (int i = 0; i < size; i++) {
                    Fragment frag = fragmentManager.getFragments().get(i);
                    if (frag instanceof StoreDetailFragment) {
                        this.mStoreFragment = (StoreDetailFragment) frag;
                    } else if (frag instanceof CategoryFragment) {
                        this.mCategoryFragment = (CategoryFragment) frag;
                    } else if (frag instanceof MainNMapFragment) {
                        this.mMainNMapFragment = (MainNMapFragment) frag;
                    } else if (frag instanceof MainFragment) {
                        this.mMainFragment = (MainFragment) frag;
                    }
                }
            }
        }

        public int getCount() {
            return 5;
        }

        public int getItemPosition(Object object) {
            return -2;
        }

        public Fragment getItem(int position) {
            switch (position) {
                case 0:
                    return getMainFragment();
                case 1:
                    return getStoreFragment();
                case 2:
                    return new LocationFragment();
                case 3:
                    return getCategoryFragment();
                case 4:
                    return getMainNMapFragment();
                default:
                    return null;
            }
        }

        public void destroyItem(ViewGroup container, int position, Object object) {
            super.destroyItem(container, position, object);
            if (position <= getCount()) {
                FragmentTransaction trans = ((Fragment) object).getFragmentManager().beginTransaction();
                trans.remove((Fragment) object);
                trans.commit();
            }
        }

        public MainFragment getMainFragment() {
            if (this.mMainFragment == null) {
                this.mMainFragment = new MainFragment();
            }
            return this.mMainFragment;
        }

        public void refreshNMapFragmentLifeCycle() {
            getMainNMapFragment().onStart();
            getMainNMapFragment().onResume();
        }

        public MainNMapFragment getMainNMapFragment() {
            if (this.mMainNMapFragment == null) {
                this.mMainNMapFragment = new MainNMapFragment();
            }
            this.mMainNMapFragment.addNMapHideListener(new NMapHideListener() {
                public void onNMapHide() {
                    boolean z;
                    ((ViewPager) MainActivity.this.findViewById(R.id.viewPager)).setCurrentItem(0, false);
                    int storeCnt = MainActivity.this.mPagerAdapter.getMainFragment().getStoreListCount();
                    MainActivity mainActivity = MainActivity.this;
                    if (storeCnt > 0) {
                        z = true;
                    } else {
                        z = false;
                    }
                    mainActivity.animateCardLayout(z);
                    MainActivity.this.setGNBMapAndList(true);
                    ((MainNMapFragment) MainActivity.this.mPagerAdapter.getItem(4)).initMap();
                }
            });
            return this.mMainNMapFragment;
        }

        public StoreDetailFragment getStoreFragment() {
            if (this.mStoreFragment == null) {
                this.mStoreFragment = new StoreDetailFragment();
            }
            return this.mStoreFragment;
        }

        public void refreshStoreFragmentLifeCycle() {
            getStoreFragment().onStart();
            getStoreFragment().onResume();
        }

        public CategoryFragment getCategoryFragment() {
            if (this.mCategoryFragment == null) {
                this.mCategoryFragment = new CategoryFragment();
            }
            return this.mCategoryFragment;
        }
    }

    public class TutorialPageTransformer implements PageTransformer {
        private static final float MIN_ALPHA = 0.5f;
        private static final float MIN_SCALE = 0.85f;

        public TutorialPageTransformer() {
        }

        public void transformPage(View view, float position) {
            int pageWidth = view.getWidth();
            int pageHeight = view.getHeight();
            if (position < -1.0f) {
                view.setAlpha(0.0f);
            } else if (position <= 1.0f) {
                float scaleFactor = Math.max(MIN_SCALE, 1.0f - Math.abs(position));
                float vertMargin = (((float) pageHeight) * (1.0f - scaleFactor)) / 2.0f;
                float horzMargin = (((float) pageWidth) * (1.0f - scaleFactor)) / 2.0f;
                if (position < 0.0f) {
                    view.setTranslationX(horzMargin - (vertMargin / 2.0f));
                } else {
                    view.setTranslationX((-horzMargin) + (vertMargin / 2.0f));
                }
                view.setScaleX(scaleFactor);
                view.setScaleY(scaleFactor);
                view.setAlpha((((scaleFactor - MIN_SCALE) / 0.14999998f) * MIN_ALPHA) + MIN_ALPHA);
            } else {
                view.setAlpha(0.0f);
            }
        }
    }

    public MainActivity() {
        boolean z = true;
        this.isCheckPermission = VERSION.SDK_INT >= 23 ? false : z;
        this.isCheckHack = false;
        this.mAutoBranchBlock = false;
        this.mAutoBranchHandler = null;
        this.mAutoBranchRunnable = null;
        this.isStoreClick = false;
        this.drawerListener = new DrawerListener() {
            public void onDrawerSlide(View drawerView, float slideOffset) {
            }

            public void onDrawerOpened(View drawerView) {
            }

            public void onDrawerClosed(View drawerView) {
            }

            public void onDrawerStateChanged(int newState) {
            }
        };
        this.permissionlistener = new PermissionListener() {
            public void onPermissionGranted() {
                MainActivity.this.isCheckPermission = true;
            }

            public void onPermissionDenied(List<String> list) {
                MainActivity.this.isCheckPermission = true;
            }
        };
    }

    public void onEventMainThread(SuccessCheckSecureEvent event) {
        checkHackToolResult(ShareatApp.getInstance().getHackToolCheckResult());
    }

    public void onEventMainThread(GuideCloseEvent event) {
        requestEventPopupApi();
    }

    public void onEventMainThread(CardUpdateEvent event) {
        setCardInfo();
    }

    public void onEventMainThread(CardSlideEvent event) {
        if (((ViewPager) findViewById(R.id.viewPager)).getCurrentItem() == 0) {
            this.mDrawerLayout.setDrawerLockMode(event.isOpen() ? 1 : 0);
        }
        if (event.isOpen()) {
            findViewById(R.id.dimBar).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
            findViewById(R.id.dimBar).setVisibility(0);
            return;
        }
        findViewById(R.id.dimBar).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_out));
        findViewById(R.id.dimBar).setVisibility(8);
    }

    public void onEventMainThread(NotifySettingEvent event) {
        String strAutoBranchSearch = event.getAutoBranchSearch();
        if (event.getNotificationModel() != null) {
            this.mModel = event.getNotificationModel();
        }
        if (true == "Y".equals(strAutoBranchSearch)) {
            AppSettingManager.getInstance().setAutoBranchSearchStatus(true);
            setLoplat();
            return;
        }
        AppSettingManager.getInstance().setAutoBranchSearchStatus(false);
        stopLoplat();
    }

    public void onEventMainThread(MainActivityFinishEvent event) {
        if (getIntent().hasExtra("quickPay")) {
            finish();
        }
    }

    public void onEventMainThread(AutoBranchEvent event) {
        if (this.mAutoBranchHandler != null) {
            this.mAutoBranchHandler.removeCallbacks(this.mAutoBranchRunnable);
            this.mAutoBranchRunnable = null;
        }
        LoplatManager.getInstance(this).setSearchingStatus(1);
        if (true != this.mAutoBranchBlock && !((CardView) findViewById(R.id.cardView)).getStoreClick() && isOpenCardView()) {
            if (!((CardView) findViewById(R.id.cardView)).getStoreClick() && isOpenCardView()) {
                ((CardView) findViewById(R.id.cardView)).stopLoading();
            }
            StoreModel sm = event.getStoreModel();
            if (sm == null) {
                ((CardView) findViewById(R.id.cardView)).setAutoBranchSearch(false);
                if (!AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
                    animActivity(new Intent(getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_search"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                }
            } else if (true != LoplatManager.getInstance(this).getRunningActionGuideActivity()) {
                if (!ShareatApp.getInstance().isPayFlowing()) {
                    ((CardView) findViewById(R.id.cardView)).setAutoBranchSearch(true);
                    ((CardView) findViewById(R.id.cardView)).setQuickMode(true);
                    ((CardView) findViewById(R.id.cardView)).setStoreModel(sm);
                }
                EventBus.getDefault().post(new RefreshQuickPayListEvent(sm));
            }
        }
    }

    public void onEventMainThread(RequestAutoBranchEvent event) {
        int nResult = LoplatManager.getInstance(this).isLoplatStatus();
        if (1 != nResult) {
            ((CardView) findViewById(R.id.cardView)).setAutoBranchSearch(false);
            if (!AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
                animActivity(new Intent(getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_search"), R.anim.fade_in_activity, R.anim.fade_out_activity);
            }
            ShareatLogger.writeLog("[ERR] not enable loplat sdk. result code : " + nResult);
        } else if (1 == event.mRequestAutoBranchCommand) {
            LoplatManager.getInstance(this).setFindSuccess(false);
            LoplatManager.getInstance(this).setRecentSearchTime(new Date(System.currentTimeMillis()));
            if (true == LoplatManager.getInstance(this).requestLocationInfo() && !((CardView) findViewById(R.id.cardView)).getStoreClick()) {
                ((CardView) findViewById(R.id.cardView)).startLoading();
            }
            this.mAutoBranchBlock = false;
            if (this.mAutoBranchHandler == null) {
                this.mAutoBranchHandler = new Handler();
            }
            if (this.mAutoBranchRunnable == null) {
                this.mAutoBranchRunnable = new Runnable() {
                    public void run() {
                        MainActivity.this.mAutoBranchBlock = true;
                        LoplatManager.getInstance(MainActivity.this.getBaseContext()).setSearchingStatus(1);
                        ((CardView) MainActivity.this.findViewById(R.id.cardView)).stopLoading();
                        if (!((CardView) MainActivity.this.findViewById(R.id.cardView)).getStoreClick()) {
                            ((CardView) MainActivity.this.findViewById(R.id.cardView)).setAutoBranchSearch(false);
                            if (!AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
                                MainActivity.this.animActivity(new Intent(MainActivity.this.getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_search"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                            }
                        }
                    }
                };
            }
            this.mAutoBranchHandler.postDelayed(this.mAutoBranchRunnable, 7000);
        } else if (2 == event.mRequestAutoBranchCommand) {
            if (this.mAutoBranchHandler != null) {
                this.mAutoBranchHandler.removeCallbacks(this.mAutoBranchRunnable);
                this.mAutoBranchBlock = true;
                ((CardView) findViewById(R.id.cardView)).stopLoading();
                if (!((CardView) findViewById(R.id.cardView)).getStoreClick()) {
                    ((CardView) findViewById(R.id.cardView)).setAutoBranchSearch(false);
                }
            }
        } else if (3 == event.mRequestAutoBranchCommand) {
            if (!((CardView) findViewById(R.id.cardView)).getStoreClick()) {
                ((CardView) findViewById(R.id.cardView)).startLoading();
            }
            this.mAutoBranchBlock = false;
            if (this.mAutoBranchHandler == null) {
                this.mAutoBranchHandler = new Handler();
            }
            if (this.mAutoBranchRunnable == null) {
                this.mAutoBranchRunnable = new Runnable() {
                    public void run() {
                        MainActivity.this.mAutoBranchBlock = true;
                        LoplatManager.getInstance(MainActivity.this.getBaseContext()).setSearchingStatus(1);
                        ((CardView) MainActivity.this.findViewById(R.id.cardView)).stopLoading();
                        if (!((CardView) MainActivity.this.findViewById(R.id.cardView)).getStoreClick()) {
                            ((CardView) MainActivity.this.findViewById(R.id.cardView)).setAutoBranchSearch(false);
                            if (!AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
                                MainActivity.this.animActivity(new Intent(MainActivity.this.getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_search"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                            }
                        }
                    }
                };
            }
            this.mAutoBranchHandler.postDelayed(this.mAutoBranchRunnable, 7000);
        }
    }

    public void onEventMainThread(CardViewStatusEvent event) {
        if (true != event.isDeliveryCardView) {
            String message = "";
            switch (((CardView) findViewById(R.id.cardView)).getCardStatus()) {
                case 1:
                    message = "\uba3c\uc800 \uce74\ub4dc\ub97c \ub4f1\ub85d\ud558\uc154\uc57c \uacb0\uc81c\uac00 \uac00\ub2a5\ud569\ub2c8\ub2e4.";
                    break;
                case 2:
                    message = "\uacb0\uc81c\ud560 \ub9e4\uc7a5\uc744 \uc120\ud0dd\ud558\uc138\uc694.";
                    break;
                case 3:
                    message = "\uce74\ub4dc\ub97c \ubc00\uc5b4\uc11c \uacb0\uc81c\uc694\uccad\ud558\uc138\uc694.";
                    break;
                case 4:
                    message = "\uac00\uc785\uc2dc \uc124\uc815\ud558\uc2e0 \ube44\ubc00\ubc88\ud638\ub97c \uc785\ub825\ud558\uc138\uc694.";
                    break;
                case 5:
                    message = "\uce74\uc6b4\ud130\uc5d0 \ubc14\ucf54\ub4dc\ub97c \uc81c\uc2dc\ud574 \uc8fc\uc138\uc694.";
                    break;
                case 6:
                    message = "";
                    break;
            }
            if (message == null || message.isEmpty()) {
                findViewById(R.id.titleGuideLabel).setVisibility(8);
                findViewById(R.id.titleGuideImageView).setVisibility(8);
            } else {
                findViewById(R.id.titleGuideLabel).setVisibility(0);
                findViewById(R.id.titleGuideImageView).setVisibility(0);
            }
            ((TextView) findViewById(R.id.titleGuideLabel)).setText(message);
        }
    }

    public void onEventMainThread(LocationEvent event) {
        if (event == null) {
            return;
        }
        if (((ViewPager) findViewById(R.id.viewPager)).getCurrentItem() == 2) {
            setMainView(false);
            ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, false);
            return;
        }
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(2, false);
    }

    public void onEventMainThread(RequestProfileUpdateEvent event) {
        requestUserInfoApi();
    }

    public void onEventMainThread(SocketSendEvent event) {
        switch (event.getType()) {
            case 1:
                getSocketManager().init();
                return;
            case 2:
                getSocketManager().onSendMessage(event.getMethodStr(), event.getDatas());
                return;
            case 3:
                GAEvent.onGaEvent((Activity) this, (int) R.string.quickpayview, (int) R.string.ga_ev_cancle, (int) R.string.quickpayview_cancelpayment);
                getSocketManager().onCancelPaying();
                return;
            default:
                return;
        }
    }

    public void onEventMainThread(SocketReceiveEvent event) {
        switch (event.getKey()) {
            case 18:
                String response = event.getParams();
                if (response == null || response.isEmpty()) {
                    showDialog("\uacb0\uc81c \uc131\uacf5/\ucde8\uc18c - \uc624\ub958\nresponse = " + response);
                    return;
                } else {
                    ((CardView) findViewById(R.id.cardView)).postPaymentResult((PayResultModel) new PayResultModel().fromJson(response));
                    return;
                }
            case 20:
                GAEvent.onGaEvent((Activity) this, (int) R.string.error, (int) R.string.ga_payment, (int) R.string.Error_Password);
                setDifferentPassword(event);
                return;
            case 21:
                setPayingCancel(event.getParams());
                return;
            case 22:
                setPayingCancel(event.getParams());
                return;
            default:
                return;
        }
    }

    public void onEventMainThread(PayingEvent event) {
        if (true != event.isDeliveryCardView && event.isPaying()) {
            ((CardView) findViewById(R.id.cardView)).showBillingView();
        }
    }

    public void onClickBackPress(View view) {
        finish();
    }

    public void onBackPressed() {
        if (findViewById(R.id.barcodeLayout).getVisibility() == 0) {
            closeBarcodeView();
        } else if (isOpenCardView()) {
            closeCardView();
            if (!this.isStoreClick && !((CardView) findViewById(R.id.cardView)).isPayingMode()) {
                ((CardView) findViewById(R.id.cardView)).clearStoreModel();
                EventBus.getDefault().post(new RequestAutoBranchEvent(2));
            }
            if (getIntent().hasExtra("quickPay")) {
                finish();
            }
        } else if (this.mDrawerLayout.isDrawerOpen((int) GravityCompat.START)) {
            this.mDrawerLayout.closeDrawer((int) GravityCompat.START);
        } else if (isNextFragment()) {
            ((CardView) findViewById(R.id.cardView)).clearStoreModel();
            ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, true);
            findViewById(R.id.nextLayout).setVisibility(8);
            setIsNextFragment(false);
            this.mPagerAdapter.getStoreFragment().clearPopupWindow();
            new Handler().postDelayed(new Runnable() {
                public void run() {
                    MainActivity.this.mPagerAdapter.getStoreFragment().clearHeader();
                }
            }, 300);
        } else if (((ViewPager) findViewById(R.id.viewPager)).getCurrentItem() != 0) {
            setMainView(false);
            if (true != this.mIsMapMode || 4 == ((ViewPager) findViewById(R.id.viewPager)).getCurrentItem()) {
                this.mIsMapMode = false;
                ((CardView) findViewById(R.id.cardView)).clearStoreModel();
                ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, false);
                ((MainNMapFragment) this.mPagerAdapter.getItem(4)).initMap();
                setGNBMapAndList(true);
                animateCardLayout(this.mPagerAdapter.getMainFragment().getStoreListCount() > 0);
                return;
            }
            this.mIsMapMode = true;
            showNMapFragment();
        } else {
            finish();
        }
    }

    public void onClickBarcode(View view) {
        if (findViewById(R.id.barcodeLayout).getVisibility() == 0) {
            closeBarcodeView();
        } else {
            openBarcodeView();
        }
    }

    public void onClickMenu(View view) {
        if (this.mDrawerLayout != null) {
            if (this.mDrawerLayout.isDrawerOpen((int) GravityCompat.START)) {
                this.mDrawerLayout.closeDrawer((int) GravityCompat.START);
                GAEvent.onGaEvent((Activity) this, (int) R.string.leftmenuview, (int) R.string.ga_ev_scroll, (int) R.string.leftmenuview_scroll_leftright);
                return;
            }
            this.mDrawerLayout.openDrawer((int) GravityCompat.START);
            GAEvent.onGaEvent((Activity) this, (int) R.string.leftmenuview, (int) R.string.ga_ev_scroll, (int) R.string.leftmenuview_scroll_leftright);
        }
    }

    public void onClickSearch(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_gnb_menu, (int) R.string.ga_ev_click, (int) R.string.ga_gnb_search);
        pushActivity(new Intent(this, SearchActivity.class));
    }

    public void onClickLogo(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_gnb_menu, (int) R.string.ga_ev_click, (int) R.string.ga_gnb_shareat_logo);
        super.onClickLogo(view);
        if (((ViewPager) findViewById(R.id.viewPager)).getCurrentItem() == 0) {
            EventBus.getDefault().post(new LogoClickEvent());
            return;
        }
        setGNBMapAndList(true);
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, false);
        animateCardLayout(this.mPagerAdapter.getMainFragment().getStoreListCount() > 0);
    }

    public void setGNBMapAndList(boolean isMapType) {
        if (true == isMapType) {
            findViewById(R.id.headerMapBtn).setVisibility(0);
            findViewById(R.id.headerListBtn).setVisibility(8);
        } else {
            findViewById(R.id.headerMapBtn).setVisibility(8);
            findViewById(R.id.headerListBtn).setVisibility(0);
        }
        findViewById(R.id.categoryButton).setSelected(false);
    }

    public void onClickCloseCard(View view) {
        super.onClickCloseCard(view);
        if (getIntent().hasExtra("quickPay")) {
            finish();
        }
    }

    public void onClickHeaderMapBtn(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_gnb_menu, (int) R.string.ga_ev_click, (int) R.string.ga_gnb_map);
        setMain(true);
        showNMapFragment();
    }

    public void onClickHeaderListBtn(View view) {
        boolean z;
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_gnb_menu, (int) R.string.ga_ev_click, (int) R.string.ga_gnb_list);
        setMain(true);
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, false);
        if (this.mPagerAdapter.getMainFragment().getStoreListCount() > 0) {
            z = true;
        } else {
            z = false;
        }
        animateCardLayout(z);
        setGNBMapAndList(true);
        ((MainNMapFragment) this.mPagerAdapter.getItem(4)).initMap();
    }

    public void onClickLocation(View view) {
        if (view == null) {
            onClickLocation(findViewById(R.id.locationButton));
            return;
        }
        super.onClickLocation(view);
        if (((ViewPager) findViewById(R.id.viewPager)).getCurrentItem() == 2) {
            setMainView(false);
            if (true == this.mIsMapMode) {
                showNMapFragment();
            } else {
                ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, false);
            }
        } else {
            ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(2, false);
        }
    }

    public void onClickCategory(View view) {
        boolean z;
        super.onClickCategory(view);
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_gnb_menu, (int) R.string.ga_ev_click, (int) R.string.ga_gnb_category_setting);
        if (this.mPagerAdapter.getCategoryFragment().getActivity() != null) {
            if (true == isMapMode()) {
                ((MainNMapFragment) this.mPagerAdapter.getItem(4)).initMap();
            }
            if (((ViewPager) findViewById(R.id.viewPager)).getCurrentItem() == 3) {
                if (this.mPagerAdapter.getMainFragment().getStoreListCount() > 0) {
                    z = true;
                } else {
                    z = false;
                }
                setMainView(z);
                ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, false);
                return;
            }
            this.mPagerAdapter.getCategoryFragment().setSortButton(ParamManager.getInstance().getSortType());
            this.mPagerAdapter.getCategoryFragment().setCategoryCheck();
            ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(3, false);
        }
    }

    public void onClickGnbOption() {
        setMainView(false);
        if (true == this.mIsMapMode) {
            ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(4, false);
        } else {
            ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, false);
        }
        EventBus.getDefault().post(new PostGnbOptionEvent());
    }

    public void onClickStoreItem(StoreModel model) {
        this.isStoreClick = true;
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_storelist, (int) R.string.ga_ev_click, (int) R.string.ga_storelist_detail);
        ((CardView) findViewById(R.id.cardView)).setStoreModel(model);
        ((CardView) findViewById(R.id.cardView)).setStoreClick(true);
        setFragmentTitle(model.getPartnerName1());
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(1, true);
        animateActionbarLayout(true);
        this.mPagerAdapter.getStoreFragment().setStoreModel(model);
        this.mPagerAdapter.refreshStoreFragmentLifeCycle();
    }

    public void onClickBackFragment(View view) {
        if (isOpenCardView()) {
            closeCardView();
        }
        ((CardView) findViewById(R.id.cardView)).clearStoreModel();
        this.mPagerAdapter.getStoreFragment().clearHeader();
        animateActionbarLayout(false);
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, true);
    }

    public void onClickFavoriteFragment(View view) {
        if (!SessionManager.getInstance().hasSession()) {
            showLoginDialog();
            return;
        }
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_store_detail, (int) R.string.store_detile_action_favi, (int) R.string.ga_store_detail_like);
        view.setSelected(!view.isSelected());
        this.mPagerAdapter.getStoreFragment().requestFavoriteStoreApi(view);
    }

    public void onQuickPayStore(final String partnerSno) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_storelist, (int) R.string.ga_ev_click, (int) R.string.ga_storelist_quickpay);
        Object[] objArr = new Object[3];
        objArr[0] = partnerSno;
        objArr[1] = String.valueOf(getGpsManager() == null ? 127.027021d : getGpsManager().getLongitude());
        objArr[2] = String.valueOf(getGpsManager() == null ? 37.4986366d : getGpsManager().getLatitude());
        String parameter = String.format("?partner_sno=%s&user_X=%s&user_Y=%s", objArr);
        StoreApi request = new StoreApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onStart() {
                MainActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                MainActivity.this.showCircleDialog(false);
                StoreDetailModel detailModel = ((StoreDetailResultModel) result).getStore_detail();
                StoreModel storeModel = new StoreModel();
                storeModel.partnerName1 = detailModel.getPartner_name1();
                storeModel.favoriteYn = detailModel.favorite_yn;
                storeModel.partnerSno = String.valueOf(detailModel.partner_sno);
                try {
                    storeModel.distance = String.valueOf(detailModel.distance);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                storeModel.setBarcode(detailModel.isBarcode());
                ((CardView) MainActivity.this.findViewById(R.id.cardView)).setStoreModel(storeModel);
                ((CardView) MainActivity.this.findViewById(R.id.cardView)).setQuickMode(true);
                MainActivity.this.animateCardLayout(true);
                MainActivity.this.openCardView();
            }

            public void onFailure(Exception exception) {
                MainActivity.this.showCircleDialog(false);
                MainActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        MainActivity.this.onQuickPayStore(partnerSno);
                    }
                });
            }

            public void onFinish() {
                MainActivity.this.showCircleDialog(false);
            }
        });
    }

    public boolean isStoreClick() {
        return this.isStoreClick;
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == -1) {
            switch (requestCode) {
                case 1:
                    postUploadImagePath(ImageDisplay.getInstance().setPickImageView(this, PhotoTypeDialog.getCameraOutputUri().getPath(), (ImageView) this.mDrawerLayout.findViewById(R.id.menuAvatarImageView)));
                    break;
                case 101:
                case 102:
                    if (resultCode == -1 && data != null) {
                        postUploadImagePath(ImageDisplay.getInstance().setPickImageView(this, ImageDisplay.getInstance().getImagePath(this, requestCode, data.getData()), (ImageView) this.mDrawerLayout.findViewById(R.id.menuAvatarImageView)));
                        break;
                    } else {
                        super.onActivityResult(requestCode, resultCode, data);
                        return;
                    }
                case 153:
                    AppSettingManager.getInstance().setPasswordCheck(true);
                    int postType = data.getIntExtra("postType", 0);
                    if (17 != postType) {
                        if (18 == postType) {
                            pushActivity(new Intent(this, MyCardActivity.class));
                            break;
                        }
                    } else {
                        pushActivity(new Intent(this, MyPaymentActivity.class));
                        break;
                    }
                    break;
                case CropActivity.CROP_FROM_STORE_DETAIL /*5858*/:
                    this.mPagerAdapter.getStoreFragment().onActivityResult(requestCode, resultCode, data);
                    break;
            }
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.friendsGroupLayout /*2131296684*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_friend);
                pushActivity(new Intent(this, FriendGroupActivity.class));
                return;
            case R.id.iconClose /*2131296721*/:
                this.mDrawerLayout.closeDrawers();
                return;
            case R.id.iconProfile /*2131296722*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_user_info);
                if (SessionManager.getInstance().hasSession()) {
                    pushActivity(new Intent(this, ProfileActivity.class));
                    return;
                } else if (!SessionManager.getInstance().hasSession()) {
                    showLoginDialog();
                    return;
                } else {
                    return;
                }
            case R.id.joinButton /*2131296763*/:
                if (!SessionManager.getInstance().hasSession()) {
                    showLoginDialog();
                    return;
                }
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_menu, (int) R.string.ga_ev_click, (int) R.string.ga_tutorial_join);
                animActivity(new Intent(this, SessionManager.getInstance().isJoinUser() ? SigninActivity.class : SignupActivity.class), R.anim.fade_in_activity, R.anim.fade_out_activity);
                return;
            case R.id.menuAvatarImageView /*2131296825*/:
                PhotoTypeDialog dialog = new PhotoTypeDialog(this, false);
                dialog.setOnDialogClickListener(new DialogClickListener() {
                    public void onClickViewer() {
                        MainActivity.this.modalActivity(new Intent(MainActivity.this, ProfileViewActivity.class).putExtra("url", SessionManager.getInstance().getUserModel().getUserImg()));
                    }

                    public void onDismiss() {
                    }
                });
                dialog.show();
                return;
            case R.id.menuFAQLayout /*2131296828*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_faq);
                GAEvent.onGAScreenView(this, R.string.ga_faq_board);
                pushActivity(new Intent(this, WebViewActivity.class).putExtra("title", "\uc790\uc8fc\ubb3b\ub294\uc9c8\ubb38").putExtra("url", String.format(ApiUrl.FAQ_URL, new Object[]{SessionManager.getInstance().getAuthToken()})));
                return;
            case R.id.menuInquiryLayout /*2131296830*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_qna_1_on_1);
                GAEvent.onGAScreenView(this, R.string.ga_qna_board);
                pushActivity(new Intent(this, InquiryActivity.class));
                return;
            case R.id.menuInterestLayout /*2131296832*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_my_active);
                pushActivity(new Intent(this, InterestActivity.class).putExtra("inMenu", ""));
                return;
            case R.id.menuMyPaymentLayout /*2131296837*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_my_payment);
                if (!AppSettingManager.getInstance().isPasswordCheck()) {
                    Intent intent = new Intent(this, ConfirmPasswordActivity.class);
                    intent.putExtra("postType", 17);
                    animActivityForResult(intent, 153, R.anim.modal_animation, R.anim.scale_down);
                    return;
                }
                pushActivity(new Intent(this, MyPaymentActivity.class));
                return;
            case R.id.menuNonUserNotifyLayout /*2131296840*/:
                GAEvent.onGAScreenView(this, R.string.ga_notice_board);
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_notify);
                if (this.mModel != null) {
                    pushActivity(new Intent(this, NotifySettingActivity.class).putExtra("models", this.mModel.getResult_list()));
                    return;
                }
                return;
            case R.id.menuNoticeLayout /*2131296841*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_notice);
                GAEvent.onGAScreenView(this, R.string.ga_notice_board);
                pushActivity(new Intent(this, WebViewActivity.class).putExtra("title", "\uacf5\uc9c0\uc0ac\ud56d").putExtra("url", String.format(ApiUrl.NOTICE_URL, new Object[]{SessionManager.getInstance().getAuthToken()})));
                return;
            case R.id.menuNotificationCenterLayout /*2131296844*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_notification_center);
                pushActivity(new Intent(this, NotificationCenterActivity.class));
                return;
            case R.id.menuNotifyLayout /*2131296845*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_notify);
                if (this.mModel != null) {
                    pushActivity(new Intent(this, NotifySettingActivity.class).putExtra("models", this.mModel.getResult_list()));
                    return;
                }
                return;
            case R.id.menuPasswordLayout /*2131296847*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_password);
                pushActivity(new Intent(this, PasswordSettingActivity.class));
                return;
            case R.id.menuRegistCouponLayout /*2131296851*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_my_coupon);
                pushActivity(new Intent(this, CouponAndPointActivity.class));
                return;
            case R.id.menuServiceInfoLayout /*2131296852*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_service_infomation);
                pushActivity(new Intent(this, ServiceInfoActivity.class));
                return;
            case R.id.menuUseGuideLayout /*2131296853*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_use_guide);
                modalActivity(new Intent(this, GuideActivity.class).putExtra("menuRequest", ""));
                return;
            case R.id.menu_account /*2131296854*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_sns);
                return;
            case R.id.myCardLayout /*2131296880*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_my_card);
                if (!AppSettingManager.getInstance().isPasswordCheck()) {
                    Intent intent2 = new Intent(this, ConfirmPasswordActivity.class);
                    intent2.putExtra("postType", 18);
                    animActivityForResult(intent2, 153, R.anim.modal_animation, R.anim.scale_down);
                    return;
                }
                pushActivity(new Intent(this, MyCardActivity.class));
                return;
            case R.id.userNumber /*2131297480*/:
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, (int) R.string.ga_slide_member_number);
                return;
            default:
                return;
        }
    }

    /* access modifiers changed from: private */
    public void initGps() {
        if (getGpsManager() == null) {
            registGpsManager();
            if (getGpsManager() != null && getGpsManager().isGetLocation() && !AppSettingManager.getInstance().getMainListActionGuideStatus()) {
                animActivity(new Intent(getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "main"), R.anim.fade_in_activity, R.anim.fade_out_activity);
            }
            new Handler().postDelayed(new Runnable() {
                public void run() {
                    if (ShareatApp.getInstance().getGpsManager() != null && true == ShareatApp.getInstance().getGpsManager().isGetLocation()) {
                        EventBus.getDefault().post(new GpsRefreshEvent());
                    }
                }
            }, 500);
        }
    }

    private void initResume() {
        setNewIcon();
        if (ShareatApp.getInstance().getSocketManager() != null && ShareatApp.getInstance().getSocketManager().isPaying()) {
            ((CardView) findViewById(R.id.cardView)).showBillingView();
        }
        if (SessionManager.getInstance().hasSession() || AppSettingManager.getInstance().isLocationInfoAgreed()) {
            initGps();
            if (this.isFirstRun) {
                if (true == SessionManager.getInstance().hasSession()) {
                    requestGetNotificationApi();
                }
                requestAdvertiseApi();
                this.isFirstRun = false;
                if (getIntent().hasExtra("push")) {
                    showCircleDialog(true);
                    new Handler().postDelayed(new Runnable() {
                        public void run() {
                            MainActivity.this.setExternalData(MainActivity.this.getIntent());
                            MainActivity.this.showCircleDialog(false);
                        }
                    }, 1000);
                } else if (getIntent().hasExtra("quickPay")) {
                    showCircleDialog(true);
                    new Handler().postDelayed(new Runnable() {
                        public void run() {
                            MainActivity.this.setExternalData(MainActivity.this.getIntent());
                            MainActivity.this.showCircleDialog(false);
                        }
                    }, 1000);
                }
            }
        } else if (this.isFirstLocationAgreement) {
            int permission1 = ContextCompat.checkSelfPermission(this, "android.permission.ACCESS_NETWORK_STATE");
            int permission2 = ContextCompat.checkSelfPermission(this, "android.permission.ACCESS_FINE_LOCATION");
            if (permission1 != -1 && permission2 != -1) {
                showConfirmDialog("\ub0b4\uc8fc\ubcc0 \uc704\uce58\uc758 \ub9e4\uc7a5 \uc815\ubcf4\ub97c \uc81c\uacf5\ubc1b\uae30\uc704\ud574 \ud604\uc7ac \uc704\uce58 \uc815\ubcf4 \uc218\uc9d1\uc5d0 \ub300\ud55c \ub3d9\uc758\ub97c \ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?", new Runnable() {
                    public void run() {
                        AppSettingManager.getInstance().setLocationInfoAgreed(true);
                        MainActivity.this.initGps();
                    }
                });
                this.isFirstLocationAgreement = false;
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        ShareatApp.getInstance();
        ShareatApp.LOG_INFO("MainActivity onResume() Call");
        super.onResume();
        if (true == this.isCheckPermission) {
            initResume();
            return;
        }
        ((Builder) ((Builder) TedPermission.with(this).setPermissionListener(this.permissionlistener)).setPermissions("android.permission.ACCESS_NETWORK_STATE", "android.permission.ACCESS_FINE_LOCATION")).check();
    }

    /* access modifiers changed from: protected */
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setExternalData(intent);
    }

    /* access modifiers changed from: protected */
    public void onStop() {
        if (isApplicationSentToBackground(this)) {
            this.isAppBackground = true;
            if (getGpsManager() != null && getGpsManager().isGetLocation()) {
                AppSettingManager.getInstance().setGPSLat(String.valueOf(getGpsManager().getLatitude()));
                AppSettingManager.getInstance().setGPSLng(String.valueOf(getGpsManager().getLongitude()));
            }
        }
        super.onStop();
    }

    /* access modifiers changed from: protected */
    public void onRestart() {
        ShareatApp.getInstance();
        ShareatApp.LOG_INFO("MainActivity onRestart() Call");
        if (this.isAppBackground) {
            this.isAppBackground = false;
            if (getGpsManager() == null || !getGpsManager().isGetLocation()) {
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_enable_gps_name, (int) R.string.ga_enable_gps_result, getString(R.string.ga_enable_gps_result_value, new Object[]{"OFF"}));
            } else {
                GAEvent.onGaEvent((Activity) this, (int) R.string.ga_enable_gps_name, (int) R.string.ga_enable_gps_result, getString(R.string.ga_enable_gps_result_value, new Object[]{"ON"}));
                try {
                    String lat = AppSettingManager.getInstance().getGPSLat();
                    String lng = AppSettingManager.getInstance().getGPSLng();
                    if (!lat.isEmpty() && !lng.isEmpty() && DistanceCalculator.isOverDistance(Double.parseDouble(lat), Double.parseDouble(lng), getGpsManager().getLatitude(), getGpsManager().getLongitude())) {
                        EventBus.getDefault().post(new PostGnbOptionEvent());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                if (true == AppSettingManager.getInstance().getAutoBranchSearchStatus()) {
                    if (!LoplatManager.getInstance(this).getInitSuccess() && 1 == LoplatManager.getInstance(this).isLoplatStatus()) {
                        setLoplat();
                    }
                    super.onRestart();
                    return;
                }
                stopLoplat();
            }
        }
        super.onRestart();
    }

    private boolean checkHackToolResult(Map<Integer, String> result) {
        if (result.isEmpty()) {
            return true;
        }
        if (this.isCheckHack) {
            return true;
        }
        this.isCheckHack = true;
        String dialogMessage = "";
        if (result.containsKey(Integer.valueOf(3))) {
            ShareatApp.getInstance().showGlobalAlert("\uc250\uc5b4\uc573\uc740, \uc5d0\ubbac\ub808\uc774\ud130\uc5d0\uc11c\ub294 \uc2e4\ud589\uc774 \ubd88\uac00 \ud569\ub2c8\ub2e4.\uc0ac\uc6a9\uc744 \uc6d0\ud558\uc2dc\uba74 \ubaa8\ubc14\uc77c \uae30\uae30\uc5d0\uc11c \uc774\uc6a9\ud574 \uc8fc\uc138\uc694", new Runnable() {
                public void run() {
                    MainActivity.this.finish(false);
                    System.exit(0);
                }
            });
            return false;
        }
        if (result.containsKey(Integer.valueOf(0))) {
            dialogMessage = "\uace0\uac1d\ub2d8\uc758 \ub514\ubc14\uc774\uc2a4\uc5d0\uc11c \uba54\ubaa8\ub9ac \ud574\ud0b9 \ud234 " + result.get(Integer.valueOf(0)) + "\uac74\uc774 \ubc1c\uacac \ub418\uc5c8\uc2b5\ub2c8\ub2e4.";
        }
        if (result.containsKey(Integer.valueOf(1))) {
            dialogMessage = dialogMessage + (!dialogMessage.isEmpty() ? "\n" : "") + "\uace0\uac1d\ub2d8\uc758 \ub514\ubc14\uc774\uc2a4\uc5d0\uc11c \uc545\uc131 \ud504\ub85c\uc138\uc2a4 " + result.get(Integer.valueOf(1)) + "\uac74\uc774 \ubc1c\uacac \ub418\uc5c8\uc2b5\ub2c8\ub2e4.";
        }
        if (result.containsKey(Integer.valueOf(2))) {
            dialogMessage = dialogMessage + (!dialogMessage.isEmpty() ? "\n" : "") + "\uace0\uac1d\ub2d8\uc758 \ub514\ubc14\uc774\uc2a4\uc5d0\uc11c \ub8e8\ud305\uc774 \uac10\uc9c0 \ub418\uc5c8\uc2b5\ub2c8\ub2e4.";
        }
        if (!dialogMessage.isEmpty()) {
            Toast.makeText(this, dialogMessage, 0).show();
        }
        return true;
    }

    private boolean isDebuggable(Context context) {
        try {
            if ((context.getPackageManager().getApplicationInfo(context.getPackageName(), 0).flags & 2) != 0) {
                return true;
            }
            return false;
        } catch (NameNotFoundException e) {
            return false;
        }
    }

    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        init();
        showMainListLoading(true);
    }

    private void init() {
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_main, 1);
        moveDrawerToTop();
        this.mPagerAdapter = new FragmentViewPagerAdapter(getSupportFragmentManager());
        final PagingEnableViewPager viewPager = (PagingEnableViewPager) findViewById(R.id.viewPager);
        viewPager.setAddStatesFromChildren(false);
        viewPager.setAdapter(this.mPagerAdapter);
        viewPager.setPagingDisabled();
        viewPager.setCurrentItem(0);
        viewPager.setOffscreenPageLimit(5);
        viewPager.addOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
                if (position == 0) {
                    MainActivity.this.mIsMapMode = false;
                    MainActivity.this.isStoreClick = false;
                    ((CardView) MainActivity.this.findViewById(R.id.cardView)).setStoreClick(false);
                    MainActivity.this.mDrawerLayout.setDrawerLockMode(0);
                } else {
                    MainActivity.this.mDrawerLayout.setDrawerLockMode(1);
                }
                if (4 == position) {
                    MainActivity.this.mIsMapMode = true;
                }
            }

            public void onPageScrollStateChanged(int state) {
                if (state == 0 && 1 == viewPager.getCurrentItem()) {
                    double longitude = 127.027021d;
                    double latitude = 37.4986366d;
                    if (MainActivity.this.getGpsManager() != null) {
                        longitude = MainActivity.this.getGpsManager().getLongitude();
                        latitude = MainActivity.this.getGpsManager().getLatitude();
                    }
                    MainActivity.this.mPagerAdapter.getStoreFragment().postStoreData(String.valueOf(longitude), String.valueOf(latitude));
                }
            }
        });
        if (SessionManager.getInstance().hasSession()) {
            startService(new Intent(this, CommunicationService.class));
            GAEvent.onUserSignIn(this, ShareatApp.getInstance().getUserNum());
            IgawAdbrix.retention("login", ShareatApp.getInstance().getUserNum());
            requestUserInfoApi();
            registServiceBind();
            ShareatApp.getInstance().setSocketManager(getSocketManager());
            if (!getIntent().hasExtra("push")) {
                requestEventPopupApi();
            }
            ShareatApp.getInstance().registPushTokenApi();
        } else {
            EventBus.getDefault().post(new MainActivityEvent());
            if (!AppSettingManager.getInstance().isShowPushAgreementDialog()) {
                final Dialog agreementDialog = new Dialog(this);
                agreementDialog.requestWindowFeature(1);
                agreementDialog.getWindow().clearFlags(2);
                agreementDialog.getWindow().setFlags(32, 32);
                agreementDialog.setContentView(R.layout.image_alert_layer);
                agreementDialog.show();
                AppSettingManager.getInstance().setShowPushAgreementDialog(true);
                agreementDialog.setOnKeyListener(new OnKeyListener() {
                    public boolean onKey(DialogInterface dialog, int keyCode, KeyEvent event) {
                        if (keyCode == 4) {
                            return true;
                        }
                        return false;
                    }
                });
                agreementDialog.findViewById(R.id.not_accept).setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        AppSettingManager.getInstance().setKeyNonMemberPushStatus(false);
                        agreementDialog.dismiss();
                        ShareatApp.getInstance().registPushTokenApi(new Runnable() {
                            public void run() {
                                MainActivity.this.requestNonUserNotificationApi(2);
                            }
                        });
                    }
                });
                agreementDialog.findViewById(R.id.accept).setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        AppSettingManager.getInstance().setKeyNonMemberPushStatus(true);
                        agreementDialog.dismiss();
                        Calendar c = Calendar.getInstance();
                        Toast.makeText(MainActivity.this.getBaseContext(), (((String.valueOf(c.get(1)) + "\ub144 ") + String.format("%02d", new Object[]{Integer.valueOf(c.get(2) + 1)}) + "\uc6d4 ") + String.format("%02d", new Object[]{Integer.valueOf(c.get(5))}) + "\uc77c") + " \uc815\ubcf4 \uc54c\ub9bc \ub3d9\uc758\ub97c \ud558\uc168\uc2b5\ub2c8\ub2e4", 1).show();
                        ShareatApp.getInstance().registPushTokenApi(new Runnable() {
                            public void run() {
                                MainActivity.this.requestNonUserNotificationApi(2);
                            }
                        });
                    }
                });
            } else {
                ShareatApp.getInstance().registPushTokenApi(new Runnable() {
                    public void run() {
                        MainActivity.this.requestNonUserNotificationApi(1);
                    }
                });
            }
        }
        this.mPagerAdapter.notifyDataSetChanged();
        setAnimationListener(new OnAnimationListener() {
            public void OnOpenCardView() {
                if (MainActivity.this.mPagerAdapter != null && MainActivity.this.mPagerAdapter.getMainFragment().getStoreListCount() > 0) {
                    MainActivity.this.showCardViewAnimation();
                }
            }
        });
        this.mMainlistLoading = new LoadingCircleDialog(this);
        this.mMainlistLoading.setCancelable(false);
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
        unregistServiceBind();
        stopService(new Intent(this, CommunicationService.class));
        stopService(new Intent(this, AddressService.class));
        if (getGpsManager() != null) {
            getGpsManager().ondestory();
        }
        AppSettingManager.getInstance().setPasswordCheck(false);
    }

    private void setDifferentPassword(SocketReceiveEvent event) {
        if (((ActivityManager) getSystemService("activity")).getRunningTasks(1).get(0).topActivity.getClassName().equals(MainActivity.class.getName())) {
            showConfirmDialog(event.getParams(), "\ud655\uc778", getString(R.string.app_password_setting), new Runnable() {
                public void run() {
                    GAEvent.onGaEvent((Activity) MainActivity.this, (int) R.string.quickpayview_pay_pw_error, (int) R.string.ga_ev_click, MainActivity.this.getString(R.string.CONFIRM));
                }
            }, new Runnable() {
                public void run() {
                    GAEvent.onGaEvent((Activity) MainActivity.this, (int) R.string.quickpayview_pay_pw_error, (int) R.string.ga_ev_click, MainActivity.this.getString(R.string.app_password_setting));
                    new CustomSchemeManager();
                    CustomSchemeManager.postSchemeAction(MainActivity.this, "shareat://shareat.me/passwordSetting");
                }
            });
        }
        ((CardView) findViewById(R.id.cardView)).finishBilling();
    }

    private boolean isSchemeLink(String linkUrl) {
        if (linkUrl == null) {
            return false;
        }
        if (linkUrl.contains("shareat://shareat.me/") || linkUrl.contains("share://shareat.me/")) {
            return true;
        }
        return false;
    }

    private void setPayingCancel(String message) {
        if (((ActivityManager) getSystemService("activity")).getRunningTasks(1).get(0).topActivity.getClassName().equals(MainActivity.class.getName())) {
            showDialog(message);
        }
        ((CardView) findViewById(R.id.cardView)).finishBilling();
    }

    public Bundle getExternalParams() {
        return this.mExternalParams;
    }

    /* access modifiers changed from: private */
    public void setExternalData(Intent data) {
        String actionId;
        if (true == data.hasExtra("quickPay")) {
            openCardView();
        } else if (data.hasExtra("push")) {
            PushModel model = (PushModel) data.getSerializableExtra("push");
            if (model != null) {
                requestReadPush(data);
                if (model.getCustomScheme() == null || model.getCustomScheme().isEmpty()) {
                    try {
                        if (Integer.valueOf(model.type) != null) {
                            if (model.getMessage() != null) {
                                switch (model.type) {
                                    case 1:
                                        actionId = "\uacb0\uc81c\uc644\ub8cc";
                                        break;
                                    case 2:
                                        actionId = "\ucc1c\ud55c\ub9e4\uc7a5\uc2e0\uaddc\ub9ac\ubdf0";
                                        break;
                                    case 3:
                                        actionId = "\ub9ac\ubdf0\uc88b\uc544\uc694";
                                        break;
                                    case 4:
                                        actionId = "1:1\ubb38\uc758\ub2f5\ubcc0";
                                        break;
                                    case 5:
                                        actionId = "\ud504\ub85c\ubaa8\uc158";
                                        break;
                                    default:
                                        actionId = "";
                                        break;
                                }
                                GAEvent.onGaEvent("\ud478\uc2dc\uba54\uc2dc\uc9c0", actionId, model.getMessage());
                            }
                            switch (model.type) {
                                case 1:
                                    if (SessionManager.getInstance().getUserModel().isEnablePassword()) {
                                        pushActivity(new Intent(this, MyPaymentActivity.class));
                                        return;
                                    }
                                    Intent intent = new Intent(this, ConfirmPasswordActivity.class);
                                    intent.putExtra("postType", 17);
                                    animActivityForResult(intent, 153, R.anim.modal_animation, R.anim.scale_down);
                                    return;
                                case 2:
                                case 3:
                                    requestPushStoreDetailApi(model.partner_sno, true);
                                    return;
                                case 5:
                                    if (model.getLinkUrl() != null && !model.getLinkUrl().isEmpty()) {
                                        Intent intent2 = new Intent(this, EventActivity.class);
                                        intent2.putExtra("link_url", model.getLinkUrl());
                                        animActivity(intent2, R.anim.fade_in_activity, R.anim.fade_out_activity);
                                        return;
                                    }
                                    return;
                                case 99:
                                    requestPushStoreDetailApi(model.partner_sno, false);
                                    return;
                                default:
                                    return;
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    Uri receiveUrl = Uri.parse(model.getCustomScheme());
                    String pathString = receiveUrl.getPath();
                    if (pathString.startsWith("/")) {
                        pathString = pathString.replaceFirst("/", "");
                    }
                    if (pathString.equals(EXTRA_SCHEME_PATH_MAINLIST) || pathString.equals("payment")) {
                        String queryString = receiveUrl.getQuery() == null ? "" : receiveUrl.getQuery();
                        if (queryString != null && !queryString.isEmpty()) {
                            Bundle bundle = CustomSchemeManager.getQueryBundle(queryString);
                            if (pathString.equals("payment")) {
                                onQuickPayStore(bundle.getString("partner_sno"));
                                return;
                            }
                            this.mExternalParams = bundle;
                            EventBus.getDefault().post(new SchemeMainlistEvent(bundle));
                            return;
                        }
                        return;
                    }
                    new CustomSchemeManager();
                    CustomSchemeManager.postSchemeAction(this, model.getCustomScheme());
                }
            }
        }
    }

    private void moveDrawerToTop() {
        this.mDrawerLayout = (DrawerLayout) findViewById(R.id.drawerLayout);
        this.mDrawerLayout.addDrawerListener(this.drawerListener);
        if (VERSION.SDK_INT >= 19) {
            this.mDrawerLayout.findViewById(R.id.drawer).setPadding(0, getStatusBarHeight(), 0, 0);
        }
        ((ViewGroup) this.mDrawerLayout.findViewById(R.id.drawer)).addView(SessionManager.getInstance().hasSession() ? View.inflate(this, R.layout.view_slide_menu, null) : View.inflate(this, R.layout.view_slide_non_member_menu, null));
        menuSetting();
    }

    private void menuSetting() {
        this.mDrawerLayout.findViewById(R.id.iconClose).setOnClickListener(this);
        this.mDrawerLayout.findViewById(R.id.iconProfile).setOnClickListener(this);
        if (!SessionManager.getInstance().hasSession()) {
            this.mDrawerLayout.findViewById(R.id.menuNonUserNotifyLayout).setOnClickListener(this);
        }
        this.mDrawerLayout.findViewById(R.id.menuNoticeLayout).setOnClickListener(this);
        this.mDrawerLayout.findViewById(R.id.menuFAQLayout).setOnClickListener(this);
        this.mDrawerLayout.findViewById(R.id.menuUseGuideLayout).setOnClickListener(this);
        this.mDrawerLayout.findViewById(R.id.menuServiceInfoLayout).setOnClickListener(this);
        ((TextView) this.mDrawerLayout.findViewById(R.id.appVersionLabel)).setText(ShareatApp.getInstance().getAppVersionName());
        if (SessionManager.getInstance().hasSession()) {
            this.mDrawerLayout.findViewById(R.id.menuMyPaymentLayout).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.myCardLayout).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.menuInterestLayout).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.menuInquiryLayout).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.menuRegistCouponLayout).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.menuNotifyLayout).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.menuPasswordLayout).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.friendsGroupLayout).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.menuAvatarImageView).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.advertiseView).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.menu_account).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.userNumber).setOnClickListener(this);
            this.mDrawerLayout.findViewById(R.id.menuNotificationCenterLayout).setOnClickListener(this);
            ((TextView) this.mDrawerLayout.findViewById(R.id.memberNumberLabel)).setText(ShareatApp.getInstance().getUserNum());
            return;
        }
        this.mDrawerLayout.findViewById(R.id.joinButton).setOnClickListener(this);
        ((Button) this.mDrawerLayout.findViewById(R.id.joinButton)).setText("\ub85c\uadf8\uc778/\ud68c\uc6d0\uac00\uc785");
        ((TextView) this.mDrawerLayout.findViewById(R.id.descriptionLabel)).setText(String.format(getResources().getString(R.string.SLIDE_VIEW_DESCRIPTION), new Object[]{"\ub85c\uadf8\uc778/\ud68c\uc6d0\uac00\uc785"}));
    }

    private void postUploadImagePath(String path) {
        if (path != null && !path.isEmpty()) {
            ShareatApp.getInstance();
            ShareatApp.requestAvatarImageApi(path);
        }
    }

    public FragmentViewPagerAdapter getPagerAdapter() {
        return this.mPagerAdapter;
    }

    public void showNMapFragment() {
        ((MainNMapFragment) this.mPagerAdapter.getItem(4)).initMap();
        this.mPagerAdapter.refreshNMapFragmentLifeCycle();
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(4, false);
        animateCardLayout(false);
        setGNBMapAndList(false);
        if (!AppSettingManager.getInstance().getNaverMapActionGuideStatus()) {
            animActivity(new Intent(getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "naver_map"), R.anim.fade_in_activity, R.anim.fade_out_activity);
        }
    }

    /* access modifiers changed from: private */
    public void requestUserInfoApi() {
        new UserInfoApi(this, 1).request(new RequestHandler() {
            public void onStart() {
                MainActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                MainActivity.this.showCircleDialog(false);
                UserModel model = ((UserResultModel) result).getUserInfo();
                if (model.getUserImg() != null) {
                    ImageDisplay.getInstance().displayImageLoadRound(model.getUserImg(), (ImageView) MainActivity.this.mDrawerLayout.findViewById(R.id.menuAvatarImageView), MainActivity.this.getResources().getDimensionPixelOffset(R.dimen.AVATAR_ROUND_SIZE_25OPX));
                }
                ((TextView) MainActivity.this.findViewById(R.id.nameLabel)).setText(model.getUserName());
                if (model.getUser_phone() != null && !model.getUser_phone().isEmpty()) {
                    String phoneNum = model.getUser_phone();
                    if (10 < phoneNum.length()) {
                        phoneNum = phoneNum.substring(0, 3) + "-" + phoneNum.substring(3, 7) + "-" + phoneNum.substring(7, phoneNum.length());
                    }
                    ((TextView) MainActivity.this.findViewById(R.id.phoneLabel)).setText(phoneNum);
                }
                ((TextView) MainActivity.this.findViewById(R.id.emailLabel)).setText(model.getEmail());
                MainActivity.this.mDrawerLayout.findViewById(R.id.menuPasswordIcon).setSelected(model.isEnablePassword());
                EventBus.getDefault().post(new SuccessProfileUpdateEvent());
                MainActivity.this.setCardInfo();
            }

            public void onFailure(Exception exception) {
                MainActivity.this.showCircleDialog(false);
                MainActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        MainActivity.this.requestUserInfoApi();
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestGetNotificationApi() {
        new NotificationApi(this, 1, SessionManager.getInstance().hasSession()).request(new RequestHandler() {
            public void onResult(Object result) {
                MainActivity.this.mModel = (NotificationResultModel) result;
                if (MainActivity.this.mModel != null) {
                    Iterator<NotificationModel> it = MainActivity.this.mModel.getResult_list().iterator();
                    while (it.hasNext()) {
                        NotificationModel notifyModel = it.next();
                        if (notifyModel.getNotice_id().equals("90")) {
                            AppSettingManager.getInstance().setAutoBranchSearchStatus("Y".equals(notifyModel.getUse_yn()));
                            return;
                        }
                    }
                }
            }

            public void onFinish() {
                super.onFinish();
                EventBus.getDefault().post(new RequestLoplatConfigEvent("loplat"));
            }

            public void onFailure(Exception exception) {
                MainActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        MainActivity.this.requestGetNotificationApi();
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestNonUserNotificationApi(final int requestType) {
        NotificationApi request = new NotificationApi(this, requestType, SessionManager.getInstance().hasSession());
        request.addParam("guid", ShareatApp.getInstance().getGUID());
        if (requestType == 2) {
            NotificationResultModel notificationModel = new NotificationResultModel();
            ArrayList<NotificationModel> arrNotificationModel = new ArrayList<>();
            NotificationModel pushAgreeModel = new NotificationModel();
            pushAgreeModel.setUse_yn(true == AppSettingManager.getInstance().getKeyNonMemberPushStatus() ? "Y" : "N");
            pushAgreeModel.setNotice_id("100");
            arrNotificationModel.add(pushAgreeModel);
            notificationModel.setResult_list(arrNotificationModel);
            request.addParam("list", notificationModel.getRequestParam());
        }
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                if (requestType == 1) {
                    MainActivity.this.mModel = (NotificationResultModel) result;
                } else {
                    MainActivity.this.requestNonUserNotificationApi(1);
                }
            }

            public void onFinish() {
                super.onFinish();
            }

            public void onFailure(Exception exception) {
                MainActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        MainActivity.this.requestNonUserNotificationApi(requestType);
                    }
                });
            }
        });
    }

    private void requestExternalConfigApi(String strExternalBrand) {
        String parameter = String.format("?app_code=%s", new Object[]{strExternalBrand});
        ExternalLoplatConfigApi request = new ExternalLoplatConfigApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onStart() {
            }

            public void onResult(Object result) {
                LoplatConfigResultModel model = (LoplatConfigResultModel) result;
                if (model != null) {
                    LoplatManager.getInstance(MainActivity.this.getBaseContext()).setLoplatConfigModel(model.getLoplat_config());
                    if (true == AppSettingManager.getInstance().getAutoBranchSearchStatus()) {
                        MainActivity.this.setLoplat();
                    } else {
                        MainActivity.this.stopLoplat();
                    }
                }
            }

            public void onFailure(Exception exception) {
                if (true == AppSettingManager.getInstance().getAutoBranchSearchStatus()) {
                    MainActivity.this.setLoplat();
                } else {
                    MainActivity.this.stopLoplat();
                }
            }
        });
    }

    public void onEventMainThread(RequestLoplatConfigEvent event) {
        requestExternalConfigApi(event.getExternalBrand());
    }

    /* access modifiers changed from: private */
    public void requestPushStoreDetailApi(final String partnerSno, final boolean isReviewTop) {
        Object[] objArr = new Object[3];
        objArr[0] = partnerSno;
        objArr[1] = String.valueOf(getGpsManager() == null ? 127.027021d : getGpsManager().getLongitude());
        objArr[2] = String.valueOf(getGpsManager() == null ? 37.4986366d : getGpsManager().getLatitude());
        String parameter = String.format("?partner_sno=%s&user_X=%s&user_Y=%s", objArr);
        StoreApi request = new StoreApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onStart() {
                MainActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                StoreDetailModel detailModel = ((StoreDetailResultModel) result).getStore_detail();
                StoreModel storeModel = new StoreModel();
                storeModel.partnerName1 = detailModel.getPartner_name1();
                storeModel.favoriteYn = detailModel.favorite_yn;
                storeModel.partnerSno = String.valueOf(detailModel.partner_sno);
                try {
                    storeModel.distance = String.valueOf(detailModel.distance);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                ((CardView) MainActivity.this.findViewById(R.id.cardView)).clearStoreModel();
                Intent intent = new Intent(MainActivity.this, StoreDetailActivity.class);
                intent.putExtra("model", storeModel);
                if (isReviewTop) {
                    intent.putExtra("isReviewTop", "");
                }
                MainActivity.this.pushActivity(intent);
                new Handler().post(new Runnable() {
                    public void run() {
                        MainActivity.this.showCircleDialog(false);
                    }
                });
            }

            public void onFailure(Exception exception) {
                MainActivity.this.showCircleDialog(false);
                MainActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        MainActivity.this.requestPushStoreDetailApi(partnerSno, isReviewTop);
                    }
                });
            }
        });
    }

    private void requestEventPopupApi() {
        if (AppSettingManager.getInstance().getEventViewingDate() <= System.currentTimeMillis()) {
            EventPopupApi request = new EventPopupApi(this);
            request.addGetParam("?board_gubun=NOTI&page=1&view_cnt=10");
            request.request(new RequestHandler() {
                public void onStart() {
                    MainActivity.this.showCircleDialog(true);
                }

                public void onFinish() {
                    MainActivity.this.showCircleDialog(false);
                }

                public void onResult(Object result) {
                    MainActivity.this.showCircleDialog(false);
                    BoardResultModel model = (BoardResultModel) result;
                    if (model.isOkResponse() && model.getResult() != null && model.getResult().equals("Y") && model.getResult_list() != null && model.getResult_list().size() > 0) {
                        MainActivity.this.mBoardModel = model.getResult_list().get(0);
                        Intent intent = new Intent(MainActivity.this, EventActivity.class);
                        intent.putExtra("model", MainActivity.this.mBoardModel);
                        MainActivity.this.animActivity(intent, R.anim.fade_in_activity, R.anim.fade_out_activity);
                    }
                }
            });
        }
    }

    /* access modifiers changed from: private */
    public void stopLoplat() {
        LoplatManager.getInstance(this).setInitSuccess(false);
        LoplatManager.getInstance(this).clearData();
        LoplatManager.getInstance(this).stopPlaceMonitoring();
    }

    /* access modifiers changed from: private */
    public void setLoplat() {
        if (VERSION.SDK_INT < 23 || (getGpsManager() != null && getGpsManager().isGetLocation())) {
            checkWiFiScanConditionInMashmallow(this);
            if (!LoplatManager.getInstance(this).getInitSuccess()) {
                ShareatLogger.writeLog("[DEBUG] Loplat SDK init Success");
                LoplatManager.getInstance(this).initPlaceEngine();
            }
            if (1 == LoplatManager.getInstance(this).isLoplatStatus()) {
                ShareatLogger.writeLog("[DEBUG] Request current place info");
                LoplatManager.getInstance(this).setFindSuccess(false);
                LoplatManager.getInstance(this).setRecentSearchTime(new Date(System.currentTimeMillis()));
                LoplatManager.getInstance(this).requestLocationInfo();
                LoplatManager.getInstance(this).startPlaceMonitoring();
                ShareatLogger.writeLog("[DEBUG] Request background place monitoring");
            }
        }
    }

    private void checkWiFiScanConditionInMashmallow(Context context) {
        if (VERSION.SDK_INT >= 23) {
            LocationManager locationManager = (LocationManager) context.getSystemService(Param.LOCATION);
            boolean isNetworkEnabled = locationManager.isProviderEnabled("network");
            boolean isGPSEnabled = locationManager.isProviderEnabled("gps");
            if (isNetworkEnabled || !isGPSEnabled) {
            }
            PackageManager pm = context.getPackageManager();
            int permission = pm.checkPermission("android.permission.ACCESS_FINE_LOCATION", context.getPackageName());
            int subpermission = pm.checkPermission("android.permission.ACCESS_COARSE_LOCATION", context.getPackageName());
            if (permission != 0 && subpermission != 0) {
                ActivityCompat.requestPermissions(this, new String[]{"android.permission.ACCESS_FINE_LOCATION"}, 1);
                ActivityCompat.requestPermissions(this, new String[]{"android.permission.ACCESS_COARSE_LOCATION"}, 1);
            }
        }
    }

    public void onEventMainThread(AdvertiseEvent event) {
        if (AdvertiseType.MAIN == event.getAdvertiseType()) {
            LinearLayout ll = (LinearLayout) findViewById(R.id.advertiseView);
            if (ll != null) {
                ll.setVisibility(0);
                AdvertiseModel am = event.getAdvertiseModel();
                float nHeight = getBaseContext().getResources().getDimension(R.dimen.ADVERTISE_HEIGHT);
                Iterator<AdvertiseDetailModel> it = am.getResult_list().iterator();
                while (it.hasNext()) {
                    final AdvertiseDetailModel advertiseDetailModel = it.next();
                    String image_path = advertiseDetailModel.getImage_path();
                    ImageView imageView = new ImageView(getBaseContext());
                    imageView.setLayoutParams(new LayoutParams(-1, (int) nHeight));
                    imageView.setScaleType(ScaleType.FIT_XY);
                    imageView.setClickable(true);
                    ImageDisplay.getInstance().displayImageLoad(image_path, imageView);
                    ll.addView(imageView);
                    imageView.setOnClickListener(new OnClickListener() {
                        public void onClick(View v) {
                            String scheme_url = advertiseDetailModel.getScheme_url();
                            String queryString = Uri.parse(scheme_url).getEncodedQuery();
                            if (queryString != null) {
                                Bundle bundle = MainActionBarActivity.getQueryBundle(queryString);
                                String link_url = bundle.getString("link_url");
                                String execute = bundle.getString("execute");
                                String title = MainActivity.this.getString(R.string.ga_slide_advertise_title, new Object[]{bundle.getString("title")});
                                if (true == MainActivity.WEB_EXECUTE_IN_TYPE.equals(execute)) {
                                    GAEvent.onGaEvent((Activity) MainActivity.this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, title);
                                    new CustomSchemeManager();
                                    CustomSchemeManager.postSchemeAction(MainActivity.this, scheme_url);
                                } else if (true == MainActivity.WEB_EXECUTE_OUT_TYPE.equals(execute)) {
                                    GAEvent.onGaEvent((Activity) MainActivity.this, (int) R.string.ga_slide_more_menu, (int) R.string.ga_ev_click, title);
                                    MainActivity.this.startActivity(new Intent("android.intent.action.VIEW", Uri.parse(link_url.replace("$user_sno", ShareatApp.getInstance().getUserNum()).replace("$auth_token", SessionManager.getInstance().getAuthToken()).replace("$version", ShareatApp.getInstance().getAppVersionName()))));
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    private void requestAdvertiseApi() {
        AdvertiseApi request = new AdvertiseApi(this);
        request.addGetParam(String.format("?os=A&app_version=%s", new Object[]{ShareatApp.getInstance().getAppVersionName()}));
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                AdvertiseModel advertiseModel = (AdvertiseModel) result;
                if (advertiseModel != null && advertiseModel.getTotal_cnt() > 0) {
                    new AdvertiseEvent(advertiseModel).setAdvertiseType(AdvertiseType.MAIN);
                    EventBus.getDefault().post(new AdvertiseEvent(advertiseModel));
                }
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }

    public boolean isCurrentFragment(Fragment fragment) {
        int fragmentIndex;
        if (fragment instanceof MainFragment) {
            fragmentIndex = 0;
        } else if (fragment instanceof StoreDetailFragment) {
            fragmentIndex = 1;
        } else if (fragment instanceof LocationFragment) {
            fragmentIndex = 2;
        } else if (fragment instanceof CategoryFragment) {
            fragmentIndex = 3;
        } else if (fragment instanceof MainNMapFragment) {
            fragmentIndex = 4;
        } else {
            fragmentIndex = 0;
        }
        if (fragmentIndex == ((ViewPager) findViewById(R.id.viewPager)).getCurrentItem()) {
            return true;
        }
        return false;
    }

    private void requestReadPush(Intent data) {
        if (data.hasExtra("push")) {
            String pushSno = ((PushModel) data.getSerializableExtra("push")).getPush_sno();
            if (pushSno != null && true != pushSno.isEmpty()) {
                ReadPushApi request = new ReadPushApi(this);
                request.addGetParam(String.format("?phone_os=A&push_sno=%s", new Object[]{pushSno}));
                request.request(new RequestHandler() {
                    public void onResult(Object result) {
                        MainActivity.this.readBadgeCount();
                        MainActivity.this.setNewIcon();
                    }

                    public void onFailure(Exception exception) {
                        super.onFailure(exception);
                    }

                    public void onFinish() {
                        super.onFinish();
                    }
                });
            }
        }
    }

    /* access modifiers changed from: private */
    public void readBadgeCount() {
        int count = AppSettingManager.getInstance().getNotificationCount() - 1;
        if (count >= 0) {
            Intent badgeIntent = new Intent("android.intent.action.BADGE_COUNT_UPDATE");
            badgeIntent.putExtra("badge_count_package_name", getApplication().getPackageName());
            badgeIntent.putExtra("badge_count_class_name", getApplication().getPackageName() + ".activity.intro.SplashActivity");
            badgeIntent.putExtra("badge_count", count);
            sendBroadcast(badgeIntent);
            AppSettingManager.getInstance().setNotificationCountint(count);
        }
    }

    /* access modifiers changed from: private */
    public void setNewIcon() {
        if (this.mDrawerLayout != null) {
            ImageView menuNewIcon = (ImageView) this.mDrawerLayout.findViewById(R.id.menuNotificationCenterImg);
            ImageView gnbNewIcon = (ImageView) findViewById(R.id.menuNewImg);
            if (AppSettingManager.getInstance().getNotificationCount() > 0) {
                if (menuNewIcon != null) {
                    menuNewIcon.setVisibility(0);
                }
                if (gnbNewIcon != null) {
                    gnbNewIcon.setVisibility(0);
                    return;
                }
                return;
            }
            if (menuNewIcon != null) {
                menuNewIcon.setVisibility(8);
            }
            if (gnbNewIcon != null) {
                gnbNewIcon.setVisibility(8);
            }
        }
    }

    public void showMainListLoading(boolean visibility) {
        if (this.mMainlistLoading != null) {
            if (visibility && !this.mMainlistLoading.isShowing()) {
                this.mMainlistLoading.show();
            }
            if (!visibility && this.mMainlistLoading != null && this.mMainlistLoading.isShowing()) {
                this.mMainlistLoading.dismiss();
            }
        }
    }

    public void onEventMainThread(MainResumeEvent event) {
        clearBillingView();
        ((CardView) findViewById(R.id.cardView)).finishBilling();
    }
}