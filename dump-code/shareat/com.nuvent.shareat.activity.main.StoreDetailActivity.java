package com.nuvent.shareat.activity.main;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.Fragment;
import android.support.v4.widget.DrawerLayout;
import android.view.View;
import android.view.animation.AnimationUtils;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.crop.CropActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.store.StoreApi;
import com.nuvent.shareat.event.CardSlideEvent;
import com.nuvent.shareat.event.CardViewStatusEvent;
import com.nuvent.shareat.event.PayingEvent;
import com.nuvent.shareat.event.SocketReceiveEvent;
import com.nuvent.shareat.fragment.StoreDetailFragment;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.LoplatManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.payment.PayResultModel;
import com.nuvent.shareat.model.store.StoreDetailModel;
import com.nuvent.shareat.model.store.StoreDetailResultModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.view.CardView;
import de.greenrobot.event.EventBus;

public class StoreDetailActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public StoreDetailFragment mFragment;
    /* access modifiers changed from: private */
    public boolean mIsOpenPassword = false;
    /* access modifiers changed from: private */
    public StoreModel mModel;

    public void onEventMainThread(CardSlideEvent event) {
        if (event.isOpen()) {
            findViewById(R.id.dimBar).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
            findViewById(R.id.dimBar).setVisibility(0);
            return;
        }
        findViewById(R.id.dimBar).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_out));
        findViewById(R.id.dimBar).setVisibility(8);
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

    private void setDifferentPassword(SocketReceiveEvent event) {
        ComponentName topActivity = ((ActivityManager) getSystemService("activity")).getRunningTasks(1).get(0).topActivity;
        if (topActivity.getClassName().equals(StoreDetailActivity.class.getName()) || topActivity.getClassName().equals("com.nuvent.shareat.store")) {
            showConfirmDialog(event.getParams(), "\ud655\uc778", getString(R.string.app_password_setting), new Runnable() {
                public void run() {
                    GAEvent.onGaEvent((Activity) StoreDetailActivity.this, (int) R.string.quickpayview_pay_pw_error, (int) R.string.ga_ev_click, StoreDetailActivity.this.getString(R.string.CONFIRM));
                }
            }, new Runnable() {
                public void run() {
                    GAEvent.onGaEvent((Activity) StoreDetailActivity.this, (int) R.string.quickpayview_pay_pw_error, (int) R.string.ga_ev_click, StoreDetailActivity.this.getString(R.string.app_password_setting));
                    new CustomSchemeManager();
                    CustomSchemeManager.postSchemeAction(StoreDetailActivity.this, "shareat://shareat.me/passwordSetting");
                }
            });
        }
        ((CardView) findViewById(R.id.cardView)).finishBilling();
    }

    private void setPayingCancel(String message) {
        if (((ActivityManager) getSystemService("activity")).getRunningTasks(1).get(0).topActivity.getClassName().equals(StoreDetailActivity.class.getName())) {
            showDialog(message);
        }
        ((CardView) findViewById(R.id.cardView)).finishBilling();
    }

    public void onEventMainThread(PayingEvent event) {
        if (true != event.isDeliveryCardView && event.isPaying()) {
            ((CardView) findViewById(R.id.cardView)).showBillingView();
        }
    }

    public void onBackPressed() {
        if (isOpenCardView()) {
            closeCardView();
        } else {
            super.onBackPressed();
        }
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_fragment, 2);
        new Handler().post(new Runnable() {
            public void run() {
                StoreDetailActivity.this.showCircleDialog(true);
            }
        });
        ((DrawerLayout) findViewById(R.id.drawerLayout)).setDrawerLockMode(1);
        if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_URL)) {
            Bundle bundle = getIntent().getBundleExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER);
            String partnerSno = bundle.getString("partner_sno");
            String newStart = bundle.getString("new_start");
            if (newStart != null && !newStart.isEmpty() && newStart.equals("ok")) {
                LoplatManager.getInstance(getBaseContext()).setNewStart(true);
            }
            this.mModel = new StoreModel();
            this.mModel.setPartnerName1("");
            this.mModel.setPartnerSno(partnerSno);
        } else {
            this.mModel = (StoreModel) getIntent().getSerializableExtra("model");
        }
        setCardInfo();
        if (this.mModel == null) {
            finish();
            return;
        }
        setFavoriteButton(this.mModel.getFavoriteYn());
        setTitle(this.mModel.getPartnerName1());
        this.mFragment = new StoreDetailFragment();
        if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_SUB_TAB_NAME)) {
            this.mFragment.setSubTab(getIntent().getStringExtra(CustomSchemeManager.EXTRA_INTENT_SUB_TAB_NAME));
        }
        if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER)) {
            Bundle value = getIntent().getBundleExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER);
            this.mFragment.setSchemeParams(value);
            this.mIsOpenPassword = "Y".equals(value.getString("open_password_view", "N"));
        }
        this.mFragment.setReviewTop(getIntent().hasExtra("isReviewTop"));
        getSupportFragmentManager().beginTransaction().add((int) R.id.container, (Fragment) this.mFragment).commit();
        requestPushStoreDetailApi(this.mModel.getPartnerSno());
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == -1) {
            switch (requestCode) {
                case CropActivity.CROP_FROM_STORE_DETAIL /*5858*/:
                    this.mFragment.onActivityResult(requestCode, resultCode, data);
                    break;
            }
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    public void onClickFavoriteFragment(View view) {
        if (!SessionManager.getInstance().hasSession()) {
            showLoginDialog();
            return;
        }
        view.setSelected(!view.isSelected());
        this.mFragment.requestFavoriteStoreApi(view);
    }

    public void onClickBackFragment(View view) {
        finish();
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
        try {
            if (ShareatApp.getInstance().getSocketManager() == null || ShareatApp.getInstance().getSocketManager().isPaying()) {
            }
        } catch (NullPointerException e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: private */
    public void requestPushStoreDetailApi(final String partnerSno) {
        double lat = 37.4986366d;
        double lng = 127.027021d;
        if (ShareatApp.getInstance().getGpsManager() != null) {
            lat = ShareatApp.getInstance().getGpsManager().getLatitude();
            lng = ShareatApp.getInstance().getGpsManager().getLongitude();
        }
        String parameter = String.format("?partner_sno=%s&user_X=%s&user_Y=%s", new Object[]{partnerSno, String.valueOf(lng), String.valueOf(lat)});
        StoreApi request = new StoreApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                StoreDetailActivity.this.showCircleDialog(false);
                StoreDetailModel detailModel = ((StoreDetailResultModel) result).getStore_detail();
                StoreDetailActivity.this.mModel.partnerName1 = detailModel.getPartner_name1();
                StoreDetailActivity.this.mModel.setBarcode(detailModel.isBarcode());
                StoreDetailActivity.this.setTitle(StoreDetailActivity.this.mModel.getPartnerName1());
                StoreDetailActivity.this.mModel.setPaymentMethodType(detailModel.getPaymentMethodType());
                StoreDetailActivity.this.mModel.setMethod(detailModel.getMethod());
                StoreDetailActivity.this.mModel.favoriteYn = detailModel.favorite_yn;
                StoreDetailActivity.this.mModel.partnerSno = String.valueOf(detailModel.partner_sno);
                StoreDetailActivity.this.mModel.setDcRate(detailModel.getDc_rate());
                try {
                    StoreDetailActivity.this.mModel.distance = String.valueOf(detailModel.distance);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                ((CardView) StoreDetailActivity.this.findViewById(R.id.cardView)).setStoreModel(StoreDetailActivity.this.mModel);
                ((CardView) StoreDetailActivity.this.findViewById(R.id.cardView)).setOpenPasswordView(StoreDetailActivity.this.mIsOpenPassword);
                StoreDetailActivity.this.mIsOpenPassword = false;
                if (!StoreDetailActivity.this.mFragment.isSetModel()) {
                    StoreDetailActivity.this.mFragment.setStoreModel(StoreDetailActivity.this.mModel);
                    double lat = 37.4986366d;
                    double lng = 127.027021d;
                    if (ShareatApp.getInstance().getGpsManager() != null) {
                        lat = ShareatApp.getInstance().getGpsManager().getLatitude();
                        lng = ShareatApp.getInstance().getGpsManager().getLongitude();
                    }
                    StoreDetailActivity.this.mFragment.postStoreData(String.valueOf(lng), String.valueOf(lat));
                }
            }

            public void onFailure(Exception exception) {
                StoreDetailActivity.this.showCircleDialog(false);
                StoreDetailActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        StoreDetailActivity.this.requestPushStoreDetailApi(partnerSno);
                    }
                });
            }

            public void onFinish() {
                StoreDetailActivity.this.showCircleDialog(false);
            }
        });
    }
}