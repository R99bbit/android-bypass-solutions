package com.nuvent.shareat.widget.view;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnDismissListener;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Rect;
import android.graphics.drawable.AnimationDrawable;
import android.graphics.drawable.BitmapDrawable;
import android.os.Build.VERSION;
import android.os.CountDownTimer;
import android.os.SystemClock;
import android.support.v4.widget.SwipeRefreshLayout;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnTouchListener;
import android.view.ViewConfiguration;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewTreeObserver;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.view.WindowManager;
import android.view.animation.AnimationUtils;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;
import android.widget.Toast;
import com.crashlytics.android.answers.Answers;
import com.crashlytics.android.answers.PurchaseEvent;
import com.facebook.appevents.AppEventsConstants;
import com.google.android.gms.analytics.HitBuilders.TransactionBuilder;
import com.google.gson.JsonParser;
import com.igaworks.adbrix.IgawAdbrix;
import com.igaworks.adbrix.util.CPEConstant;
import com.igaworks.commerce.IgawCommerce;
import com.igaworks.commerce.IgawCommerce.IgawPaymentMethod;
import com.igaworks.commerce.IgawCommerceProductCategoryModel;
import com.igaworks.commerce.IgawCommerceProductModel;
import com.igaworks.interfaces.CommonInterface;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.common.CardRegistActivity;
import com.nuvent.shareat.activity.main.ActionGuideActivity;
import com.nuvent.shareat.activity.main.QuickPayActivity;
import com.nuvent.shareat.activity.main.ReviewActivity;
import com.nuvent.shareat.activity.menu.MyCardActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.DeliveryPaymentApi;
import com.nuvent.shareat.api.PointAvailableAmountApi;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.StoreCouponListApi;
import com.nuvent.shareat.api.card.CardDeleteApi;
import com.nuvent.shareat.api.card.CardListApi;
import com.nuvent.shareat.api.card.RegistMainCardApi;
import com.nuvent.shareat.api.common.PaymentLimitDistanceApi;
import com.nuvent.shareat.dialog.CouponListDialog;
import com.nuvent.shareat.dialog.CouponListDialog.GetCoupon;
import com.nuvent.shareat.dialog.ReviewTypeDialog;
import com.nuvent.shareat.dialog.ReviewTypeDialog.DialogClickListener;
import com.nuvent.shareat.event.BarcodePayingEvent;
import com.nuvent.shareat.event.BarcodeRefreshEvent;
import com.nuvent.shareat.event.CardSlideEvent;
import com.nuvent.shareat.event.CardViewStatusEvent;
import com.nuvent.shareat.event.CouponUpdateEvent;
import com.nuvent.shareat.event.DeliveryActivityFinishEvent;
import com.nuvent.shareat.event.MainActivityFinishEvent;
import com.nuvent.shareat.event.PaySuccessEvent;
import com.nuvent.shareat.event.PayingEvent;
import com.nuvent.shareat.event.RequestAutoBranchEvent;
import com.nuvent.shareat.event.ReviewCountUpdateEvent;
import com.nuvent.shareat.event.SocketSendEvent;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.LoplatManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.manager.socket.SocketInterface;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.CouponDetailModel;
import com.nuvent.shareat.model.PaydisModel;
import com.nuvent.shareat.model.PaydisResultModel;
import com.nuvent.shareat.model.PointDetailModel;
import com.nuvent.shareat.model.PointModel;
import com.nuvent.shareat.model.ReviewTagModel;
import com.nuvent.shareat.model.StoreCouponResultModel;
import com.nuvent.shareat.model.delivery.DeliveryPaymentOrderListModel;
import com.nuvent.shareat.model.delivery.DeliveryPaymentResultModel;
import com.nuvent.shareat.model.external.LoplatConfigModel;
import com.nuvent.shareat.model.payment.PayModel;
import com.nuvent.shareat.model.payment.PayResultModel;
import com.nuvent.shareat.model.payment.PaymentDetailModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.model.user.CardModel;
import com.nuvent.shareat.model.user.CardResultModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.MD5;
import com.nuvent.shareat.util.ShareAtUtil;
import com.nuvent.shareat.util.ShareatLogger;
import com.nuvent.shareat.widget.listener.XSwipeDismissTouchListener;
import com.nuvent.shareat.widget.listener.XSwipeDismissTouchListener.IMainCardViewDismiss;
import de.greenrobot.event.EventBus;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.net.URLDecoder;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Currency;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import net.xenix.android.widget.FontEditTextView;
import net.xenix.android.widget.FontTextView;
import net.xenix.android.widget.LetterSpacingTextView;
import net.xenix.util.FormatUtil;
import net.xenix.util.ImageDisplay;
import net.xenix.util.ProportionalImageView;

public class CardView extends FrameLayout {
    public static final int CARD_STATUS_BARCODE_PAYING = 5;
    public static final int CARD_STATUS_CARD_EMPTY = 1;
    public static final int CARD_STATUS_CARD_PAYING = 6;
    public static final int CARD_STATUS_DELIVERY_PAY_COMPLETE_ = 7;
    public static final int CARD_STATUS_PASSWORD_EMPTY = 4;
    public static final int CARD_STATUS_STORE_EMPTY = 2;
    public static final int CARD_STATUS_STORE_SELECTED = 3;
    public static final String DELIVERY = "DELIVERY";
    static int OPEN_PASSWORD_VIEW = 254;
    public static final int PAY_SUCCESS_CODE = 30;
    static Date sDuplicateEventDefence;
    private final float PAYMENT_LIMIT_DISTANCE = 10000.0f;
    /* access modifiers changed from: private */
    public String adPayTopSchemeUrl = "";
    /* access modifiers changed from: private */
    public String adPayTopSubTitle = "";
    /* access modifiers changed from: private */
    public Map<String, String> deliveryInfoData;
    /* access modifiers changed from: private */
    public int iUsablePoint = 0;
    private boolean isPayingMode;
    private boolean isQuickMode;
    private boolean isSearchQuickMode;
    private OnGlobalLayoutListener layoutListener;
    private OnTouchListener mClearStoreTouchListener = new OnTouchListener() {
        public boolean onTouch(View v, MotionEvent motionEvent) {
            switch (motionEvent.getActionMasked()) {
                case 0:
                    CardView.this.mDownX = motionEvent.getRawX();
                    break;
                case 1:
                    if (CardView.this.mMainCardModel != null && CardView.this.mMainCardModel.getCard_name().equals("Cash Card")) {
                        Toast.makeText(CardView.this.getContext(), "Cash Card \uacb0\uc81c \uc900\ube44\uc911\uc785\ub2c8\ub2e4.", 0).show();
                        break;
                    } else {
                        ShareatApp.getInstance().setQuickPayClick(true);
                        ((BaseActivity) CardView.this.getContext()).startActivityForResult(new Intent(CardView.this.getContext(), QuickPayActivity.class), MainActionBarActivity.QUICKPAYACTIVITY_RESULT_CODE);
                        break;
                    }
                    break;
            }
            return true;
        }
    };
    /* access modifiers changed from: private */
    public ArrayList<CouponDetailModel> mCouponModels = new ArrayList<>();
    private int mCurrentCardStatus = 6;
    /* access modifiers changed from: private */
    public float mDownX;
    private boolean mIsCreateCardView = false;
    private ArrayList<Integer> mKeypadIds;
    private OnClickListener mKeypadListener = new OnClickListener() {
        public void onClick(View v) {
            if (CardView.this.mPassword == null || 4 > CardView.this.mPassword.length()) {
                CardView.this.mPassword = CardView.this.mPassword + ((Button) v).getText().toString();
                CardView.this.setPasswordInputView();
            }
        }
    };
    /* access modifiers changed from: private */
    public CardModel mMainCardModel;
    /* access modifiers changed from: private */
    public CardResultModel mModel;
    private OnClickListener mNpayClick = new OnClickListener() {
        public void onClick(View v) {
            ((BaseActivity) CardView.this.getContext()).showToast(CardView.this.getResources().getString(R.string.n_payment_ready_msg));
        }
    };
    private boolean mOpenPasswordView;
    /* access modifiers changed from: private */
    public String mPassword = "";
    private OnClickListener mPasswordViewClickListener = new OnClickListener() {
        public void onClick(View v) {
            CardView.this.showPasswordView();
        }
    };
    /* access modifiers changed from: private */
    public int mPaymentLimitDistance = 10000;
    private String mPinNumber = "";
    /* access modifiers changed from: private */
    public PopupWindow mPopupWindow;
    /* access modifiers changed from: private */
    public String mRequestPartnerSno = "";
    /* access modifiers changed from: private */
    public String mRequestPassword = "";
    private ResizeLayoutStruct mResizeLayoutStruct;
    /* access modifiers changed from: private */
    public CouponDetailModel mSelectedCouponModel;
    private boolean mStoreClick;
    /* access modifiers changed from: private */
    public StoreModel mStoreModel;
    private SwipeRefreshLayout mSwipeRefresh;
    private CountDownTimer mTimer;
    /* access modifiers changed from: private */
    public XSwipeDismissTouchListener mTouchListener;

    private class ResizeLayoutStruct {
        private double deviceDensity = 0.0d;
        private int screenHeight = 0;
        private int scrollHeight = 0;
        private double standardDensity = 3.0d;
        private int standardHeight = ImageDisplay.MAX_IMAGE_SIZE;

        public ResizeLayoutStruct() {
            try {
                DisplayMetrics outMetrics = new DisplayMetrics();
                ((WindowManager) CardView.this.getContext().getSystemService("window")).getDefaultDisplay().getMetrics(outMetrics);
                boolean bHasMenuKey = ViewConfiguration.get(CardView.this.getContext()).hasPermanentMenuKey();
                boolean bHasBackKey = KeyCharacterMap.deviceHasKey(4);
                if (bHasMenuKey || bHasBackKey) {
                    this.screenHeight = outMetrics.heightPixels;
                } else {
                    this.screenHeight = CardView.this.getRealHeight();
                }
                this.deviceDensity = ((double) outMetrics.densityDpi) / 160.0d;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public int getScreenHeight() {
            return this.screenHeight;
        }

        public double getDeviceDensity() {
            return this.deviceDensity;
        }

        public double getStandardDensity() {
            return this.standardDensity;
        }

        public int getStandardHeight() {
            return this.standardHeight;
        }

        public void setScrollHeight(int scrollHeight2) {
            this.scrollHeight = scrollHeight2;
        }

        public int getScrollHeight() {
            return this.scrollHeight;
        }
    }

    public CardView(Context context) {
        super(context);
        init();
    }

    public CardView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public CardView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void setCardStatus(int value) {
        this.mCurrentCardStatus = value;
    }

    public int getCardStatus() {
        return this.mCurrentCardStatus;
    }

    public boolean isPayingMode() {
        return this.isPayingMode;
    }

    public void setStoreClick(boolean storeClick) {
        this.mStoreClick = storeClick;
    }

    public boolean getStoreClick() {
        return this.mStoreClick;
    }

    public StoreModel getStoreModel() {
        return this.mStoreModel;
    }

    public void startLoading() {
        LetterSpacingTextView lstStoreName = (LetterSpacingTextView) findViewById(R.id.searching_text);
        lstStoreName.setCustomLetterSpacing(-2.3f);
        lstStoreName.setText("\ub9e4\uc7a5 \uac80\uc0c9\uc911\uc785\ub2c8\ub2e4...");
        findViewById(R.id.searching_progress).setVisibility(0);
        findViewById(R.id.noneStoreLayout).setVisibility(8);
        findViewById(R.id.branch_info_layout).setVisibility(0);
        findViewById(R.id.refresh_branch).setVisibility(0);
        findViewById(R.id.auto_branch_search_layout).setVisibility(0);
    }

    public void stopLoading() {
        findViewById(R.id.searching_progress).setVisibility(8);
        findViewById(R.id.auto_branch_search_layout).setVisibility(8);
    }

    public void setAutoBranchSearch(boolean bIsSearch) {
        if (true == bIsSearch) {
            findViewById(R.id.noneStoreLayout).setVisibility(8);
            findViewById(R.id.branch_info_layout).setVisibility(0);
            findViewById(R.id.refresh_branch).setVisibility(0);
        } else {
            findViewById(R.id.noneStoreLayout).setVisibility(0);
            findViewById(R.id.branch_info_layout).setVisibility(8);
            findViewById(R.id.refresh_branch).setVisibility(8);
        }
        findViewById(R.id.auto_branch_search_layout).setVisibility(8);
    }

    public void setDeliveryInfoData(Map<String, String> deliveryInfoData2) {
        this.deliveryInfoData = deliveryInfoData2;
    }

    public Map<String, String> getDeliveryInfoData() {
        return this.deliveryInfoData;
    }

    private boolean isDeliveryCardView() {
        if (this.mStoreModel != null && true == DELIVERY.equals(this.mStoreModel.getPaymentMethodType())) {
            return true;
        }
        return false;
    }

    public void setStoreModel(StoreModel model) {
        this.mStoreModel = model;
        if (this.mStoreModel == null) {
            clearStoreModel();
        }
        setCardStatus(3);
        EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
        if (true == "BARCODE".equals(this.mStoreModel.getPaymentMethodType())) {
            ((TextView) findViewById(R.id.quickPayIconLayout)).setText("\ubc14\ucf54\ub4dc\ub85c\uacb0\uc81c");
            ((TextView) findViewById(R.id.quickPayIconLayout)).setCompoundDrawablesWithIntrinsicBounds(R.drawable.quick_pay_icon_barcode, 0, 0, 0);
            findViewById(R.id.barcodeLabel).setVisibility(0);
            findViewById(R.id.barcodeLabelIcon).setVisibility(0);
        } else if (true == DELIVERY.equals(this.mStoreModel.getPaymentMethodType())) {
            ((TextView) findViewById(R.id.quickPayIconLayout)).setText(true == "QUICK".equals(this.mStoreModel.getMethod()) ? "\ubc30\ub2ec\uc8fc\ubb38" : "\ubc30\uc1a1\uc8fc\ubb38");
            ((TextView) findViewById(R.id.quickPayIconLayout)).setCompoundDrawablesWithIntrinsicBounds(R.drawable.buy_bt_icon, 0, 0, 0);
            findViewById(R.id.barcodeLabel).setVisibility(8);
            findViewById(R.id.barcodeLabelIcon).setVisibility(8);
        } else {
            ((TextView) findViewById(R.id.quickPayIconLayout)).setText("\ubc14\ub85c\uacb0\uc81c");
            ((TextView) findViewById(R.id.quickPayIconLayout)).setCompoundDrawablesWithIntrinsicBounds(R.drawable.quick_pay_icon, 0, 0, 0);
            findViewById(R.id.barcodeLabel).setVisibility(8);
            findViewById(R.id.barcodeLabelIcon).setVisibility(8);
        }
        if (this.mMainCardModel == null || !this.mMainCardModel.getCard_name().equals("Cash Card")) {
            findViewById(R.id.paymentLayout).setOnTouchListener(this.mTouchListener);
        } else {
            findViewById(R.id.paymentLayout).setOnTouchListener(this.mClearStoreTouchListener);
        }
        findViewById(R.id.noneStoreLayout).setVisibility(8);
        findViewById(R.id.branch_info_layout).setVisibility(0);
        findViewById(R.id.auto_branch_info_layout).setVisibility(0);
        if (true == this.isQuickMode) {
            findViewById(R.id.refresh_branch).setVisibility(0);
        } else {
            findViewById(R.id.refresh_branch).setVisibility(4);
        }
        LetterSpacingTextView lstStoreName = (LetterSpacingTextView) findViewById(R.id.storeNameLabel1);
        lstStoreName.setCustomLetterSpacing(-2.3f);
        lstStoreName.setText(model.getPartnerName1());
        LetterSpacingTextView lstPossibleCoupon = (LetterSpacingTextView) findViewById(R.id.possible_coupon_text);
        lstPossibleCoupon.setCustomLetterSpacing(-2.3f);
        lstPossibleCoupon.setText("\uc0ac\uc6a9\uac00\ub2a5 \ucfe0\ud3f0 :  ");
        LetterSpacingTextView lstCountUnit = (LetterSpacingTextView) findViewById(R.id.count_unit_text);
        lstCountUnit.setCustomLetterSpacing(-2.3f);
        lstCountUnit.setText("\uc7a5");
        LetterSpacingTextView lstPayMethod = (LetterSpacingTextView) findViewById(R.id.pay_method);
        lstPayMethod.setCustomLetterSpacing(-2.3f);
        lstPayMethod.setText(" (\uacb0\uc81c\uc2dc \uc120\ud0dd\uac00\ub2a5)");
        LetterSpacingTextView lstUsablePointText = (LetterSpacingTextView) findViewById(R.id.usable_point_text);
        lstUsablePointText.setCustomLetterSpacing(-2.3f);
        lstUsablePointText.setText("\uc0ac\uc6a9\uac00\ub2a5 \uc801\ub9bd\uae08 : ");
        ((EditText) findViewById(R.id.point_tobe_used)).setText(FormatUtil.onDecimalFormat(this.iUsablePoint));
        ((TextView) findViewById(R.id.usable_point_amount)).setText(FormatUtil.onDecimalFormat(this.iUsablePoint));
        LetterSpacingTextView lstPointUnitText = (LetterSpacingTextView) findViewById(R.id.point_unit_text);
        lstPointUnitText.setCustomLetterSpacing(-2.3f);
        lstPointUnitText.setText("\uc6d0");
        LetterSpacingTextView lstPointDesc = (LetterSpacingTextView) findViewById(R.id.point_desc);
        lstPointDesc.setCustomLetterSpacing(-2.3f);
        lstPointDesc.setText(" (\ubbf8\uc0ac\uc6a9)");
        findViewById(R.id.point_tobe_used).setVisibility(8);
        findViewById(R.id.usable_point_text).setVisibility(0);
        findViewById(R.id.usable_point_amount).setVisibility(0);
        findViewById(R.id.check_use_point_text_on).setVisibility(8);
        findViewById(R.id.check_use_point_text_off).setVisibility(0);
        findViewById(R.id.check_use_point_circle).setBackgroundResource(R.drawable.btn_toggle_off);
        findViewById(R.id.usable_saving_point).setVisibility(0);
        ((FontTextView) findViewById(R.id.point_unit_text)).setTextColor(Color.rgb(CPEConstant.DIALOG_REWARD_HEIGHT_PORTRAIT, 183, 195));
        findViewById(R.id.tobe_used_point_layout).setVisibility(8);
        ((EditText) findViewById(R.id.point_tobe_used)).setOnEditorActionListener(new OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                if (v.getId() == R.id.point_tobe_used && actionId == 6) {
                    CardView.this.checkUsablePoint(((EditText) CardView.this.findViewById(R.id.point_tobe_used)).getText().toString());
                }
                return false;
            }
        });
        if (model.getDcRate() > 0) {
            findViewById(R.id.discount_layer).setVisibility(0);
            ((TextView) findViewById(R.id.discount_text)).setText("\uc0c1\uc2dc " + model.getDcRate() + "%\ud61c\ud0dd");
            lstStoreName.setMaxEms(10);
        } else {
            findViewById(R.id.discount_layer).setVisibility(8);
            lstStoreName.setMaxEms(14);
        }
        resizeScrollView();
        requestPaymentLimitDistanceApi();
        requestCouponListApi(this.mStoreModel);
        requestAvailablePointApi();
    }

    private void resizeScrollView() {
        int scrollHeight;
        if (this.mResizeLayoutStruct == null) {
            this.mResizeLayoutStruct = new ResizeLayoutStruct();
            if (true == isDeliveryCardView()) {
                ScrollView s = (ScrollView) findViewById(R.id.cardScrollView);
                s.measure(-1, -2);
                scrollHeight = s.getMeasuredHeight();
            } else {
                scrollHeight = findViewById(R.id.cardScrollView).getHeight();
            }
            this.mResizeLayoutStruct.setScrollHeight(scrollHeight);
            int calcHeight = (int) ((((double) this.mResizeLayoutStruct.getStandardHeight()) * this.mResizeLayoutStruct.getDeviceDensity()) / this.mResizeLayoutStruct.getStandardDensity());
            if (calcHeight > this.mResizeLayoutStruct.getScreenHeight()) {
                LayoutParams layoutParams = findViewById(R.id.cardScrollView).getLayoutParams();
                layoutParams.height = (((scrollHeight - (calcHeight - this.mResizeLayoutStruct.getScreenHeight())) - ((int) dpToPx(getContext(), 5))) - ((int) dpToPx(getContext(), 8))) - ((int) dpToPx(getContext(), 6));
            }
        }
    }

    /* access modifiers changed from: private */
    public int getRealHeight() {
        boolean bHasMenuKey = ViewConfiguration.get(getContext()).hasPermanentMenuKey();
        boolean bHasBackKey = KeyCharacterMap.deviceHasKey(4);
        if (bHasMenuKey || bHasBackKey) {
            return 0;
        }
        Display display = ((WindowManager) getContext().getSystemService("window")).getDefaultDisplay();
        if (VERSION.SDK_INT >= 17) {
            DisplayMetrics realMetrics = new DisplayMetrics();
            display.getRealMetrics(realMetrics);
            int realWidth = realMetrics.widthPixels;
            return realMetrics.heightPixels;
        } else if (VERSION.SDK_INT >= 14) {
            try {
                Method mGetRawH = Display.class.getMethod("getRawHeight", new Class[0]);
                int realWidth2 = ((Integer) Display.class.getMethod("getRawWidth", new Class[0]).invoke(display, new Object[0])).intValue();
                return ((Integer) mGetRawH.invoke(display, new Object[0])).intValue();
            } catch (Exception e) {
                int realWidth3 = display.getWidth();
                return display.getHeight();
            }
        } else {
            int realWidth4 = display.getWidth();
            return display.getHeight();
        }
    }

    public void clearStoreModelForQuickPay() {
        setCardStatus(2);
        EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
        if (this.mCouponModels == null) {
            this.mCouponModels = new ArrayList<>();
        } else {
            this.mCouponModels.clear();
        }
        this.mPinNumber = null;
        this.mStoreModel = null;
        findViewById(R.id.paymentLayout).setOnTouchListener(this.mClearStoreTouchListener);
        findViewById(R.id.noneStoreLayout).setVisibility(0);
        findViewById(R.id.auto_branch_info_layout).setVisibility(8);
        findViewById(R.id.refresh_branch).setVisibility(8);
        ((LetterSpacingTextView) findViewById(R.id.storeNameLabel1)).setText("");
        LetterSpacingTextView lstPossibleCoupon = (LetterSpacingTextView) findViewById(R.id.possible_coupon_text);
        lstPossibleCoupon.setCustomLetterSpacing(-2.3f);
        lstPossibleCoupon.setText("\uc0ac\uc6a9\uac00\ub2a5 \ucfe0\ud3f0 :  ");
        LetterSpacingTextView lstCountUnit = (LetterSpacingTextView) findViewById(R.id.count_unit_text);
        lstCountUnit.setCustomLetterSpacing(-2.3f);
        lstCountUnit.setText("\uc7a5");
        LetterSpacingTextView lstPayMethod = (LetterSpacingTextView) findViewById(R.id.pay_method);
        lstPayMethod.setCustomLetterSpacing(-2.3f);
        lstPayMethod.setText(" (\uacb0\uc81c\uc2dc \uc120\ud0dd\uac00\ub2a5)");
        LetterSpacingTextView lstUsablePointText = (LetterSpacingTextView) findViewById(R.id.usable_point_text);
        lstUsablePointText.setCustomLetterSpacing(-2.3f);
        lstUsablePointText.setText("\uc0ac\uc6a9\uac00\ub2a5 \uc801\ub9bd\uae08 : ");
        ((EditText) findViewById(R.id.point_tobe_used)).setText(FormatUtil.onDecimalFormat(this.iUsablePoint));
        ((TextView) findViewById(R.id.usable_point_amount)).setText(FormatUtil.onDecimalFormat(this.iUsablePoint));
        LetterSpacingTextView lstPointUnitText = (LetterSpacingTextView) findViewById(R.id.point_unit_text);
        lstPointUnitText.setCustomLetterSpacing(-2.3f);
        lstPointUnitText.setText("\uc6d0");
        LetterSpacingTextView lstPointDesc = (LetterSpacingTextView) findViewById(R.id.point_desc);
        lstPointDesc.setCustomLetterSpacing(-2.3f);
        lstPointDesc.setText(" (\ubbf8\uc0ac\uc6a9)");
        findViewById(R.id.point_tobe_used).setVisibility(8);
        findViewById(R.id.usable_point_text).setVisibility(0);
        findViewById(R.id.usable_point_amount).setVisibility(0);
        findViewById(R.id.check_use_point_text_on).setVisibility(8);
        findViewById(R.id.check_use_point_text_off).setVisibility(0);
        findViewById(R.id.check_use_point_circle).setTranslationX(12.0f);
        findViewById(R.id.check_use_point_circle).setBackgroundResource(R.drawable.btn_toggle_off);
        ((FontTextView) findViewById(R.id.point_unit_text)).setTextColor(Color.rgb(CPEConstant.DIALOG_REWARD_HEIGHT_PORTRAIT, 183, 195));
        findViewById(R.id.usable_saving_point).setVisibility(8);
        findViewById(R.id.tobe_used_point_layout).setVisibility(8);
        findViewById(R.id.auto_branch_benefit2).setVisibility(8);
        ((TextView) findViewById(R.id.coupon_count)).setText("");
        ((TextView) findViewById(R.id.quickPayIconLayout)).setText("\ubc14\ub85c\uacb0\uc81c");
        ((TextView) findViewById(R.id.quickPayIconLayout)).setCompoundDrawablesWithIntrinsicBounds(R.drawable.quick_pay_icon, 0, 0, 0);
        findViewById(R.id.barcodeLabel).setVisibility(8);
        findViewById(R.id.barcodeLabelIcon).setVisibility(8);
        setAutoBranchSearch(false);
    }

    public void clearStoreModel() {
        setScrollView(0, false);
        setCardStatus(2);
        EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
        if (this.mCouponModels == null) {
            this.mCouponModels = new ArrayList<>();
        } else {
            this.mCouponModels.clear();
        }
        this.mPinNumber = null;
        this.mStoreModel = null;
        this.mTouchListener.onCancelAnimateView();
        findViewById(R.id.paymentLayout).setOnTouchListener(this.mClearStoreTouchListener);
        findViewById(R.id.noneStoreLayout).setVisibility(0);
        findViewById(R.id.auto_branch_info_layout).setVisibility(8);
        findViewById(R.id.refresh_branch).setVisibility(8);
        ((LetterSpacingTextView) findViewById(R.id.storeNameLabel1)).setText("");
        LetterSpacingTextView lstPossibleCoupon = (LetterSpacingTextView) findViewById(R.id.possible_coupon_text);
        lstPossibleCoupon.setCustomLetterSpacing(-2.3f);
        lstPossibleCoupon.setText("\uc0ac\uc6a9\uac00\ub2a5 \ucfe0\ud3f0 :  ");
        LetterSpacingTextView lstCountUnit = (LetterSpacingTextView) findViewById(R.id.count_unit_text);
        lstCountUnit.setCustomLetterSpacing(-2.3f);
        lstCountUnit.setText("\uc7a5");
        LetterSpacingTextView lstPayMethod = (LetterSpacingTextView) findViewById(R.id.pay_method);
        lstPayMethod.setCustomLetterSpacing(-2.3f);
        lstPayMethod.setText(" (\uacb0\uc81c\uc2dc \uc120\ud0dd\uac00\ub2a5)");
        LetterSpacingTextView lstUsablePointText = (LetterSpacingTextView) findViewById(R.id.usable_point_text);
        lstUsablePointText.setCustomLetterSpacing(-2.3f);
        lstUsablePointText.setText("\uc0ac\uc6a9\uac00\ub2a5 \uc801\ub9bd\uae08 : ");
        ((EditText) findViewById(R.id.point_tobe_used)).setText(FormatUtil.onDecimalFormat(this.iUsablePoint));
        ((TextView) findViewById(R.id.usable_point_amount)).setText(FormatUtil.onDecimalFormat(this.iUsablePoint));
        LetterSpacingTextView lstPointUnitText = (LetterSpacingTextView) findViewById(R.id.point_unit_text);
        lstPointUnitText.setCustomLetterSpacing(-2.3f);
        lstPointUnitText.setText("\uc6d0");
        LetterSpacingTextView lstPointDesc = (LetterSpacingTextView) findViewById(R.id.point_desc);
        lstPointDesc.setCustomLetterSpacing(-2.3f);
        lstPointDesc.setText(" (\ubbf8\uc0ac\uc6a9)");
        findViewById(R.id.point_tobe_used).setVisibility(8);
        findViewById(R.id.usable_point_text).setVisibility(0);
        findViewById(R.id.usable_point_amount).setVisibility(0);
        findViewById(R.id.check_use_point_text_on).setVisibility(8);
        findViewById(R.id.check_use_point_text_off).setVisibility(0);
        findViewById(R.id.check_use_point_circle).setTranslationX(12.0f);
        findViewById(R.id.check_use_point_circle).setBackgroundResource(R.drawable.btn_toggle_off);
        ((FontTextView) findViewById(R.id.point_unit_text)).setTextColor(Color.rgb(CPEConstant.DIALOG_REWARD_HEIGHT_PORTRAIT, 183, 195));
        findViewById(R.id.usable_saving_point).setVisibility(8);
        findViewById(R.id.tobe_used_point_layout).setVisibility(8);
        findViewById(R.id.auto_branch_benefit2).setVisibility(8);
        ((TextView) findViewById(R.id.coupon_count)).setText("");
        ((TextView) findViewById(R.id.quickPayIconLayout)).setText("\ubc14\ub85c\uacb0\uc81c");
        ((TextView) findViewById(R.id.quickPayIconLayout)).setCompoundDrawablesWithIntrinsicBounds(R.drawable.quick_pay_icon, 0, 0, 0);
        findViewById(R.id.barcodeLabel).setVisibility(8);
        findViewById(R.id.barcodeLabelIcon).setVisibility(8);
        setAutoBranchSearch(false);
    }

    public void setQuickMode(boolean isQuickMode2) {
        this.isQuickMode = isQuickMode2;
    }

    public boolean getQuickMode() {
        return this.isQuickMode;
    }

    public void refreshStoreData(StoreModel sm) {
        if (sm != null) {
            this.isQuickMode = true;
            this.isSearchQuickMode = true;
            clearStoreModelForQuickPay();
            setStoreModel(sm);
        }
    }

    public void onEventMainThread(BarcodeRefreshEvent event) {
        if (this.mPinNumber != null && this.mStoreModel != null) {
            if (event.getMethod().equals("successCustomerExtendAuthExpire")) {
                Date date = null;
                try {
                    date = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT).parse(event.getExpireDate());
                } catch (ParseException e) {
                    e.printStackTrace();
                }
                startTimer(date.getTime() - System.currentTimeMillis());
                return;
            }
            ((BaseActivity) getContext()).showDialog("\ubc14\ucf54\ub4dc \uc0c8\ub85c\uace0\uce68\uc5d0 \uc2e4\ud328\ud588\uc2b5\ub2c8\ub2e4.\n\ub2e4\uc2dc \uc2dc\ub3c4\ud574 \uc8fc\uc138\uc694.");
        }
    }

    public void onEventMainThread(BarcodePayingEvent event) {
        setCardStatus(5);
        EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
        String expireDate = event.getExpireDate();
        String paysImageUrl = event.getImageUrl();
        this.mPinNumber = event.getBarcode();
        Date date = null;
        try {
            date = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT).parse(expireDate);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        startTimer(date.getTime() - System.currentTimeMillis());
        String barcodeUrl = String.format(ApiUrl.BARCODE_IMAGE, new Object[]{event.getBarcode()});
        findViewById(R.id.billingTextLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
        findViewById(R.id.billingTextLayout).setVisibility(8);
        findViewById(R.id.payLightIcon).setVisibility(8);
        findViewById(R.id.barcodePayLayout).setVisibility(0);
        ImageDisplay.getInstance().displayImageLoad(barcodeUrl, (ImageView) findViewById(R.id.smallBarcodeImageView));
        ImageDisplay.getInstance().displayImageLoad(paysImageUrl, (ImageView) findViewById(R.id.paysImageView));
        ((MainActionBarActivity) getContext()).setBarcode(barcodeUrl);
    }

    public void onEventMainThread(CouponUpdateEvent event) {
        requestCouponListApi(this.mStoreModel);
    }

    public void onEventMainThread(CardSlideEvent event) {
        GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.quickpayview, (int) R.string.ga_ev_scroll, (int) R.string.quickpayview_scroll_updown);
        if (!event.isOpen()) {
            if (!this.mStoreClick && this.isQuickMode) {
                this.isQuickMode = false;
                this.isSearchQuickMode = false;
                clearStoreModel();
            }
            findViewById(R.id.cardMenuLayout01).setVisibility(8);
            findViewById(R.id.cardMenuLayout02).setVisibility(8);
            findViewById(R.id.cardMenuLayout03).setVisibility(8);
            if (findViewById(R.id.billingResultLayout).getVisibility() == 0) {
                findViewById(R.id.billingResultLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
                findViewById(R.id.billingResultLayout).setVisibility(8);
            } else if (findViewById(R.id.delivery_result_layout).getVisibility() == 0) {
                findViewById(R.id.delivery_result_layout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
                findViewById(R.id.delivery_result_layout).setVisibility(8);
            } else if (findViewById(R.id.paymentFailedLayout).getVisibility() == 0) {
                findViewById(R.id.billingLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
                findViewById(R.id.billingLayout).setVisibility(8);
                findViewById(R.id.paymentPartnerInfo).setVisibility(8);
                ((TextView) findViewById(R.id.paymentStatusLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_LABEL));
                ((TextView) findViewById(R.id.paymentDescriptionLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_DESC_LABEL));
                ((TextView) findViewById(R.id.paymentSubDescriptionLabel)).setText("");
                findViewById(R.id.paymentFailedLayout).setVisibility(8);
                findViewById(R.id.billingCancelButton).setVisibility(0);
                ImageView imageView = (ImageView) findViewById(R.id.billingImageView);
                imageView.setBackgroundResource(R.drawable.loading_animation);
                ((AnimationDrawable) imageView.getBackground()).start();
            }
            this.mTouchListener.onCancelAnimateView();
        }
    }

    public void postPaymentResult(PayResultModel model) {
        boolean z = false;
        if (((MainActionBarActivity) getContext()).isOpenBarcodeView()) {
            ((MainActionBarActivity) getContext()).closeBarcodeView();
        }
        this.isPayingMode = true;
        findViewById(R.id.topButton).setVisibility(8);
        MainActionBarActivity mainActionBarActivity = (MainActionBarActivity) getContext();
        if (!this.isPayingMode) {
            z = true;
        }
        mainActionBarActivity.setCardCloseViewVisiblity(z);
        if (30 == model.group_pay_status) {
            if (!this.isQuickMode) {
                requestCouponListApi(this.mStoreModel);
                requestAvailablePointApi();
            }
            try {
                GAEvent.onGaEventSendParams(new TransactionBuilder().setTransactionId(String.valueOf(model.group_id)).setAffiliation(URLDecoder.decode(model.partner_name1, "UTF-8")).setRevenue((double) model.pay_real).setTax(0.0d).setShipping(0.0d).setCurrencyCode("KRW").build());
                Answers.getInstance().logPurchase(new PurchaseEvent().putItemPrice(BigDecimal.valueOf((long) model.pay_real)).putCurrency(Currency.getInstance("KRW")).putItemName(URLDecoder.decode(model.partner_name1, "UTF-8")).putSuccess(true));
            } catch (Exception e) {
                e.printStackTrace();
            }
            String partner_name = "";
            try {
                partner_name = URLDecoder.decode(model.partner_name1, "UTF-8");
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            IgawAdbrix.purchase(getContext(), Integer.toString((int) System.currentTimeMillis()), IgawCommerceProductModel.create(Integer.toString(model.partner_sno), partner_name, Double.valueOf((double) model.pay_real), Double.valueOf((double) model.getDiscountValue()), Integer.valueOf(1), IgawCommerce.Currency.KR_KRW, IgawCommerceProductCategoryModel.create(""), null), IgawPaymentMethod.MobilePayment);
            if (true != DELIVERY.equals(this.mStoreModel.getPaymentMethodType())) {
                showBillingSuccessView(model);
            }
            EventBus.getDefault().post(new ReviewCountUpdateEvent());
            EventBus.getDefault().post(new PaySuccessEvent(DELIVERY.equals(this.mStoreModel.getPaymentMethodType())));
        } else if (40 <= model.group_pay_status) {
            try {
                GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.error, (int) R.string.ga_payment, (int) R.string.Error_FailPayment);
                Answers.getInstance().logPurchase(new PurchaseEvent().putItemPrice(BigDecimal.valueOf((long) model.pay_real)).putCurrency(Currency.getInstance("KRW")).putItemName(URLDecoder.decode(model.partner_name1, "UTF-8")).putSuccess(false));
            } catch (Exception e3) {
                e3.printStackTrace();
            }
            showBillingFailedView(model);
        }
    }

    public void showBillingView() {
        if (findViewById(R.id.billingLayout).getVisibility() != 0) {
            findViewById(R.id.billingLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_in));
            findViewById(R.id.billingLayout).setVisibility(0);
            ImageView imageView = (ImageView) findViewById(R.id.billingImageView);
            imageView.setBackgroundResource(R.drawable.loading_animation);
            if (this.mStoreModel != null) {
                findViewById(R.id.paymentPartnerInfo).setVisibility(0);
                ((FontTextView) findViewById(R.id.paymentPartnerName)).setText(this.mStoreModel.getPartnerName1());
                ((TextView) findViewById(R.id.paymentStatusLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_LABEL));
            }
            ((AnimationDrawable) imageView.getBackground()).start();
        }
    }

    public void clearBillingView() {
        boolean z;
        this.mSelectedCouponModel = null;
        this.isPayingMode = false;
        findViewById(R.id.topButton).setVisibility(0);
        MainActionBarActivity mainActionBarActivity = (MainActionBarActivity) getContext();
        if (!this.isPayingMode) {
            z = true;
        } else {
            z = false;
        }
        mainActionBarActivity.setCardCloseViewVisiblity(z);
        setCardStatus(this.mStoreModel == null ? 2 : 3);
        EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
        ((TextView) findViewById(R.id.billingDateLabel)).setText("");
        ((TextView) findViewById(R.id.venderNameLabel)).setText("");
        ((TextView) findViewById(R.id.customerNameLabel)).setText("");
        ((TextView) findViewById(R.id.customerPriceLabel)).setText("");
        ((TextView) findViewById(R.id.billingPriceLabel)).setText("");
        ((TextView) findViewById(R.id.totalPriceLabel)).setText("");
        ((TextView) findViewById(R.id.billingPriceNameLabel)).setText("");
        ((TextView) findViewById(R.id.dcPriceNameLabel)).setText("");
        ((TextView) findViewById(R.id.dcPriceLabel)).setText("");
        ((TextView) findViewById(R.id.pointDcLabel)).setText("");
        ((TextView) findViewById(R.id.couponDcLabel)).setText("");
        findViewById(R.id.pointLayout).setVisibility(8);
        findViewById(R.id.couponLayout).setVisibility(8);
        ((TextView) findViewById(R.id.paymentStatusLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_LABEL));
        ((TextView) findViewById(R.id.paymentDescriptionLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_DESC_LABEL));
        ((TextView) findViewById(R.id.paymentSubDescriptionLabel)).setText("");
        findViewById(R.id.payLightIcon).setVisibility(0);
        findViewById(R.id.barcodePayLayout).setVisibility(8);
        findViewById(R.id.billingTextLayout).setVisibility(0);
        findViewById(R.id.paymentFailedLayout).setVisibility(8);
        findViewById(R.id.billingCancelButton).setVisibility(0);
        findViewById(R.id.paymentPartnerInfo).setVisibility(8);
        ImageView imageView = (ImageView) findViewById(R.id.billingImageView);
        imageView.setBackgroundResource(R.drawable.loading_animation);
        ((AnimationDrawable) imageView.getBackground()).start();
        findViewById(R.id.billingResultLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
        findViewById(R.id.billingResultLayout).setVisibility(8);
        findViewById(R.id.delivery_result_layout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
        findViewById(R.id.delivery_result_layout).setVisibility(8);
        ((MainActionBarActivity) getContext()).closeCardView();
    }

    private void startTimer(long diffTime) {
        if (0 >= diffTime) {
        }
        findViewById(R.id.refreshBarcodeSmall).setVisibility(8);
        findViewById(R.id.dimBarcodeLayout).setVisibility(4);
        ((TextView) findViewById(R.id.barcodeTimerLabel)).setText("");
        ((TextView) findViewById(R.id.barcodeTitleLabel)).setText("\ubc14\ucf54\ub4dc\uacb0\uc81c \ub9e4\uc7a5\uc785\ub2c8\ub2e4.");
        ((TextView) findViewById(R.id.barcodeSubTitleLabel)).setText("\uce74\uc6b4\ud130\uc5d0 \ubc14\ucf54\ub4dc\ub97c \uc81c\uc2dc\ud574\uc8fc\uc138\uc694.(1\ud68c\ud55c\ub3c4 50\ub9cc\uc6d0)");
        final SimpleDateFormat dateFormat = new SimpleDateFormat("mm:ss");
        if (this.mTimer != null) {
            this.mTimer.cancel();
        }
        this.mTimer = new CountDownTimer(diffTime, 1000) {
            public void onTick(long millisUntilFinished) {
                String timerText = dateFormat.format(new Date(millisUntilFinished));
                ((TextView) CardView.this.findViewById(R.id.barcodeTimerLabel)).setText(timerText);
                ((MainActionBarActivity) CardView.this.getContext()).setBarcodeTimerLabel(timerText);
            }

            public void onFinish() {
                ((TextView) CardView.this.findViewById(R.id.barcodeTitleLabel)).setText("\uc720\ud6a8\uc2dc\uac04 \ub9cc\ub8cc");
                ((TextView) CardView.this.findViewById(R.id.barcodeSubTitleLabel)).setText("\uc0c8\ub85c\uace0\uce68\ud558\uc5ec \ubc14\ucf54\ub4dc\ub97c \ub2e4\uc2dc \uc0dd\uc131\ud574\uc8fc\uc138\uc694.");
                ((TextView) CardView.this.findViewById(R.id.barcodeTimerLabel)).setText("00:00");
                ((MainActionBarActivity) CardView.this.getContext()).setBarcodeTimerLabel("00:00");
                ((MainActionBarActivity) CardView.this.getContext()).closeBarcodeView();
                CardView.this.findViewById(R.id.dimBarcodeLayout).setVisibility(0);
                CardView.this.findViewById(R.id.refreshBarcodeSmall).setVisibility(0);
                CardView.this.findViewById(R.id.dimBarcodeLayout).setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        CardView.this.requestExpireBarcode();
                    }
                });
                CardView.this.findViewById(R.id.refreshBarcodeSmall).setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        CardView.this.requestExpireBarcode();
                    }
                });
            }
        };
        this.mTimer.start();
    }

    /* access modifiers changed from: private */
    public void requestExpireBarcode() {
        GAEvent.onGaEvent(getResources().getString(R.string.ga_paying), getResources().getString(R.string.ga_barcode_pay), getResources().getString(R.string.ga_barcode_refresh));
        try {
            Map<String, String> dataMap = new HashMap<>();
            dataMap.put("partner_sno", this.mRequestPartnerSno);
            dataMap.put("pin_no", this.mPinNumber);
            EventBus.getDefault().post(new SocketSendEvent(2, SocketInterface.METHOD_CUSTOMER_EXTEND_AUTH_EXPIRE, dataMap));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void resizeSuccessView(boolean hasAdvertise) {
        boolean bHasMenuKey = ViewConfiguration.get((BaseActivity) getContext()).hasPermanentMenuKey();
        boolean bHasBackKey = KeyCharacterMap.deviceHasKey(4);
        LinearLayout lCustomerInfoLabel = (LinearLayout) findViewById(R.id.customerInfoLabel);
        LinearLayout.LayoutParams lpCustomerInfoLabel = (LinearLayout.LayoutParams) lCustomerInfoLabel.getLayoutParams();
        LinearLayout lCustomerInfoLabelInner = (LinearLayout) findViewById(R.id.customerInfoLabelInner);
        LinearLayout.LayoutParams lpCustomerInfoLabelInner = (LinearLayout.LayoutParams) lCustomerInfoLabelInner.getLayoutParams();
        LinearLayout lBillingResultInner = (LinearLayout) findViewById(R.id.billingResultLayoutInner);
        LinearLayout.LayoutParams lpBillingResultInner = (LinearLayout.LayoutParams) lBillingResultInner.getLayoutParams();
        if (lpBillingResultInner != null) {
            if (hasAdvertise) {
                lpBillingResultInner.topMargin = 17;
                lpCustomerInfoLabel.height = 266;
                lpCustomerInfoLabelInner.topMargin = 63;
                if (!bHasMenuKey && !bHasBackKey) {
                    lpCustomerInfoLabel.height = 116;
                }
            } else {
                lpBillingResultInner.topMargin = 120;
                lpCustomerInfoLabel.height = 420;
                lpCustomerInfoLabelInner.topMargin = 90;
                if (!bHasMenuKey && !bHasBackKey) {
                    lpCustomerInfoLabel.height = 270;
                }
            }
        }
        lBillingResultInner.setLayoutParams(lpBillingResultInner);
        lCustomerInfoLabel.setLayoutParams(lpCustomerInfoLabel);
        lCustomerInfoLabelInner.setLayoutParams(lpCustomerInfoLabelInner);
    }

    /* access modifiers changed from: private */
    public void setBanner(PayResultModel model) {
        boolean hasAdvertise = false;
        LinearLayout adPayResultTopLayout = (LinearLayout) findViewById(R.id.advertise_pay_result_top);
        if (model.ad_list == null || model.getAdvertiseListLength() <= 0) {
            adPayResultTopLayout.setVisibility(8);
            adPayResultTopLayout.setVisibility(8);
        } else if (adPayResultTopLayout != null) {
            adPayResultTopLayout.removeAllViews();
            ProportionalImageView adPayResultTop = new ProportionalImageView(getContext());
            adPayResultTop.setLayoutParams(new FrameLayout.LayoutParams(-1, -2));
            adPayResultTop.setAdjustViewBounds(true);
            ImageDisplay.getInstance().displayImageLoad(model.getAdvertiseImgUrl(0), adPayResultTop);
            adPayResultTopLayout.addView(adPayResultTop);
            this.adPayTopSchemeUrl = model.getAdvertiseSchemeUrl(0);
            this.adPayTopSubTitle = model.getAdvertiseSubTitle(0);
            adPayResultTop.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    try {
                        if (CardView.this.adPayTopSubTitle == null) {
                            CardView.this.adPayTopSubTitle = "";
                        } else {
                            try {
                                CardView.this.adPayTopSubTitle = URLDecoder.decode(CardView.this.adPayTopSubTitle, "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                e.printStackTrace();
                            }
                        }
                        GAEvent.onGaEvent(CardView.this.getResources().getString(R.string.ga_payment_result), CardView.this.getResources().getString(R.string.ga_ev_click), new StringBuilder().append(CardView.this.getResources().getString(R.string.ga_ad_banner)).append(CardView.this.adPayTopSubTitle).toString() == null ? "" : EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + CardView.this.adPayTopSubTitle);
                        CustomSchemeManager.postSchemeAction(CardView.this.getContext(), CardView.this.adPayTopSchemeUrl);
                    } catch (NullPointerException e2) {
                        e2.printStackTrace();
                    }
                }
            });
            hasAdvertise = true;
        }
        resizeSuccessView(hasAdvertise);
    }

    /* access modifiers changed from: private */
    public void deliveryBillingSuccessView(String imgPath, PayResultModel payResultModel, DeliveryPaymentOrderListModel model) {
        GAEvent.onGAScreenView((BaseActivity) getContext(), R.string.ga_pay_delivery_result);
        showBillingView();
        findViewById(R.id.delivery_result_layout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_in));
        findViewById(R.id.delivery_result_layout).setVisibility(0);
        findViewById(R.id.billingLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
        findViewById(R.id.billingLayout).setVisibility(8);
        ImageView imageView = (ImageView) findViewById(R.id.billingImageView);
        imageView.setBackgroundResource(R.drawable.loading_animation);
        AnimationDrawable frameAnimation = (AnimationDrawable) imageView.getBackground();
        frameAnimation.stop();
        frameAnimation.selectDrawable(0);
        ImageView objectImage = (ImageView) findViewById(R.id.object_image);
        TextView orderObjectName = (TextView) findViewById(R.id.order_object_name);
        TextView freeDelivery = (TextView) findViewById(R.id.order_object_no_charge);
        TextView orderCountText = (TextView) findViewById(R.id.order_count_text);
        TextView originalPrice = (TextView) findViewById(R.id.order_object_original_price);
        originalPrice.setPaintFlags(originalPrice.getPaintFlags() | 16);
        TextView salePrice = (TextView) findViewById(R.id.order_object_sale_price);
        TextView receiverName = (TextView) findViewById(R.id.receiver_name);
        TextView receiverPhoneNumber = (TextView) findViewById(R.id.receiver_phone_number);
        TextView fullAddress = (TextView) findViewById(R.id.address);
        TextView requestMessage = (TextView) findViewById(R.id.request_message);
        PayModel userPayModel = null;
        String userSno = ShareatApp.getInstance().getUserNum();
        for (int i = 0; i < payResultModel.user_list.length; i++) {
            if (userSno.equals(String.valueOf(payResultModel.user_list[i].user_sno))) {
                userPayModel = payResultModel.user_list[i];
            }
        }
        if (userPayModel == null) {
            PayModel userPayModel2 = payResultModel.user_list[0];
        }
        if (true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(this.mStoreModel.getMethod())) {
            freeDelivery.setText("\ubc30\ub2ec\uc0c1\ud488");
        } else {
            freeDelivery.setText("\ubc30\uc1a1\uc0c1\ud488");
        }
        salePrice.setText(FormatUtil.onDecimalFormat(String.valueOf(model.getItemPrice() * model.getCount())));
        try {
            orderObjectName.setText(URLDecoder.decode(model.getMenuName(), "UTF-8"));
            receiverName.setText("\uc218\ub839\uc778 : " + URLDecoder.decode(model.getReceiveName(), "UTF-8"));
            receiverPhoneNumber.setText(model.getReceivePhone());
            String realZipCode = "";
            if (true != model.getZipCode().isEmpty()) {
                realZipCode = "(" + model.getZipCode() + ") ";
            }
            fullAddress.setText(URLDecoder.decode(realZipCode + model.getAddress() + " " + model.getAddressRest(), "UTF-8"));
            requestMessage.setText(URLDecoder.decode(model.getRequestMessage(), "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        originalPrice.setText(FormatUtil.onDecimalFormat(String.valueOf(Integer.valueOf(model.getMenuOriginPrice()).intValue() * model.getCount())));
        orderCountText.setText("\uc218\ub7c9 : " + String.valueOf(model.getCount()) + "\uac1c");
        ImageDisplay.getInstance().displayImageLoad(imgPath, objectImage);
    }

    private void showBillingSuccessView(PayResultModel model) {
        GAEvent.onGAScreenView((BaseActivity) getContext(), R.string.ga_pay_result);
        showBillingView();
        findViewById(R.id.billingResultLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_in));
        findViewById(R.id.billingResultLayout).setVisibility(0);
        findViewById(R.id.billingLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
        findViewById(R.id.billingLayout).setVisibility(8);
        ImageView imageView = (ImageView) findViewById(R.id.billingImageView);
        imageView.setBackgroundResource(R.drawable.loading_animation);
        AnimationDrawable framAnimation = (AnimationDrawable) imageView.getBackground();
        framAnimation.stop();
        framAnimation.selectDrawable(0);
        PayModel userPayModel = null;
        String userSno = ShareatApp.getInstance().getUserNum();
        for (int i = 0; i < model.user_list.length; i++) {
            if (userSno.equals(String.valueOf(model.user_list[i].user_sno))) {
                userPayModel = model.user_list[i];
            }
        }
        if (userPayModel == null) {
            userPayModel = model.user_list[0];
        }
        boolean hasAdvertise = false;
        LinearLayout adPayResultTopLayout = (LinearLayout) findViewById(R.id.advertise_pay_result_top);
        if (model.ad_list == null || model.getAdvertiseListLength() <= 0) {
            adPayResultTopLayout.setVisibility(8);
        } else if (adPayResultTopLayout != null) {
            adPayResultTopLayout.removeAllViews();
            ProportionalImageView adPayResultTop = new ProportionalImageView(getContext());
            adPayResultTop.setLayoutParams(new FrameLayout.LayoutParams(-1, -2));
            adPayResultTop.setAdjustViewBounds(true);
            ImageDisplay.getInstance().displayImageLoad(model.getAdvertiseImgUrl(0), adPayResultTop);
            adPayResultTopLayout.addView(adPayResultTop);
            this.adPayTopSchemeUrl = model.getAdvertiseSchemeUrl(0);
            this.adPayTopSubTitle = model.getAdvertiseSubTitle(0);
            adPayResultTop.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    try {
                        if (CardView.this.adPayTopSubTitle == null) {
                            CardView.this.adPayTopSubTitle = "";
                        } else {
                            try {
                                CardView.this.adPayTopSubTitle = URLDecoder.decode(CardView.this.adPayTopSubTitle, "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                e.printStackTrace();
                            }
                        }
                        GAEvent.onGaEvent(CardView.this.getResources().getString(R.string.ga_payment_result), CardView.this.getResources().getString(R.string.ga_ev_click), new StringBuilder().append(CardView.this.getResources().getString(R.string.ga_ad_banner)).append(CardView.this.adPayTopSubTitle).toString() == null ? "" : EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + CardView.this.adPayTopSubTitle);
                        CustomSchemeManager.postSchemeAction(CardView.this.getContext(), CardView.this.adPayTopSchemeUrl);
                    } catch (NullPointerException e2) {
                        e2.printStackTrace();
                    }
                }
            });
            hasAdvertise = true;
        }
        resizeSuccessView(hasAdvertise);
        ((TextView) findViewById(R.id.billingDateLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAY_DATE_LABEL) + " " + model.pay_date_text);
        ((TextView) findViewById(R.id.venderNameLabel)).setText(getContext().getString(R.string.CARD_VIEW_VENDOR_NAME_LABEL) + " " + URLDecoder.decode(model.partner_name1));
        ((TextView) findViewById(R.id.customerNameLabel)).setText(SessionManager.getInstance().getUserModel().getUserName());
        ((TextView) findViewById(R.id.customerPriceLabel)).setText(FormatUtil.onDecimalFormat(userPayModel.pay_amt) + "\uc6d0");
        ((TextView) findViewById(R.id.billingPriceLabel)).setText(FormatUtil.onDecimalFormat(model.pay_total) + "\uc6d0");
        ((TextView) findViewById(R.id.totalPriceLabel)).setText(FormatUtil.onDecimalFormat(userPayModel.pay_amt) + "\uc6d0");
        ((TextView) findViewById(R.id.billingPriceNameLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAY_PRICE_LABEL) + String.format(" (%s\uc778)", new Object[]{FormatUtil.onDecimalFormat(model.user_cnt)}));
        ((TextView) findViewById(R.id.dcPriceNameLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAY_DC_PRICE_LABEL) + " (" + model.dc_rate + "%\ud560\uc778)");
        ((TextView) findViewById(R.id.dcPriceLabel)).setText(FormatUtil.onDecimalFormat(-(model.pay_total - model.pay_real)) + "\uc6d0");
        if (!userPayModel.point_amt.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            findViewById(R.id.pointLayout).setVisibility(0);
            ((TextView) findViewById(R.id.pointDcLabel)).setText("-" + FormatUtil.onDecimalFormat(userPayModel.point_amt) + "\uc6d0");
        }
        if (!userPayModel.coupon_amt.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            findViewById(R.id.couponLayout).setVisibility(0);
            ((TextView) findViewById(R.id.couponDcLabel)).setText("-" + FormatUtil.onDecimalFormat(userPayModel.coupon_amt) + "\uc6d0");
        }
    }

    private void showBillingFailedView(PayResultModel model) {
        showBillingView();
        if (findViewById(R.id.barcodePayLayout).getVisibility() == 0) {
            findViewById(R.id.billingTextLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_in));
            findViewById(R.id.billingTextLayout).setVisibility(0);
            findViewById(R.id.barcodePayLayout).setVisibility(8);
            findViewById(R.id.payLightIcon).setVisibility(0);
        }
        if (62 == model.group_pay_status) {
            ((TextView) findViewById(R.id.paymentDescriptionLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_CANCEL_DESC_LABEL));
            try {
                ((TextView) findViewById(R.id.paymentStatusLabel)).setText(URLDecoder.decode(model.group_pay_status_text, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            ((TextView) findViewById(R.id.paymentSubDescriptionLabel)).setText("(\uacb0\uc81c\ucde8\uc18c : \uce74\uc6b4\ud130\ucde8\uc18c)");
        } else {
            ((TextView) findViewById(R.id.paymentDescriptionLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_FAILED_DESC_LABEL));
            ((TextView) findViewById(R.id.paymentStatusLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_FAILED_LABEL));
            ((TextView) findViewById(R.id.paymentSubDescriptionLabel)).setText("(\uacb0\uc81c\uc2e4\ud328 : " + URLDecoder.decode((model.user_list[0].cancel_result == null || URLDecoder.decode(model.user_list[0].cancel_result).equals("null")) ? "" : model.user_list[0].cancel_result) + ")");
        }
        if (59 == model.group_pay_status) {
            ((BaseActivity) getContext()).showDialog((model.user_list[0].cancel_result == null || URLDecoder.decode(model.user_list[0].cancel_result).equals("null")) ? "" : model.user_list[0].cancel_result);
        }
        ((ImageView) findViewById(R.id.billingImageView)).setBackgroundResource(R.drawable.billing_failed_icon);
        findViewById(R.id.paymentFailedLayout).setVisibility(0);
        findViewById(R.id.billingCancelButton).setVisibility(8);
    }

    /* access modifiers changed from: private */
    public void showDeliveryBillingFailedView(int group_pay_status, String errMsg) {
        showBillingView();
        if (findViewById(R.id.barcodePayLayout).getVisibility() == 0) {
            findViewById(R.id.billingTextLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_in));
            findViewById(R.id.billingTextLayout).setVisibility(0);
            findViewById(R.id.barcodePayLayout).setVisibility(8);
            findViewById(R.id.payLightIcon).setVisibility(0);
        }
        if (62 == group_pay_status) {
            ((TextView) findViewById(R.id.paymentDescriptionLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_CANCEL_DESC_LABEL));
            try {
                ((TextView) findViewById(R.id.paymentStatusLabel)).setText(URLDecoder.decode(errMsg, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            ((TextView) findViewById(R.id.paymentSubDescriptionLabel)).setText("(\uacb0\uc81c\ucde8\uc18c : \uce74\uc6b4\ud130\ucde8\uc18c)");
        } else {
            ((TextView) findViewById(R.id.paymentDescriptionLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_FAILED_DESC_LABEL));
            ((TextView) findViewById(R.id.paymentStatusLabel)).setText(getContext().getString(R.string.CARD_VIEW_PAYING_FAILED_LABEL));
            try {
                ((TextView) findViewById(R.id.paymentSubDescriptionLabel)).setText("(\uacb0\uc81c\uc2e4\ud328 : " + URLDecoder.decode(errMsg, "UTF-8") + ")");
            } catch (UnsupportedEncodingException e2) {
                e2.printStackTrace();
            }
        }
        if (59 == group_pay_status) {
            ((BaseActivity) getContext()).showDialog(errMsg);
        }
        ((ImageView) findViewById(R.id.billingImageView)).setBackgroundResource(R.drawable.billing_failed_icon);
        findViewById(R.id.paymentFailedLayout).setVisibility(0);
        findViewById(R.id.billingCancelButton).setVisibility(8);
    }

    private void showCouponListDialog() {
        ShareatLogger.writeLog("[DEBUG] Show Coupon Dialog");
        this.mSelectedCouponModel = null;
        CouponListDialog dialog = new CouponListDialog(getContext(), this.mCouponModels);
        dialog.setOnSelectedCoupon(new GetCoupon() {
            public void onSelectCoupon(CouponDetailModel model) {
                CardView.this.mSelectedCouponModel = model;
                CardView.this.findViewById(R.id.auto_branch_benefit2).setVisibility(8);
                ((TextView) CardView.this.findViewById(R.id.coupon_count)).setText("");
                CardView.this.findViewById(R.id.auto_branch_benefit_complet).setVisibility(0);
                LetterSpacingTextView lstAcceptCouponInfo = (LetterSpacingTextView) CardView.this.findViewById(R.id.accept_coupon_info);
                lstAcceptCouponInfo.setCustomLetterSpacing(-2.3f);
                lstAcceptCouponInfo.setText("\ucfe0\ud3f0\uc801\uc6a9 \uc0ac\ud56d : ");
                LetterSpacingTextView lstCouponName = (LetterSpacingTextView) CardView.this.findViewById(R.id.coupon_name);
                lstCouponName.setCustomLetterSpacing(-2.3f);
                if (CardView.this.mSelectedCouponModel.getCoupon_type().equals("10")) {
                    lstCouponName.setText(FormatUtil.onDecimalFormat(CardView.this.mSelectedCouponModel.getDiscount_value()) + "\uc6d0 \ud560\uc778 \ucfe0\ud3f0 \uc801\uc6a9");
                } else if (CardView.this.mSelectedCouponModel.getCoupon_type().equals("20")) {
                    lstCouponName.setText(CardView.this.mSelectedCouponModel.getDiscount_value() + "% \ud560\uc778 \ucfe0\ud3f0 \uc801\uc6a9");
                }
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.quickpayview, (int) R.string.apply_coupon, (int) R.string.apply_coupon);
                if (!AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
                    AppSettingManager.getInstance().setCardviewActionGuideStatus(true);
                    ((BaseActivity) CardView.this.getContext()).animActivity(new Intent((BaseActivity) CardView.this.getContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_password"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                }
            }

            public void onNotUsed() {
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.quickpayview, (int) R.string.apply_coupon, (int) R.string.not_used_coupon);
                if (!AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
                    AppSettingManager.getInstance().setCardviewActionGuideStatus(true);
                    ((BaseActivity) CardView.this.getContext()).animActivity(new Intent((BaseActivity) CardView.this.getContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_password"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                }
            }
        });
        dialog.setOnDismissListener(new OnDismissListener() {
            public void onDismiss(DialogInterface dialog) {
                if (!AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
                    AppSettingManager.getInstance().setCardviewActionGuideStatus(true);
                    ((BaseActivity) CardView.this.getContext()).animActivity(new Intent((BaseActivity) CardView.this.getContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_password"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                }
            }
        });
        dialog.show();
    }

    private void requestCouponListApi(StoreModel sm) {
        if (sm != null) {
            StoreCouponListApi request = new StoreCouponListApi(getContext());
            request.addParam("partner_sno", sm.getPartnerSno());
            request.request(new RequestHandler() {
                public void onResult(Object result) {
                    StoreCouponResultModel model = (StoreCouponResultModel) result;
                    if (!model.getResult().equals("Y") || model.getResult_list().size() <= 0) {
                        CardView.this.findViewById(R.id.auto_branch_benefit_complet).setVisibility(8);
                        CardView.this.findViewById(R.id.auto_branch_benefit2).setVisibility(0);
                        ((TextView) CardView.this.findViewById(R.id.coupon_count)).setText(AppEventsConstants.EVENT_PARAM_VALUE_NO);
                        return;
                    }
                    CardView.this.mCouponModels = model.getResult_list();
                    if (CardView.this.mCouponModels == null || CardView.this.mCouponModels.size() <= 0) {
                        CardView.this.findViewById(R.id.auto_branch_benefit2).setVisibility(8);
                        ((TextView) CardView.this.findViewById(R.id.coupon_count)).setText("");
                        return;
                    }
                    CardView.this.findViewById(R.id.auto_branch_benefit_complet).setVisibility(8);
                    CardView.this.findViewById(R.id.auto_branch_benefit2).setVisibility(0);
                    ((TextView) CardView.this.findViewById(R.id.coupon_count)).setText(String.valueOf(CardView.this.mCouponModels.size()));
                }

                public void onFinish() {
                    super.onFinish();
                }
            });
        }
    }

    private void requestAvailablePointApi() {
        new PointAvailableAmountApi(getContext()).request(new RequestHandler() {
            public void onResult(Object result) {
                PointModel model = (PointModel) result;
                if (!model.getResult().equals("Y") || model.getResult_list().size() <= 0) {
                    ((TextView) CardView.this.findViewById(R.id.usable_point_amount)).setText(AppEventsConstants.EVENT_PARAM_VALUE_NO);
                    ((EditText) CardView.this.findViewById(R.id.point_tobe_used)).setText(AppEventsConstants.EVENT_PARAM_VALUE_NO);
                    CardView.this.iUsablePoint = 0;
                    return;
                }
                PointDetailModel availablePointModel = model.getResult_list().get(0);
                ((TextView) CardView.this.findViewById(R.id.usable_point_amount)).setText(FormatUtil.onDecimalFormat(availablePointModel.getPoint_value()));
                ((EditText) CardView.this.findViewById(R.id.point_tobe_used)).setText(FormatUtil.onDecimalFormat(availablePointModel.getPoint_value()));
                CardView.this.iUsablePoint = availablePointModel.getPoint_value();
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }

    public void setOpenPasswordView(boolean bOpen) {
        this.mOpenPasswordView = bOpen;
    }

    private float dpToPx(Context context, int dp) {
        return ((float) dp) * (((float) context.getResources().getDisplayMetrics().densityDpi) / 160.0f);
    }

    /* access modifiers changed from: private */
    public void postPaying() {
        boolean isChecked = true;
        setCardStatus(4);
        EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
        ShareatApp.getInstance().setPayFlowing(true);
        if (this.mCouponModels != null && this.mCouponModels.size() > 0) {
            showCouponListDialog();
        } else if (!AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
            ((BaseActivity) getContext()).animActivity(new Intent((BaseActivity) getContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_password"), R.anim.fade_in_activity, R.anim.fade_out_activity);
        }
        shuffleKeypad();
        findViewById(R.id.bottomCardView).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
        findViewById(R.id.bottomCardView).setVisibility(8);
        findViewById(R.id.paymentStateIcon).setBackgroundResource(R.drawable.key_bottom_round_g);
        setPayNViewStatus(false);
        if (findViewById(R.id.check_use_point_button) != null) {
            if (((int) findViewById(R.id.check_use_point_circle).getTranslationX()) >= 0) {
                isChecked = false;
            }
            if (isChecked) {
                String inputPoint = ((EditText) findViewById(R.id.point_tobe_used)).getText().toString();
                if (inputPoint == null || "".equals(inputPoint)) {
                    inputPoint = AppEventsConstants.EVENT_PARAM_VALUE_NO;
                }
                String inputPoint2 = inputPoint.replaceAll(",", "");
                ((FontTextView) findViewById(R.id.tobe_used_point_amount)).setText(FormatUtil.onDecimalFormat(inputPoint2));
                if (!checkUsablePoint(inputPoint2)) {
                    ((FontTextView) findViewById(R.id.tobe_used_point_amount)).setText(FormatUtil.onDecimalFormat(this.iUsablePoint));
                }
            } else {
                ((FontTextView) findViewById(R.id.tobe_used_point_amount)).setText(AppEventsConstants.EVENT_PARAM_VALUE_NO);
            }
            hideKeyboard();
            findViewById(R.id.usable_saving_point).setVisibility(8);
            findViewById(R.id.tobe_used_point_layout).setVisibility(0);
        }
    }

    public void showPasswordView() {
        findViewById(R.id.paymentLayout).dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis() + 100, OPEN_PASSWORD_VIEW, 0.0f, 0.0f, 0));
    }

    /* access modifiers changed from: private */
    public void setOpenCardFrame() {
        ((BaseActivity) getContext()).updateSocketUrl();
        if (ShareatApp.getInstance().getGpsManager() == null) {
            ((BaseActivity) getContext()).registGpsManager();
        }
        if (!ShareatApp.getInstance().getGpsManager().isGetLocation()) {
            ((BaseActivity) getContext()).showConfirmDialog(String.format(getResources().getString(R.string.QUICK_PAYMENT_ALERT), new Object[]{this.mStoreModel.getPartnerName1()}), (Runnable) new Runnable() {
                public void run() {
                    CardView.this.postPaying();
                }
            }, (Runnable) new Runnable() {
                public void run() {
                    CardView.this.mTouchListener.onCancelAnimateView();
                }
            });
        } else if (this.mStoreModel.getDistance().isEmpty()) {
            this.mTouchListener.onCancelAnimateView();
        } else if (Integer.parseInt(this.mStoreModel.getDistance()) < this.mPaymentLimitDistance) {
            postPaying();
        } else {
            GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.error, (int) R.string.ga_payment, (int) R.string.ga_gps_error);
            this.mTouchListener.onCancelAnimateView();
            ((BaseActivity) getContext()).showDialog(getContext().getResources().getString(R.string.PAYMENT_DISTANCE_ERROR));
        }
    }

    /* access modifiers changed from: private */
    public void setCloseCardFrame() {
        int i = this.mStoreModel == null ? 2 : this.isPayingMode ? 6 : 3;
        setCardStatus(i);
        EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
        findViewById(R.id.auto_branch_benefit2).setVisibility(0);
        ((TextView) findViewById(R.id.coupon_count)).setText(this.mCouponModels == null ? AppEventsConstants.EVENT_PARAM_VALUE_NO : String.valueOf(this.mCouponModels.size()));
        findViewById(R.id.auto_branch_benefit_complet).setVisibility(8);
        findViewById(R.id.passwordInputLabel01).setSelected(false);
        findViewById(R.id.passwordInputLabel02).setSelected(false);
        findViewById(R.id.passwordInputLabel03).setSelected(false);
        findViewById(R.id.passwordInputLabel04).setSelected(false);
        this.mPassword = "";
        if (findViewById(R.id.bottomCardView).getVisibility() != 0) {
            findViewById(R.id.bottomCardView).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_in));
            findViewById(R.id.bottomCardView).setVisibility(0);
        }
        findViewById(R.id.paymentStateIcon).setBackgroundResource(R.drawable.key_bottom_round);
        setPayNViewStatus(true);
        findViewById(R.id.usable_saving_point).setVisibility(0);
        findViewById(R.id.tobe_used_point_layout).setVisibility(8);
    }

    /* access modifiers changed from: protected */
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        EventBus.getDefault().unregister(this);
    }

    private void setPayNViewStatus(boolean isEnable) {
    }

    public void setScrollView(int scrollY, boolean enable) {
        try {
            findViewById(R.id.cardScrollView).setScrollY(scrollY);
            findViewById(R.id.cardScrollView).setVerticalScrollBarEnabled(enable);
        } catch (Exception e) {
        }
    }

    private void init() {
        View.inflate(getContext(), R.layout.view_card, this);
        if (!this.mIsCreateCardView && !EventBus.getDefault().isRegistered(this)) {
            EventBus.getDefault().register(this);
            this.mIsCreateCardView = true;
        }
        this.mKeypadIds = new ArrayList<>();
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey01));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey02));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey03));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey04));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey05));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey06));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey07));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey08));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey09));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey10));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey11));
        this.mKeypadIds.add(Integer.valueOf(R.id.randomKey12));
        shuffleKeypad();
        boolean hasBackKey = KeyCharacterMap.deviceHasKey(4);
        boolean hasHomeKey = KeyCharacterMap.deviceHasKey(3);
        if (!hasBackKey && !hasHomeKey) {
            findViewById(R.id.avatarLineView).setVisibility(8);
            findViewById(R.id.avatarLayout).setVisibility(8);
            LinearLayout lToBeUsedPoint = (LinearLayout) findViewById(R.id.tobe_used_point_layout);
            LinearLayout.LayoutParams lpToBeUsedPoint = (LinearLayout.LayoutParams) lToBeUsedPoint.getLayoutParams();
            lpToBeUsedPoint.bottomMargin = 100;
            lToBeUsedPoint.setLayoutParams(lpToBeUsedPoint);
            LinearLayout lUsableSavingPoint = (LinearLayout) findViewById(R.id.usable_saving_point);
            LinearLayout.LayoutParams lpUsableSavingPoint = (LinearLayout.LayoutParams) lUsableSavingPoint.getLayoutParams();
            lpUsableSavingPoint.bottomMargin = 100;
            lUsableSavingPoint.setLayoutParams(lpUsableSavingPoint);
        }
        setScrollView(0, false);
        int bottomMargin = getResources().getDimensionPixelOffset(R.dimen.ACTIONBAR_HEIGHT) - getResources().getDimensionPixelOffset(R.dimen.CARD_VIEW_OPEN_MARGIN);
        if (VERSION.SDK_INT >= 19) {
            bottomMargin += ((BaseActivity) getContext()).getStatusBarHeight();
        }
        ((RelativeLayout.LayoutParams) findViewById(R.id.billingLayout).getLayoutParams()).bottomMargin = bottomMargin;
        ((RelativeLayout.LayoutParams) findViewById(R.id.billingResultLayout).getLayoutParams()).bottomMargin = bottomMargin;
        ((RelativeLayout.LayoutParams) findViewById(R.id.delivery_result_layout).getLayoutParams()).bottomMargin = bottomMargin;
        this.mTouchListener = new XSwipeDismissTouchListener(getContext(), findViewById(R.id.paymentLayout), Integer.valueOf(0), new IMainCardViewDismiss() {
            public void onDismiss(View view) {
            }

            public boolean onDismiss(int position, Boolean dismiss) {
                if (dismiss.booleanValue()) {
                    CardView.this.setOpenCardFrame();
                } else {
                    CardView.this.setCloseCardFrame();
                }
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.quickpayview, (int) R.string.ga_ev_scroll, (int) R.string.quickpayview_scroll_card_leftright);
                return false;
            }

            public boolean canDismiss(int position) {
                return true;
            }
        });
        findViewById(R.id.barcodeZoomLayout).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent(CardView.this.getResources().getString(R.string.ga_paying), CardView.this.getResources().getString(R.string.ga_barcode_pay), CardView.this.getResources().getString(R.string.ga_barcode_zoom));
                ((MainActionBarActivity) CardView.this.getContext()).openBarcodeView();
            }
        });
        findViewById(R.id.keyDelete).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (!CardView.this.mPassword.isEmpty()) {
                    GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.quickpayview, (int) R.string.quickPayView_Password_Delete_Title, (int) R.string.quickPayView_Password_Delete);
                    char[] toArray = CardView.this.mPassword.toCharArray();
                    CardView.this.mPassword = "";
                    for (int i = 0; i < toArray.length - 1; i++) {
                        CardView.this.mPassword = CardView.this.mPassword + String.valueOf(toArray[i]);
                    }
                    CardView.this.setPasswordInputView();
                }
            }
        });
        findViewById(R.id.keyCancel).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.quickpayview, (int) R.string.ga_ev_cancle, (int) R.string.quickpayview_keypad_cancel);
                if (CardView.this.mPassword == null || CardView.this.mPassword.isEmpty()) {
                    CardView.this.mTouchListener.onCancelAnimateView();
                    return;
                }
                CardView.this.mPassword = "";
                CardView.this.setPasswordInputView();
            }
        });
        findViewById(R.id.keyConfirm).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (4 > CardView.this.mPassword.length()) {
                    Toast.makeText(CardView.this.getContext(), "\ube44\ubc00\ubc88\ud638\ub97c \ubaa8\ub450 \uc785\ub825\ud574 \uc8fc\uc138\uc694.", 0).show();
                    return;
                }
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.quickpayview, (int) R.string.ga_ev_complete, (int) R.string.quickPayView_Keypad_Confirm);
                CardView.this.mRequestPassword = CardView.this.mPassword;
                CardView.this.mRequestPartnerSno = CardView.this.mStoreModel.getPartnerSno();
                CardView.this.requestBilling();
                CardView.this.mTouchListener.onCancelAnimateView();
            }
        });
        findViewById(R.id.billingCancelButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent(CardView.this.getResources().getString(R.string.ga_paying), CardView.this.getResources().getString(R.string.ga_ev_click), CardView.this.getResources().getString(R.string.CARD_VIEW_PAYING_CANCEL_LABEL));
                ((BaseActivity) CardView.this.getContext()).showConfirmDialog(CardView.this.getContext().getResources().getString(R.string.paying_cancle_msg_confirm), new Runnable() {
                    public void run() {
                        ((TextView) CardView.this.findViewById(R.id.paymentStatusLabel)).setText(CardView.this.getContext().getString(R.string.CARD_VIEW_PAYING_LABEL));
                        ((TextView) CardView.this.findViewById(R.id.paymentDescriptionLabel)).setText(CardView.this.getContext().getString(R.string.CARD_VIEW_PAYING_DESC_LABEL));
                        ((TextView) CardView.this.findViewById(R.id.paymentSubDescriptionLabel)).setText("");
                        CardView.this.findViewById(R.id.paymentFailedLayout).setVisibility(8);
                        CardView.this.findViewById(R.id.billingCancelButton).setVisibility(0);
                        CardView.this.findViewById(R.id.paymentPartnerInfo).setVisibility(8);
                        ImageView imageView = (ImageView) CardView.this.findViewById(R.id.billingImageView);
                        imageView.setBackgroundResource(R.drawable.loading_animation);
                        ((AnimationDrawable) imageView.getBackground()).start();
                        EventBus.getDefault().post(new SocketSendEvent(3, null, null));
                        CardView.this.finishBilling();
                    }
                });
            }
        });
        findViewById(R.id.billingfinishButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                CardView.this.clearBillingView();
                EventBus.getDefault().post(new MainActivityFinishEvent());
            }
        });
        findViewById(R.id.reviewWriteButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.ga_pay_result, (int) R.string.ga_ev_click, (int) R.string.ga_pay_result_review);
                CardView.this.showReviewTypePopup();
            }
        });
        findViewById(R.id.order_history_btn).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.ga_payment_detail, (int) R.string.ga_ev_click, (int) R.string.ga_pay_result_order_history);
                new CustomSchemeManager();
                CustomSchemeManager.postSchemeAction(CardView.this.getContext(), "shareat://shareat.me/orderHistory");
            }
        });
        findViewById(R.id.finish_btn).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                EventBus.getDefault().post(new DeliveryActivityFinishEvent());
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.ga_payment_detail, (int) R.string.ga_ev_click, (int) R.string.ga_pay_result_delivery_finish);
                CardView.this.clearBillingView();
                EventBus.getDefault().post(new MainActivityFinishEvent());
            }
        });
        findViewById(R.id.billingFailedCancelButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                ((BaseActivity) CardView.this.getContext()).showConfirmDialog(CardView.this.getContext().getResources().getString(R.string.paying_cancle_msg_confirm), new Runnable() {
                    public void run() {
                        ((TextView) CardView.this.findViewById(R.id.paymentStatusLabel)).setText(CardView.this.getContext().getString(R.string.CARD_VIEW_PAYING_LABEL));
                        ((TextView) CardView.this.findViewById(R.id.paymentDescriptionLabel)).setText(CardView.this.getContext().getString(R.string.CARD_VIEW_PAYING_DESC_LABEL));
                        ((TextView) CardView.this.findViewById(R.id.paymentSubDescriptionLabel)).setText("");
                        CardView.this.findViewById(R.id.paymentFailedLayout).setVisibility(8);
                        CardView.this.findViewById(R.id.billingCancelButton).setVisibility(0);
                        CardView.this.findViewById(R.id.paymentPartnerInfo).setVisibility(8);
                        ImageView imageView = (ImageView) CardView.this.findViewById(R.id.billingImageView);
                        imageView.setBackgroundResource(R.drawable.loading_animation);
                        ((AnimationDrawable) imageView.getBackground()).start();
                        EventBus.getDefault().post(new SocketSendEvent(3, null, null));
                        CardView.this.finishBilling();
                    }
                });
            }
        });
        findViewById(R.id.retryButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                ((TextView) CardView.this.findViewById(R.id.paymentStatusLabel)).setText(CardView.this.getContext().getString(R.string.CARD_VIEW_PAYING_LABEL));
                ((TextView) CardView.this.findViewById(R.id.paymentDescriptionLabel)).setText(CardView.this.getContext().getString(R.string.CARD_VIEW_PAYING_DESC_LABEL));
                ((TextView) CardView.this.findViewById(R.id.paymentSubDescriptionLabel)).setText("");
                CardView.this.findViewById(R.id.paymentFailedLayout).setVisibility(8);
                CardView.this.findViewById(R.id.billingCancelButton).setVisibility(0);
                ImageView imageView = (ImageView) CardView.this.findViewById(R.id.billingImageView);
                imageView.setBackgroundResource(R.drawable.loading_animation);
                ((AnimationDrawable) imageView.getBackground()).start();
                CardView.this.requestBilling();
            }
        });
        findViewById(R.id.noneStoreLayout).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.quickpayview, (int) R.string.ga_ev_click, (int) R.string.quickPaySearch);
                ShareatApp.getInstance().setQuickPayClick(true);
                ((BaseActivity) CardView.this.getContext()).startActivityForResult(new Intent(CardView.this.getContext(), QuickPayActivity.class), MainActionBarActivity.QUICKPAYACTIVITY_RESULT_CODE);
            }
        });
        View guideView = View.inflate(getContext(), R.layout.view_popup_card_regist, null);
        this.mPopupWindow = new PopupWindow(guideView, -2, -2);
        this.mPopupWindow.setOutsideTouchable(true);
        this.mPopupWindow.setFocusable(true);
        this.mPopupWindow.setBackgroundDrawable(new BitmapDrawable());
        guideView.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                ((BaseActivity) CardView.this.getContext()).modalActivity(new Intent(CardView.this.getContext(), CardRegistActivity.class));
                CardView.this.mPopupWindow.dismiss();
            }
        });
        findViewById(R.id.paymentLayout).setOnTouchListener(this.mClearStoreTouchListener);
        if (!SessionManager.getInstance().hasSession()) {
            findViewById(R.id.joinTextLayout).setVisibility(0);
            ((TextView) findViewById(R.id.joinTextLayout)).setText("\ub85c\uadf8\uc778/\ud68c\uc6d0\uac00\uc785 \ud6c4, \ubc14\ub85c \uacb0\uc81c\ud558\uae30\uac00 \uac00\ub2a5\ud569\ub2c8\ub2e4.");
            findViewById(R.id.quickPayIconLayout).setVisibility(8);
        }
        findViewById(R.id.refresh_branch).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.quickpayview, (int) R.string.ga_ev_click, (int) R.string.refreshBranchSearch);
                ShareatApp.getInstance().setQuickPayClick(true);
                ((BaseActivity) CardView.this.getContext()).startActivityForResult(new Intent(CardView.this.getContext(), QuickPayActivity.class), MainActionBarActivity.QUICKPAYACTIVITY_RESULT_CODE);
            }
        });
        ((MainActionBarActivity) getContext()).getWindow().setSoftInputMode(32);
    }

    /* access modifiers changed from: private */
    public void requestBilling() {
        boolean z;
        boolean isChecked;
        ShareatApp.getInstance();
        if (1 != ShareatApp.getInstance().mNetWorkStatus) {
            if (ShareatApp.getInstance().getCurrentActivity() != null) {
                ((BaseActivity) ShareatApp.getInstance().getCurrentActivity()).showDialog(getResources().getString(R.string.COMMON_NETWORK_ERROR));
            }
        } else if (this.mStoreModel != null && this.mStoreModel.getPartnerSno() != null) {
            ShareatLogger.writeLog("[DEBUG] RequestBilling partner_sno=" + this.mStoreModel.getPartnerSno());
            ShareatLogger.writeLog("[DEBUG] RequestBilling mRequestPartnerSno=" + this.mRequestPartnerSno);
            setCardStatus(6);
            EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
            this.isPayingMode = true;
            findViewById(R.id.topButton).setVisibility(8);
            MainActionBarActivity mainActionBarActivity = (MainActionBarActivity) getContext();
            if (!this.isPayingMode) {
                z = true;
            } else {
                z = false;
            }
            mainActionBarActivity.setCardCloseViewVisiblity(z);
            try {
                Map<String, String> dataMap = new HashMap<>();
                dataMap.put("partner_sno", this.mRequestPartnerSno);
                dataMap.put("partnerSno", this.mRequestPartnerSno);
                dataMap.put("card_sno", this.mMainCardModel.getCard_sno());
                dataMap.put("cardSno", this.mMainCardModel.getCard_sno());
                dataMap.put("pin_pwd", MD5.makeMD5(this.mRequestPassword));
                dataMap.put("pinPwd", MD5.makeMD5(this.mRequestPassword));
                if (!(this.mSelectedCouponModel == null || this.mSelectedCouponModel.getCoupon_sn() == null)) {
                    dataMap.put("coupon_sn", this.mSelectedCouponModel.getCoupon_sn());
                    dataMap.put("couponSn", this.mSelectedCouponModel.getCoupon_sn());
                }
                if (findViewById(R.id.check_use_point_button) != null) {
                    if (((int) findViewById(R.id.check_use_point_circle).getTranslationX()) < 0) {
                        isChecked = true;
                    } else {
                        isChecked = false;
                    }
                    if (isChecked) {
                        dataMap.put("point_amt", ((EditText) findViewById(R.id.point_tobe_used)).getText().toString().replaceAll(",", ""));
                        dataMap.put("pointAmt", ((EditText) findViewById(R.id.point_tobe_used)).getText().toString().replaceAll(",", ""));
                    }
                }
                if (true == DELIVERY.equals(this.mStoreModel.getPaymentMethodType())) {
                    requestDeliveryPay(dataMap);
                    showBillingView();
                    EventBus.getDefault().post(new PayingEvent(true, true));
                    return;
                }
                EventBus.getDefault().post(new SocketSendEvent(2, SocketInterface.METHOD_CUSTOMER_PAY_REQUEST_STATUS, dataMap));
                if (true == this.isQuickMode && true == ((MainActionBarActivity) getContext()).isMapMode()) {
                    GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.quickpayview_pay_req, (int) R.string.quickpayview_pay_req, (int) R.string.ga_nmap_quick_payment_click);
                } else if (true == this.mStoreClick) {
                    GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.quickpayview_pay_req, (int) R.string.quickpayview_pay_req, (int) R.string.quickpayview_searchtype_detail);
                } else if (true == this.isQuickMode && true == this.isSearchQuickMode) {
                    GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.quickpayview_pay_req, (int) R.string.quickpayview_pay_req, (int) R.string.quickpayview_searchtype_search);
                } else {
                    GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.quickpayview_pay_req, (int) R.string.quickpayview_pay_req, (int) R.string.quickpayview_searchtype_auto);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void finishBilling() {
        boolean z;
        setCardStatus(this.mStoreModel == null ? 2 : 3);
        EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
        this.isPayingMode = false;
        findViewById(R.id.topButton).setVisibility(0);
        MainActionBarActivity mainActionBarActivity = (MainActionBarActivity) getContext();
        if (!this.isPayingMode) {
            z = true;
        } else {
            z = false;
        }
        mainActionBarActivity.setCardCloseViewVisiblity(z);
        GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.ga_pay_result, (int) R.string.ga_ev_click, (int) R.string.ga_pay_result_close);
        findViewById(R.id.billingLayout).startAnimation(AnimationUtils.loadAnimation(getContext(), R.anim.fade_out));
        findViewById(R.id.billingLayout).setVisibility(8);
        findViewById(R.id.barcodePayLayout).setVisibility(8);
        findViewById(R.id.payLightIcon).setVisibility(0);
        findViewById(R.id.billingTextLayout).setVisibility(0);
        ImageView imageView = (ImageView) findViewById(R.id.billingImageView);
        imageView.setBackgroundResource(R.drawable.loading_animation);
        AnimationDrawable frameAnimation = (AnimationDrawable) imageView.getBackground();
        frameAnimation.stop();
        frameAnimation.selectDrawable(0);
    }

    public boolean isRegisterMainCard() {
        if (this.mMainCardModel == null || this.mModel == null) {
            return false;
        }
        if (!this.mMainCardModel.getCard_name().equals("Cash Card") || this.mModel.getCard_list().size() != 0) {
            return true;
        }
        return false;
    }

    public void hideCardGuideView() {
        findViewById(R.id.closeGuideLayout).setVisibility(8);
        findViewById(R.id.rootLayout).setBackgroundResource(R.drawable.key_bottom_bg);
    }

    public void showCardCloseGuideView(boolean visible) {
        int i = 8;
        setScrollView(0, false);
        if (this.mMainCardModel == null || this.mModel == null) {
            hideCardGuideView();
            return;
        }
        if (!this.mMainCardModel.getCard_name().equals("Cash Card") || this.mModel.getCard_list().size() != 0) {
            findViewById(R.id.cardRegistTextLayout).setVisibility(8);
            findViewById(R.id.quickPayIconLayout).setVisibility(0);
        } else {
            findViewById(R.id.cardRegistTextLayout).setVisibility(0);
            findViewById(R.id.quickPayIconLayout).setVisibility(8);
        }
        View findViewById = findViewById(R.id.closeGuideLayout);
        if (visible) {
            i = 0;
        }
        findViewById.setVisibility(i);
        if (visible) {
            findViewById(R.id.rootLayout).setBackgroundColor(0);
        } else {
            findViewById(R.id.rootLayout).setBackgroundResource(R.drawable.key_bottom_bg);
        }
    }

    public void setCardViewData() {
        if (!SessionManager.getInstance().hasSession()) {
            findViewById(R.id.joinTextLayout).setVisibility(0);
            findViewById(R.id.quickPayIconLayout).setVisibility(8);
            return;
        }
        findViewById(R.id.cardRegistTextLayout).setVisibility(8);
        findViewById(R.id.quickPayIconLayout).setVisibility(0);
        if (SessionManager.getInstance().getUserModel() != null) {
            ImageDisplay.getInstance().displayImageLoadRound(SessionManager.getInstance().getUserModel().getUserImg(), (ImageView) findViewById(R.id.payNAvatar01), getResources().getDimensionPixelOffset(R.dimen.AVATAR_ROUND_SIZE_15OPX));
            ((TextView) findViewById(R.id.payNSelectName01)).setText(SessionManager.getInstance().getUserModel().getUserName());
        }
        ((ImageView) findViewById(R.id.cardImageView01)).setImageResource(R.drawable.card_bottom_none);
        ((ImageView) findViewById(R.id.cardImageView02)).setImageResource(R.drawable.card_bottom_none);
        ((ImageView) findViewById(R.id.cardImageView03)).setImageResource(R.drawable.card_bottom_none);
        findViewById(R.id.cardLayout01).setVisibility(8);
        findViewById(R.id.cardLayout02).setVisibility(8);
        findViewById(R.id.cardLayout03).setVisibility(8);
        findViewById(R.id.cardAdd03).setVisibility(8);
        final ArrayList<CardModel> models = this.mModel.getCard_list();
        OnClickListener onClickAddListener = new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.quickpayview, (int) R.string.ga_ev_card_reg, (int) R.string.quickpayview_registercard);
                Intent intent = new Intent(CardView.this.getContext(), CardRegistActivity.class);
                intent.putExtra("isMyCardInit", true);
                ((BaseActivity) CardView.this.getContext()).modalActivity(intent);
            }
        };
        if (1 == models.size()) {
            ((TextView) findViewById(R.id.cardNameLabel)).setText(models.get(0).getCard_name());
            ((TextView) findViewById(R.id.cardNumLabel)).setText(ShareAtUtil.replaceCardNum(models.get(0).getCard_no()));
            ImageDisplay.getInstance().displayImageLoad(models.get(0).getCard_img(), (ImageView) findViewById(R.id.cardImageView));
            findViewById(R.id.cardAddButton).setOnClickListener(onClickAddListener);
            findViewById(R.id.cardAddButton).setVisibility(0);
            this.mMainCardModel = models.get(0);
            models.remove(0);
            findViewById(R.id.cardRegistTextLayout).setVisibility(0);
            findViewById(R.id.quickPayIconLayout).setVisibility(8);
            setCardStatus(1);
            EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
            if (ShareatApp.getInstance().getGpsManager() != null && true == ShareatApp.getInstance().getGpsManager().isGetLocation() && !AppSettingManager.getInstance().getMainListActionGuideStatus()) {
                ((BaseActivity) getContext()).animActivity(new Intent((BaseActivity) getContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "main"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                return;
            }
            return;
        }
        setCardStatus(this.mStoreModel == null ? 2 : 3);
        EventBus.getDefault().post(new CardViewStatusEvent(isDeliveryCardView()));
        findViewById(R.id.cardAddButton).setVisibility(8);
        int i = 0;
        while (true) {
            if (i >= models.size()) {
                break;
            } else if (models.get(i).getMain_card().equals("Y")) {
                ((TextView) findViewById(R.id.cardNameLabel)).setText(models.get(i).getCard_name());
                ((TextView) findViewById(R.id.cardNumLabel)).setText(ShareAtUtil.replaceCardNum(models.get(i).getCard_no()));
                if (!models.get(i).getCard_name().equals("Cash Card")) {
                    ImageDisplay.getInstance().displayImageLoad(models.get(i).getCard_img(), (ImageView) findViewById(R.id.cardImageView));
                    this.mTouchListener.setValidCard(true);
                } else {
                    ((ImageView) findViewById(R.id.cardImageView)).setImageResource(R.drawable.img_card_nu);
                    this.mTouchListener.setValidCard(false);
                }
                this.mMainCardModel = models.get(i);
                models.remove(i);
            } else {
                i++;
            }
        }
        findViewById(R.id.paymentLayout).setOnClickListener(this.mPasswordViewClickListener);
        if ((this.mMainCardModel == null || !this.mMainCardModel.getCard_name().equals("Cash Card")) && this.mStoreModel != null) {
            findViewById(R.id.paymentLayout).setOnTouchListener(this.mTouchListener);
        } else {
            findViewById(R.id.paymentLayout).setOnTouchListener(this.mClearStoreTouchListener);
        }
        int i2 = 0;
        while (true) {
            if (i2 >= models.size()) {
                break;
            } else if (models.get(i2).getCard_name().equals("Cash Card")) {
                models.remove(i2);
                models.add(0, models.get(i2));
                break;
            } else {
                i2++;
            }
        }
        findViewById(R.id.cardMenuLayout01).setVisibility(8);
        findViewById(R.id.cardMenuLayout02).setVisibility(8);
        findViewById(R.id.cardMenuLayout03).setVisibility(8);
        findViewById(R.id.cardMainSet01).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                CardView.this.postRegistMainCard((CardModel) models.get(0));
            }
        });
        findViewById(R.id.cardMainSet02).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                CardView.this.postRegistMainCard((CardModel) models.get(1));
            }
        });
        findViewById(R.id.cardMainSet03).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                CardView.this.postRegistMainCard((CardModel) models.get(2));
            }
        });
        findViewById(R.id.cardRemove01).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (models.size() > 0) {
                    CardView.this.postCardDelete((CardModel) models.get(0));
                }
            }
        });
        findViewById(R.id.cardRemove02).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (1 < models.size()) {
                    CardView.this.postCardDelete((CardModel) models.get(1));
                }
            }
        });
        findViewById(R.id.cardRemove03).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (2 < models.size()) {
                    CardView.this.postCardDelete((CardModel) models.get(2));
                }
            }
        });
        findViewById(R.id.cardAdd01).setOnClickListener(onClickAddListener);
        findViewById(R.id.cardAdd02).setOnClickListener(onClickAddListener);
        findViewById(R.id.cardAdd03).setOnClickListener(onClickAddListener);
        findViewById(R.id.cardEdit01).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (models.size() > 0) {
                    CardView.this.cardNameChange(((CardModel) models.get(0)).getCard_sno());
                }
            }
        });
        findViewById(R.id.cardEdit02).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (1 < models.size()) {
                    CardView.this.cardNameChange(((CardModel) models.get(1)).getCard_sno());
                }
            }
        });
        findViewById(R.id.cardEdit03).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (2 < models.size()) {
                    CardView.this.cardNameChange(((CardModel) models.get(2)).getCard_sno());
                }
            }
        });
        int i3 = 0;
        while (i3 < models.size()) {
            int viewId = R.id.cardImageView01;
            switch (i3) {
                case 0:
                    viewId = R.id.cardImageView01;
                    findViewById(R.id.cardLayout01).setVisibility(0);
                    findViewById(R.id.cardMoreMenu01).setVisibility(0);
                    findViewById(R.id.cardAdd01).setVisibility(8);
                    findViewById(R.id.cardAdd02).setVisibility(0);
                    findViewById(R.id.cardImageView01).setVisibility(0);
                    findViewById(R.id.cardMoreMenu01).setOnClickListener(new OnClickListener() {
                        public void onClick(View v) {
                            CardView.this.findViewById(R.id.cardMenuLayout02).setVisibility(8);
                            CardView.this.findViewById(R.id.cardMenuLayout03).setVisibility(8);
                            if (CardView.this.findViewById(R.id.cardMenuLayout01).getVisibility() != 0) {
                                CardView.this.findViewById(R.id.cardMenuLayout01).setVisibility(0);
                            } else {
                                CardView.this.findViewById(R.id.cardMenuLayout01).setVisibility(8);
                            }
                        }
                    });
                    findViewById(R.id.cardLayout02).setVisibility(0);
                    break;
                case 1:
                    viewId = R.id.cardImageView02;
                    findViewById(R.id.cardMoreMenu02).setVisibility(0);
                    findViewById(R.id.cardAdd02).setVisibility(8);
                    findViewById(R.id.cardAdd03).setVisibility(0);
                    findViewById(R.id.cardImageView02).setVisibility(0);
                    findViewById(R.id.cardMoreMenu02).setOnClickListener(new OnClickListener() {
                        public void onClick(View v) {
                            CardView.this.findViewById(R.id.cardMenuLayout01).setVisibility(8);
                            CardView.this.findViewById(R.id.cardMenuLayout03).setVisibility(8);
                            if (CardView.this.findViewById(R.id.cardMenuLayout02).getVisibility() != 0) {
                                CardView.this.findViewById(R.id.cardMenuLayout02).setVisibility(0);
                            } else {
                                CardView.this.findViewById(R.id.cardMenuLayout02).setVisibility(8);
                            }
                        }
                    });
                    findViewById(R.id.cardAdd03).setVisibility(0);
                    break;
                case 2:
                    viewId = R.id.cardImageView03;
                    findViewById(R.id.cardLayout03).setVisibility(0);
                    findViewById(R.id.cardMoreMenu03).setVisibility(0);
                    findViewById(R.id.cardAdd03).setVisibility(8);
                    findViewById(R.id.cardImageView03).setVisibility(0);
                    findViewById(R.id.cardMoreMenu03).setOnClickListener(new OnClickListener() {
                        public void onClick(View v) {
                            CardView.this.findViewById(R.id.cardMenuLayout01).setVisibility(8);
                            CardView.this.findViewById(R.id.cardMenuLayout02).setVisibility(8);
                            if (CardView.this.findViewById(R.id.cardMenuLayout03).getVisibility() != 0) {
                                CardView.this.findViewById(R.id.cardMenuLayout03).setVisibility(0);
                            } else {
                                CardView.this.findViewById(R.id.cardMenuLayout03).setVisibility(8);
                            }
                        }
                    });
                    break;
            }
            if (!models.get(i3).getCard_name().equals("Cash Card")) {
                ImageDisplay.getInstance().displayImageLoad(models.get(i3).getCard_img(), (ImageView) findViewById(viewId));
                int i4 = i3 == 0 ? R.id.cardRemove01 : i3 == 1 ? R.id.cardRemove02 : R.id.cardRemove03;
                findViewById(i4).setVisibility(0);
            } else {
                ((ImageView) findViewById(viewId)).setImageResource(R.drawable.img_card_nu);
                int i5 = i3 == 0 ? R.id.cardRemove01 : i3 == 1 ? R.id.cardRemove02 : R.id.cardRemove03;
                findViewById(i5).setVisibility(8);
            }
            i3++;
        }
    }

    /* access modifiers changed from: private */
    public void postRegistMainCard(final CardModel model) {
        ((BaseActivity) getContext()).showConfirmDialog("\"" + model.getCard_name() + "\"" + getContext().getString(R.string.payment_main_card_change_req_msg), new Runnable() {
            public void run() {
                CardView.this.requestRegistMainCard(model.getCard_sno());
            }
        });
    }

    public void requestCardListApi() {
        new CardListApi(getContext()).request(new RequestHandler() {
            public void onResult(Object result) {
                CardView.this.mModel = (CardResultModel) result;
                CardView.this.setCardViewData();
            }

            public void onFailure(Exception exception) {
                ((BaseActivity) CardView.this.getContext()).handleException(exception, new Runnable() {
                    public void run() {
                        CardView.this.requestCardListApi();
                    }
                }, null);
            }
        });
    }

    public void requestRegistMainCard(final String cardNo) {
        GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.quickpayview, (int) R.string.ga_ev_change, (int) R.string.quickpayview_updatemaincard);
        RegistMainCardApi request = new RegistMainCardApi(getContext());
        request.addParam("card_sno", cardNo);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                if (((BaseResultModel) result).getResult().equals("Y")) {
                    CardView.this.requestCardListApi();
                } else {
                    ((BaseActivity) CardView.this.getContext()).showDialog(CardView.this.getResources().getString(R.string.MY_CARD_MAIN_CARD_REGIST_ALERT));
                }
            }

            public void onFailure(Exception exception) {
                ((BaseActivity) CardView.this.getContext()).handleException(exception, new Runnable() {
                    public void run() {
                        CardView.this.requestRegistMainCard(cardNo);
                    }
                }, null);
            }
        });
    }

    public void requestAutoBranch() {
        if (this.mStoreModel == null) {
            if (AppSettingManager.getInstance().getAutoBranchSearchStatus()) {
                if (LoplatManager.getInstance((BaseActivity) getContext()).getSearchingStatus() == 0) {
                    EventBus.getDefault().post(new RequestAutoBranchEvent(3));
                    return;
                }
                Date FindPartnerDate = LoplatManager.getInstance((BaseActivity) getContext()).getFindPartnerTime();
                Date recentSearchDate = LoplatManager.getInstance((BaseActivity) getContext()).getRecentSearchTime();
                Date currentDate = new Date(System.currentTimeMillis());
                boolean bFindSuccess = LoplatManager.getInstance((BaseActivity) getContext()).getFindSuccess();
                LoplatConfigModel lcm = LoplatManager.getInstance((BaseActivity) getContext()).getLoplatConfigModel();
                if (recentSearchDate != null) {
                    long lSearchInteval = (currentDate.getTime() - recentSearchDate.getTime()) / 60000;
                    int nPeriod = 5;
                    if (lcm != null) {
                        nPeriod = lcm.getSearchFailPeriod();
                    }
                    if (((long) nPeriod) > lSearchInteval && !bFindSuccess) {
                        ShareatLogger.writeLog("[DEBUG] 5min was called and search failed");
                        if (!AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
                            Intent intent = new Intent((BaseActivity) getContext(), ActionGuideActivity.class);
                            ((BaseActivity) getContext()).animActivity(intent.putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_search"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                            return;
                        }
                        return;
                    }
                }
                if (FindPartnerDate == null) {
                    EventBus.getDefault().post(new RequestAutoBranchEvent(1));
                    return;
                }
                long lMinDiff = (currentDate.getTime() - FindPartnerDate.getTime()) / 60000;
                int nSavePeriod = 3;
                if (lcm != null) {
                    nSavePeriod = lcm.getBranchInfoSavePeriod();
                }
                if (((long) nSavePeriod) <= lMinDiff || true != bFindSuccess) {
                    LoplatManager.getInstance((BaseActivity) getContext()).clearData();
                    EventBus.getDefault().post(new RequestAutoBranchEvent(1));
                    return;
                }
                StoreModel sm = LoplatManager.getInstance((BaseActivity) getContext()).getStoreModel();
                if (sm != null) {
                    ShareatLogger.writeLog("[DEBUG] Recent data is valid - " + lMinDiff + "\ubd84");
                    ((CardView) findViewById(R.id.cardView)).setQuickMode(true);
                    ((CardView) findViewById(R.id.cardView)).setAutoBranchSearch(true);
                    ((CardView) findViewById(R.id.cardView)).setStoreModel(sm);
                    return;
                }
                ((CardView) findViewById(R.id.cardView)).setAutoBranchSearch(false);
            }
        } else if (!((MainActionBarActivity) getContext()).isMapMode() && !AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
            Intent intent2 = new Intent((BaseActivity) getContext(), ActionGuideActivity.class);
            ((BaseActivity) getContext()).animActivity(intent2.putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_normal"), R.anim.fade_in_activity, R.anim.fade_out_activity);
        }
    }

    public void showCardGuideView() {
        if (true != ((MainActionBarActivity) getContext()).isFinishing() && findViewById(R.id.cardAddButton) != null && findViewById(R.id.cardAddButton).getVisibility() == 0 && findViewById(R.id.billingLayout).getVisibility() != 0 && findViewById(R.id.bottomCardView).getVisibility() == 0) {
            this.mPopupWindow.showAtLocation(findViewById(R.id.rootLayout), 0, (findViewById(R.id.rootLayout).getWidth() / 2) - getResources().getDimensionPixelOffset(R.dimen.CARD_REGIST_X_LOCATION_MARGIN), (int) (findViewById(R.id.bottomCardViewLayout).getY() + ((float) getResources().getDimensionPixelOffset(R.dimen.CARD_REGIST_Y_LOCATION_MARGIN))));
        }
    }

    public void shuffleKeypad() {
        Collections.shuffle(this.mKeypadIds);
        for (int i = 0; i < this.mKeypadIds.size(); i++) {
            if (i > 9) {
                findViewById(this.mKeypadIds.get(i).intValue()).setEnabled(false);
                ((Button) findViewById(this.mKeypadIds.get(i).intValue())).setText("");
                ((Button) findViewById(this.mKeypadIds.get(i).intValue())).setCompoundDrawablesWithIntrinsicBounds(R.drawable.keypad_icon_lock, 0, 0, 0);
            } else {
                findViewById(this.mKeypadIds.get(i).intValue()).setEnabled(true);
                ((Button) findViewById(this.mKeypadIds.get(i).intValue())).setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0);
                ((Button) findViewById(this.mKeypadIds.get(i).intValue())).setText("" + i);
            }
            findViewById(this.mKeypadIds.get(i).intValue()).setOnClickListener(this.mKeypadListener);
        }
    }

    /* access modifiers changed from: private */
    public void showReviewTypePopup() {
        GAEvent.onGAScreenView((BaseActivity) getContext(), R.string.ga_review_popup);
        ReviewTypeDialog dialog = new ReviewTypeDialog(getContext());
        dialog.setOnDialogClickListener(new DialogClickListener() {
            public void onClickNext(ArrayList<ReviewTagModel> tags) {
                GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.ga_store_detail, (int) R.string.store_detile_action_review_write, (int) R.string.ga_store_detail_review_write);
                Intent intent = new Intent(CardView.this.getContext(), ReviewActivity.class);
                intent.putExtra("partnerSno", CardView.this.mRequestPartnerSno);
                intent.putExtra("tags", tags);
                ((BaseActivity) CardView.this.getContext()).pushActivity(intent);
            }
        });
        dialog.show();
    }

    /* access modifiers changed from: private */
    /* JADX WARNING: Code restructure failed: missing block: B:10:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:3:0x003a, code lost:
        if (4 != r6.mPassword.length()) goto L_?;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:4:0x003c, code lost:
        findViewById(com.nuvent.shareat.R.id.keyConfirm).performClick();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:6:0x0051, code lost:
        findViewById(com.nuvent.shareat.R.id.passwordInputLabel03).setSelected(true);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x0058, code lost:
        findViewById(com.nuvent.shareat.R.id.passwordInputLabel02).setSelected(true);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x005f, code lost:
        findViewById(com.nuvent.shareat.R.id.passwordInputLabel01).setSelected(true);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:?, code lost:
        return;
     */
    public void setPasswordInputView() {
        findViewById(R.id.passwordInputLabel01).setSelected(false);
        findViewById(R.id.passwordInputLabel02).setSelected(false);
        findViewById(R.id.passwordInputLabel03).setSelected(false);
        findViewById(R.id.passwordInputLabel04).setSelected(false);
        switch (this.mPassword.length()) {
            case 1:
                break;
            case 2:
                break;
            case 3:
                break;
            case 4:
                findViewById(R.id.passwordInputLabel04).setSelected(true);
                break;
        }
    }

    /* access modifiers changed from: private */
    public void postCardDelete(final CardModel model) {
        GAEvent.onGaEvent((Activity) (BaseActivity) getContext(), (int) R.string.payment_setting, (int) R.string.ga_ev_click, (int) R.string.payment_setting_delete_card);
        if (!TextUtils.isEmpty(model.getMain_card()) && model.getMain_card().equals("Y")) {
            ((BaseActivity) getContext()).showDialog(getContext().getResources().getString(R.string.payment_main_card_del_enable_mag), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss();
                }
            });
        } else if (model.getCard_id().equals("00")) {
            ((BaseActivity) getContext()).showDialog(getContext().getResources().getString(R.string.payment_main_card_del_enable_cash_card), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss();
                }
            });
        } else {
            ((BaseActivity) getContext()).showConfirmDialog(model.getCard_name() + getContext().getResources().getString(R.string.payment_main_card_del_req_msg), new Runnable() {
                public void run() {
                    CardView.this.requestCardDelete(model.getCard_sno());
                }
            });
        }
    }

    /* access modifiers changed from: private */
    public void requestCardDelete(final String cardSno) {
        CardDeleteApi request = new CardDeleteApi(getContext());
        request.addParam("card_sno", cardSno);
        request.request(new RequestHandler() {
            public void onStart() {
                ((BaseActivity) CardView.this.getContext()).showCircleDialog(true);
            }

            public void onResult(Object result) {
                ((BaseActivity) CardView.this.getContext()).showCircleDialog(false);
                if (new JsonParser().parse((String) result).getAsJsonObject().get("result").getAsString().equals("Y")) {
                    CardView.this.requestCardListApi();
                }
            }

            public void onFailure(Exception exception) {
                ((BaseActivity) CardView.this.getContext()).showCircleDialog(false);
                ((BaseActivity) CardView.this.getContext()).handleException(exception, new Runnable() {
                    public void run() {
                        CardView.this.requestCardDelete(cardSno);
                    }
                }, null);
            }

            public void onFinish() {
                ((BaseActivity) CardView.this.getContext()).showCircleDialog(false);
            }
        });
    }

    /* access modifiers changed from: private */
    public void cardNameChange(String cardSno) {
        Intent intent = new Intent(getContext(), MyCardActivity.class);
        intent.putExtra("cardSno", cardSno);
        ((BaseActivity) getContext()).pushActivity(intent);
    }

    /* access modifiers changed from: private */
    public void setPaymentLimitDistance(int distance) {
        if (distance != 0) {
            this.mPaymentLimitDistance = distance;
        }
    }

    /* access modifiers changed from: private */
    public void requestPaymentLimitDistanceApi() {
        new PaymentLimitDistanceApi(getContext()).request(new RequestHandler() {
            public void onResult(Object result) {
                PaydisModel pmodel;
                PaydisResultModel model = (PaydisResultModel) result;
                if (model.getResult_list() != null && model.getResult_list().size() > 0) {
                    ArrayList<PaydisModel> paydisModels = model.getResult_list();
                    String standardDistance = String.valueOf(CardView.this.mPaymentLimitDistance);
                    Iterator<PaydisModel> it = paydisModels.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            break;
                        }
                        pmodel = it.next();
                        if (true == CardView.DELIVERY.equals(CardView.this.mStoreModel.getPaymentMethodType())) {
                            if (true == "PDIS".equals(pmodel.getCode_id())) {
                                standardDistance = pmodel.getCode_value();
                                break;
                            } else if (true == "QDIS".equals(pmodel.getCode_id())) {
                                standardDistance = pmodel.getCode_value();
                            }
                        } else if (true == "APP".equals(CardView.this.mStoreModel.getPaymentMethodType()) || true == "BARCODE".equals(CardView.this.mStoreModel.getPaymentMethodType())) {
                            standardDistance = pmodel.getCode_value();
                        }
                    }
                    standardDistance = pmodel.getCode_value();
                    CardView.this.setPaymentLimitDistance(Integer.parseInt(standardDistance));
                }
            }

            public void onFailure(Exception exception) {
                ((BaseActivity) CardView.this.getContext()).handleException(exception, new Runnable() {
                    public void run() {
                        CardView.this.requestPaymentLimitDistanceApi();
                    }
                });
            }
        });
    }

    public int getIUsablePoint() {
        return this.iUsablePoint;
    }

    /* access modifiers changed from: private */
    public boolean checkUsablePoint(String inputPointToBeUsed) {
        if (inputPointToBeUsed == null || "".equals(inputPointToBeUsed)) {
            inputPointToBeUsed = AppEventsConstants.EVENT_PARAM_VALUE_NO;
        }
        String inputPointToBeUsed2 = inputPointToBeUsed.replaceAll(",", "");
        if (Integer.parseInt(inputPointToBeUsed2) > this.iUsablePoint) {
            Toast.makeText(getContext(), "\ubcf4\uc720\ud558\uc2e0 \uc801\ub9bd\uae08 \ubcf4\ub2e4 \ub9ce\uc740 \uc801\ub9bd\uae08\uc744 \uc785\ub825\ud558\uc168\uc2b5\ub2c8\ub2e4.", 0).show();
            ((EditText) findViewById(R.id.point_tobe_used)).setText(FormatUtil.onDecimalFormat(this.iUsablePoint));
            return false;
        }
        ((EditText) findViewById(R.id.point_tobe_used)).setText(FormatUtil.onDecimalFormat(inputPointToBeUsed2));
        return true;
    }

    private void hideKeyboard() {
        Activity activity = (Activity) getContext();
        InputMethodManager imm = (InputMethodManager) activity.getSystemService("input_method");
        View view = activity.getCurrentFocus();
        if (view == null) {
            view = new View(activity);
        }
        imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
    }

    public void addResizeLayoutListener() {
        ViewTreeObserver viewTreeObserver = findViewById(R.id.root_layout).getViewTreeObserver();
        AnonymousClass52 r1 = new OnGlobalLayoutListener() {
            public void onGlobalLayout() {
                if (((FontEditTextView) CardView.this.findViewById(R.id.point_tobe_used)).isFocused()) {
                    Rect rect = new Rect();
                    CardView.this.findViewById(R.id.root_layout).getWindowVisibleDisplayFrame(rect);
                    if (CardView.this.findViewById(R.id.root_layout).getRootView().getHeight() - rect.bottom == 0) {
                        CardView.this.findViewById(R.id.root_layout).animate().setDuration(400).translationY(0.0f);
                        return;
                    }
                    Rect pointRect = new Rect();
                    CardView.this.findViewById(R.id.point_tobe_used).getGlobalVisibleRect(pointRect);
                    if (rect.bottom < pointRect.bottom) {
                        CardView.this.findViewById(R.id.root_layout).animate().setDuration(400).translationY((float) (-(pointRect.bottom - rect.bottom)));
                    }
                    GAEvent.onGaEvent((Activity) (MainActionBarActivity) CardView.this.getContext(), (int) R.string.ga_apply_point, (int) R.string.ga_ev_click, (int) R.string.ga_point_tobe_edit);
                }
            }
        };
        this.layoutListener = r1;
        viewTreeObserver.addOnGlobalLayoutListener(r1);
    }

    public void removeResizeLayoutListener() {
        findViewById(R.id.root_layout).animate().setDuration(400).translationY(0.0f);
        if (VERSION.SDK_INT >= 16) {
            findViewById(R.id.root_layout).getViewTreeObserver().removeOnGlobalLayoutListener(this.layoutListener);
        } else {
            findViewById(R.id.root_layout).getViewTreeObserver().removeGlobalOnLayoutListener(this.layoutListener);
        }
    }

    private void requestDeliveryPay(Map<String, String> payData) {
        DeliveryPaymentApi request = new DeliveryPaymentApi(getContext());
        for (String key : payData.keySet()) {
            request.addParam(key, payData.get(key));
        }
        for (String key2 : this.deliveryInfoData.keySet()) {
            request.addParam(key2, this.deliveryInfoData.get(key2));
        }
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                DeliveryPaymentResultModel deliveryPaymentResultModel = (DeliveryPaymentResultModel) result;
                PayResultModel payResultModel = deliveryPaymentResultModel.getPay_result();
                DeliveryPaymentOrderListModel deliveryPaymentOrderListModel = deliveryPaymentResultModel.getOrder_result();
                CardView.this.postPaymentResult(payResultModel);
                if (30 == payResultModel.group_pay_status) {
                    CardView.this.deliveryBillingSuccessView((String) CardView.this.deliveryInfoData.get("menuImagePath"), payResultModel, deliveryPaymentOrderListModel);
                    CardView.this.setBanner(payResultModel);
                    return;
                }
                try {
                    GAEvent.onGaEvent((Activity) (BaseActivity) CardView.this.getContext(), (int) R.string.error, (int) R.string.ga_payment, (int) R.string.Error_FailPayment);
                    Answers.getInstance().logPurchase(new PurchaseEvent().putItemPrice(BigDecimal.valueOf((long) payResultModel.pay_real)).putCurrency(Currency.getInstance("KRW")).putItemName(URLDecoder.decode(payResultModel.partner_name1, "UTF-8")).putSuccess(false));
                } catch (Exception e) {
                    e.printStackTrace();
                }
                CardView.this.showDeliveryBillingFailedView(deliveryPaymentResultModel.getGroup_pay_status(), deliveryPaymentResultModel.getResult_message());
            }

            public void onFailure(Exception exception) {
                ((BaseActivity) CardView.this.getContext()).handleException(exception, new Runnable() {
                    public void run() {
                    }
                }, null);
            }
        });
    }
}