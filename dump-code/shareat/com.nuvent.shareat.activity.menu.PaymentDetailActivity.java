package com.nuvent.shareat.activity.menu;

import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.FrameLayout.LayoutParams;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.common.WebViewActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.card.PaymentDetailApi;
import com.nuvent.shareat.api.store.ADBannerApi;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.model.ADBannerDetailModel;
import com.nuvent.shareat.model.ADBannerResultModel;
import com.nuvent.shareat.model.MyPaymentModel;
import com.nuvent.shareat.model.payment.PaymentDetailModel;
import com.nuvent.shareat.util.GAEvent;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.List;
import net.xenix.util.ImageDisplay;
import net.xenix.util.ProportionalImageView;

public class PaymentDetailActivity extends MainActionBarActivity implements OnClickListener {
    /* access modifiers changed from: private */
    public ProportionalImageView adPayDetailTopImageView;
    /* access modifiers changed from: private */
    public ADBannerDetailModel adPayDetailTopModel;
    private MyPaymentModel mMyPaymentModel;

    public void onBackPressed() {
        if (isOpenBarcodeView()) {
            closeBarcodeView();
        } else {
            finish();
        }
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickEmail(View view) {
        pushActivity(new Intent(this, WebViewActivity.class).putExtra("title", "\uc601\uc218\uc99d").putExtra("url", String.format(ApiUrl.RECENT_DO, new Object[]{ShareatApp.getInstance().getUserNum(), this.mMyPaymentModel.pay_group, this.mMyPaymentModel.order_id})));
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_payment_detail, 5);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\uc601\uc218\uc99d");
        GAEvent.onGAScreenView(this, R.string.ga_pay_result);
        this.mMyPaymentModel = (MyPaymentModel) getIntent().getSerializableExtra("data");
        ((TextView) findViewById(R.id.titleLabel)).setText(getResources().getString(R.string.PAYMENT_DETAIL_TITLE));
        getData();
        if (this.mMyPaymentModel.getPay_method() == null || this.mMyPaymentModel.getPay_method().equals("APP")) {
            findViewById(R.id.barcodeButtonLayout).setBackgroundResource(R.drawable.payment_barcode_dim_button);
            ((ImageView) findViewById(R.id.barcodeButtonIcon)).setImageResource(R.drawable.payment_barcode_icon_off);
            ((TextView) findViewById(R.id.barcodeButtonText)).setTextColor(Color.parseColor("#ffdbdde3"));
        } else {
            setBarcode(String.format(ApiUrl.BARCODE_IMAGE, new Object[]{this.mMyPaymentModel.getPin_no()}));
            setBarcodeTimerLabel("");
            findViewById(R.id.barcodeButtonLayout).setBackgroundResource(R.drawable.payment_barcode_button);
            ((ImageView) findViewById(R.id.barcodeButtonIcon)).setImageResource(R.drawable.payment_barcode_icon);
            ((TextView) findViewById(R.id.barcodeButtonText)).setTextColor(Color.parseColor("#ffffffff"));
            findViewById(R.id.barcodeButtonLayout).setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    PaymentDetailActivity.this.openBarcodeView();
                }
            });
        }
        this.adPayDetailTopImageView = new ProportionalImageView(this);
        this.adPayDetailTopImageView.setLayoutParams(new LayoutParams(-1, -1));
        this.adPayDetailTopImageView.setAdjustViewBounds(true);
        setADBanner();
    }

    /* access modifiers changed from: private */
    public void getData() {
        new PaymentDetailApi(this, ApiUrl.PAYMENT_HISTORY_INFO + String.format("?pay_group=%1$s&order_id=%2$s", new Object[]{this.mMyPaymentModel.pay_group, this.mMyPaymentModel.order_id})).request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onResult(Object result) {
                PaymentDetailActivity.this.initView((PaymentDetailModel) result);
            }

            public void onFailure(Exception exception) {
                PaymentDetailActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        PaymentDetailActivity.this.getData();
                    }
                });
            }
        });
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.emailButton /*2131296628*/:
                startActivity(new Intent("android.intent.action.VIEW", Uri.parse(String.format(ApiUrl.RECENT_DO, new Object[]{ShareatApp.getInstance().getUserNum(), this.mMyPaymentModel.pay_group, this.mMyPaymentModel.order_id}))));
                return;
            default:
                return;
        }
    }

    /* access modifiers changed from: private */
    public void initView(PaymentDetailModel result) {
        ((TextView) findViewById(R.id.payment_result_value_label)).setText(stringFormmter(R.string.payment_result_value_label_text, String.valueOf(this.mMyPaymentModel.getPeopleCount())));
        ((TextView) findViewById(R.id.payment_result_value)).setText(this.mMyPaymentModel.getPayTotal(String.valueOf(this.mMyPaymentModel.pay_total)) + "\uc6d0");
        ((TextView) findViewById(R.id.payment_result_store)).setText(stringFormmter(R.string.payment_result_store_text, result.partner_name1));
        ((TextView) findViewById(R.id.payment_result_discount_label)).setText(stringFormmter(R.string.payment_result_discount_label_text, String.valueOf(result.dc_rate)));
        ((TextView) findViewById(R.id.payment_result_discount_value)).setText("-" + result.getPersonDiscountAmt(result.person_discount_amt) + "\uc6d0");
        ((TextView) findViewById(R.id.payment_result_real_value)).setText(result.getRealPay(String.valueOf(result.pay_amt)) + "\uc6d0");
        ((TextView) findViewById(R.id.payment_result_day)).setText(stringFormmter(R.string.payment_result_day_text, result.pay_date_text));
        View userView = findViewById(R.id.payment_board_center);
        final View view = userView;
        final PaymentDetailModel paymentDetailModel = result;
        AnonymousClass3 r0 = new Runnable() {
            public void run() {
                PaymentDetailActivity.this.createUserView(view, view.getLayoutParams().height, paymentDetailModel.pay_amt);
            }
        };
        userView.post(r0);
        TextView cuponWon = (TextView) findViewById(R.id.payment_cupon_value);
        TextView pointWon = (TextView) findViewById(R.id.payment_point_value);
        View couponParent = (View) cuponWon.getParent();
        if (TextUtils.isEmpty(result.coupon_amt) || AppEventsConstants.EVENT_PARAM_VALUE_NO.equals(result.coupon_amt)) {
            findViewById(R.id.payment_result_cupon_value_label).setVisibility(8);
            couponParent.setVisibility(8);
        } else {
            cuponWon.setText("-" + result.onDecimalFormat(Integer.parseInt(result.coupon_amt)) + "\uc6d0");
            findViewById(R.id.payment_result_cupon_value_label).setVisibility(0);
            couponParent.setVisibility(0);
        }
        View pointParent = (View) pointWon.getParent();
        if (TextUtils.isEmpty(result.point_amt) || AppEventsConstants.EVENT_PARAM_VALUE_NO.equals(result.point_amt)) {
            findViewById(R.id.payment_result_point_value_label).setVisibility(8);
            pointParent.setVisibility(8);
            return;
        }
        pointWon.setText("-" + result.onDecimalFormat(Integer.parseInt(result.point_amt)) + "\uc6d0");
        findViewById(R.id.payment_result_point_value_label).setVisibility(0);
        pointParent.setVisibility(0);
    }

    private String stringFormmter(int strRes, String data) {
        return String.format(getString(strRes), new Object[]{data});
    }

    /* access modifiers changed from: private */
    public void createUserView(View view, int height, int payAmt) {
        View convertView = LayoutInflater.from(this).inflate(R.layout.view_result_user_item, null, false);
        TextView userName = (TextView) convertView.findViewById(R.id.payment_user_name);
        TextView payValue = (TextView) convertView.findViewById(R.id.payment_user_value);
        userName.setText(this.mMyPaymentModel.user_view_name);
        payValue.setText(stringFormmter(R.string.payment_result_won_text, this.mMyPaymentModel.getRealPay(String.valueOf(payAmt))));
        convertView.setLayoutParams(new ViewGroup.LayoutParams(-1, -2));
        userName.setSelected(true);
        payValue.setSelected(true);
        View findViewById = convertView.findViewById(R.id.payment_user_mark);
        ((LinearLayout) view).addView(convertView);
    }

    /* access modifiers changed from: private */
    public void onClickBanner() {
        String adPayTopSubTitle = "";
        try {
            if (this.adPayDetailTopModel != null) {
                try {
                    adPayTopSubTitle = URLDecoder.decode(adPayTopSubTitle, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
            GAEvent.onGaEvent(getResources().getString(R.string.ga_payment_detail), getResources().getString(R.string.ga_ev_click), new StringBuilder().append(getResources().getString(R.string.ga_ad_banner)).append(adPayTopSubTitle).toString() == null ? "" : EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + adPayTopSubTitle);
            CustomSchemeManager.postSchemeAction(this, this.adPayDetailTopModel.getScheme_url());
        } catch (NullPointerException e2) {
            e2.printStackTrace();
        }
    }

    /* access modifiers changed from: private */
    public void resizePaymentDetailView(boolean hasAdvertise) {
        LinearLayout.LayoutParams lpPaymentBoardTop = (LinearLayout.LayoutParams) ((LinearLayout) findViewById(R.id.payment_board_top)).getLayoutParams();
        LinearLayout.LayoutParams lpPaymentBoardCenter = (LinearLayout.LayoutParams) ((LinearLayout) findViewById(R.id.payment_board_center_layout)).getLayoutParams();
        if (hasAdvertise) {
            lpPaymentBoardTop.topMargin = 17;
            lpPaymentBoardCenter.height = 300;
            return;
        }
        lpPaymentBoardTop.topMargin = 120;
        lpPaymentBoardCenter.height = 420;
    }

    private void setADBanner() {
        new ADBannerApi(this).request(new RequestHandler() {
            public void onResult(Object result) {
                List<ADBannerDetailModel> adBannerList = ((ADBannerResultModel) result).getResult_list();
                boolean hasAdvertise = false;
                LinearLayout adPayDetailTopLayout = (LinearLayout) PaymentDetailActivity.this.findViewById(R.id.advertise_pay_detail_top);
                if (adBannerList == null || adBannerList.isEmpty()) {
                    adPayDetailTopLayout.setVisibility(8);
                } else {
                    PaymentDetailActivity.this.adPayDetailTopModel = adBannerList.get(0);
                    if (adPayDetailTopLayout != null) {
                        adPayDetailTopLayout.removeAllViews();
                        ImageDisplay.getInstance().displayImageLoad(PaymentDetailActivity.this.adPayDetailTopModel.getImg_url(), PaymentDetailActivity.this.adPayDetailTopImageView);
                        adPayDetailTopLayout.addView(PaymentDetailActivity.this.adPayDetailTopImageView);
                        PaymentDetailActivity.this.adPayDetailTopImageView.setOnClickListener(new OnClickListener() {
                            public void onClick(View v) {
                                PaymentDetailActivity.this.onClickBanner();
                            }
                        });
                        hasAdvertise = true;
                    }
                }
                PaymentDetailActivity.this.resizePaymentDetailView(hasAdvertise);
            }
        });
    }
}