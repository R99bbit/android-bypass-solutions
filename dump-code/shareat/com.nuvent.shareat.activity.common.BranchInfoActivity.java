package com.nuvent.shareat.activity.common;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningAppProcessInfo;
import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.NotificationCompat.Builder;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.WindowManager.LayoutParams;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.ExternalBridgeActivity;
import com.nuvent.shareat.api.RegistStoreCouponApi;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.event.CouponUpdateEvent;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.store.StoreModel;
import de.greenrobot.event.EventBus;
import net.xenix.android.widget.LetterSpacingTextView;
import net.xenix.util.ImageDisplay;

public class BranchInfoActivity extends BaseActivity implements OnClickListener {
    static int TEST_COUNT = 0;
    private LinearLayout mBranchDetail;
    private ImageButton mClose;
    private String mPartnerSno;
    private Handler mPopupLiveHandler = null;
    private Runnable mPopupLiveRunnable = null;
    private LinearLayout mQuickPay;
    private StoreModel mStoreModel;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        LayoutParams window = new LayoutParams();
        window.flags = 2;
        window.dimAmount = 0.4f;
        getWindow().setAttributes(window);
        setContentView(R.layout.auto_branch_popup);
        this.mBranchDetail = (LinearLayout) findViewById(R.id.popup_branch_detail);
        this.mQuickPay = (LinearLayout) findViewById(R.id.popup_quick_pay);
        this.mClose = (ImageButton) findViewById(R.id.auto_branch_close);
        this.mBranchDetail.setOnClickListener(this);
        this.mQuickPay.setOnClickListener(this);
        this.mClose.setOnClickListener(this);
        this.mStoreModel = new StoreModel();
        this.mPartnerSno = getIntent().getStringExtra("clientCode");
        if (this.mPartnerSno == null || true == this.mPartnerSno.isEmpty()) {
            finish(0, 0);
            return;
        }
        this.mStoreModel = (StoreModel) getIntent().getSerializableExtra("model");
        showPopup();
    }

    private void setTestLivePopupTimer() {
        if (this.mPopupLiveHandler == null) {
            this.mPopupLiveHandler = new Handler();
        }
        if (this.mPopupLiveRunnable == null) {
            this.mPopupLiveRunnable = new Runnable() {
                public void run() {
                    BranchInfoActivity.TEST_COUNT++;
                    if (BranchInfoActivity.TEST_COUNT == 1) {
                        BranchInfoActivity.this.SetTestBranchInfo();
                    } else {
                        BranchInfoActivity.this.onBackPressed();
                    }
                }
            };
        }
        this.mPopupLiveHandler.postDelayed(this.mPopupLiveRunnable, 10000);
    }

    private void setLivePopupTimer() {
        if (this.mPopupLiveHandler == null) {
            this.mPopupLiveHandler = new Handler();
        }
        if (this.mPopupLiveRunnable == null) {
            this.mPopupLiveRunnable = new Runnable() {
                public void run() {
                    BranchInfoActivity.this.onBackPressed();
                }
            };
        }
        this.mPopupLiveHandler.postDelayed(this.mPopupLiveRunnable, 600000);
    }

    private void showPopup() {
        SetBranchInfo();
        if (isLock()) {
            SetNotification();
        }
        ((LinearLayout) findViewById(R.id.auto_branch_popup)).setVisibility(0);
        ImageDisplay.getInstance().displayImageLoad(this.mStoreModel.getMainImgUrl(), (ImageView) findViewById(R.id.auto_branch_image));
        setLivePopupTimer();
    }

    /* access modifiers changed from: protected */
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        this.mPartnerSno = intent.getStringExtra("clientCode");
        if (this.mPartnerSno == null || true == this.mPartnerSno.isEmpty()) {
            finish(0, 0);
            return;
        }
        this.mStoreModel = (StoreModel) getIntent().getSerializableExtra("model");
        showPopup();
    }

    private boolean isLock() {
        return ((KeyguardManager) getSystemService("keyguard")).inKeyguardRestrictedInputMode();
    }

    public void onBackPressed() {
        if (this.mPopupLiveHandler != null) {
            this.mPopupLiveHandler.removeCallbacks(this.mPopupLiveRunnable);
        }
        finish(0, 0);
    }

    public void onClick(View view) {
        if (view == this.mBranchDetail) {
            if (this.mStoreModel.partnerSno != null && !this.mStoreModel.partnerSno.isEmpty()) {
                if (isRunningProcess(getBaseContext(), getBaseContext().getPackageName())) {
                    String shareUrl = "shareat://shareat.me/store?" + "partner_sno=" + this.mPartnerSno;
                    new CustomSchemeManager();
                    CustomSchemeManager.postSchemeAction(this, shareUrl);
                } else {
                    Intent i = new Intent(this, ExternalBridgeActivity.class);
                    i.setData(Uri.parse("shareat://shareat.me/store?" + "new_start=ok&partner_sno=" + this.mPartnerSno));
                    pushActivity(i);
                }
                finish(0, 0);
            }
        } else if (view == this.mQuickPay) {
            if (this.mStoreModel.partnerSno != null && !this.mStoreModel.partnerSno.isEmpty()) {
                if (isRunningProcess(getBaseContext(), getBaseContext().getPackageName())) {
                    String shareUrl2 = "shareat://shareat.me/store/payment?" + "partner_sno=" + this.mPartnerSno + "&open_password_view=Y";
                    new CustomSchemeManager();
                    CustomSchemeManager.postSchemeAction(this, shareUrl2);
                } else {
                    Intent i2 = new Intent(this, ExternalBridgeActivity.class);
                    i2.setData(Uri.parse("shareat://shareat.me/store/payment?" + "new_start=ok&partner_sno=" + this.mPartnerSno));
                    pushActivity(i2);
                }
                finish(0, 0);
            }
        } else if (view == this.mClose) {
            finish(0, 0);
        }
    }

    public void SetTestBranchInfo() {
        String coupon = null;
        TextView tvCoupon = (TextView) findViewById(R.id.auto_branch_coupon);
        TextView tvDiscount = (TextView) findViewById(R.id.auto_branch_discount);
        LinearLayout lrCoupon = (LinearLayout) findViewById(R.id.coupon_donwload_img);
        TextView tvBenefit = (TextView) findViewById(R.id.auto_branch_benefit);
        ((TextView) findViewById(R.id.auto_branch_partner_name1)).setText("\ud14c\uc2a4\ud2b8");
        String strBenefitText = "";
        tvBenefit.setVisibility(0);
        if (15 <= 0 || coupon == null || true == coupon.isEmpty() || true == coupon.equals("-")) {
            if (15 > 0) {
                findViewById(R.id.auto_branch_discount_layout).setVisibility(0);
                tvDiscount.setText(15 + "%");
                strBenefitText = String.format(getResources().getString(R.string.COMMON_DISCOUNT_BENEFIT_TEXT), new Object[]{Integer.valueOf(15)});
            } else {
                LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) ((LinearLayout) findViewById(R.id.auto_branch_contents)).getLayoutParams();
                if (lp != null) {
                    lp.topMargin = 0;
                }
                findViewById(R.id.auto_branch_discount_layout).setVisibility(8);
            }
            if (coupon == null || true == coupon.isEmpty() || true == coupon.equals("-")) {
                tvCoupon.setText("");
                tvCoupon.setVisibility(8);
                lrCoupon.setVisibility(8);
            } else {
                lrCoupon.setVisibility(0);
                tvCoupon.setVisibility(0);
                tvCoupon.setText(coupon + " \ubc1b\uae30");
                strBenefitText = String.format(getResources().getString(R.string.COMMON_COUPON_BENEFIT_TEXT), new Object[]{coupon});
            }
        } else {
            findViewById(R.id.auto_branch_discount_layout).setVisibility(0);
            tvDiscount.setText(15 + "%");
            strBenefitText = String.format(getResources().getString(R.string.COMMON_DUAL_BENEFIT_TEXT), new Object[]{Integer.valueOf(15), coupon});
            lrCoupon.setVisibility(0);
            tvCoupon.setVisibility(0);
            tvCoupon.setText(coupon + " \ubc1b\uae30");
        }
        tvBenefit.setText(strBenefitText);
    }

    public void SetBranchInfo() {
        String partnerName = this.mStoreModel.getPartnerName1();
        int discount = this.mStoreModel.getDcRate();
        String categoryName = this.mStoreModel.getCategoryName();
        String coupon = this.mStoreModel.getCouponName();
        LetterSpacingTextView tvPartnerName = (LetterSpacingTextView) findViewById(R.id.auto_branch_partner_name1);
        LetterSpacingTextView tvCoupon = (LetterSpacingTextView) findViewById(R.id.auto_branch_coupon);
        TextView tvDiscount = (TextView) findViewById(R.id.auto_branch_discount);
        LinearLayout lrCoupon = (LinearLayout) findViewById(R.id.coupon_donwload_img);
        LetterSpacingTextView tvBenefit = (LetterSpacingTextView) findViewById(R.id.auto_branch_benefit);
        tvPartnerName.setCustomLetterSpacing(-2.3f);
        tvPartnerName.setText(partnerName);
        tvBenefit.setCustomLetterSpacing(-2.6f);
        tvCoupon.setCustomLetterSpacing(-2.6f);
        String strBenefitText = this.mStoreModel.getCouponInfo();
        if (discount <= 0 || coupon == null || true == coupon.isEmpty() || true == coupon.equals("-")) {
            if (discount > 0) {
                tvBenefit.setVisibility(0);
                findViewById(R.id.auto_branch_discount_layout).setVisibility(0);
                tvDiscount.setText(discount + "%");
            } else {
                LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) findViewById(R.id.auto_branch_contents).getLayoutParams();
                if (lp != null) {
                    lp.topMargin = 0;
                }
                tvBenefit.setVisibility(8);
                findViewById(R.id.auto_branch_discount_layout).setVisibility(8);
            }
            if (coupon == null || true == coupon.isEmpty() || true == coupon.equals("-")) {
                tvCoupon.setText("");
                tvCoupon.setVisibility(8);
                lrCoupon.setVisibility(8);
            } else {
                lrCoupon.setVisibility(0);
                tvCoupon.setVisibility(0);
                tvCoupon.setText(coupon + " \ubc1b\uae30");
                tvBenefit.setVisibility(0);
            }
        } else {
            tvBenefit.setVisibility(0);
            findViewById(R.id.auto_branch_discount_layout).setVisibility(0);
            tvDiscount.setText(discount + "%");
            lrCoupon.setVisibility(0);
            tvCoupon.setVisibility(0);
            tvCoupon.setText(coupon + " \ubc1b\uae30");
        }
        if (strBenefitText == null || true == strBenefitText.isEmpty()) {
            tvBenefit.setVisibility(8);
        }
        tvBenefit.setText(strBenefitText);
    }

    public void onCouponDonwloadClick(View view) {
        updateUserCouponApi();
    }

    private void updateUserCouponApi() {
        RegistStoreCouponApi request = new RegistStoreCouponApi(getBaseContext());
        request.addParam("coupon_group_sno", this.mStoreModel.getCouponGroupSno());
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                BaseResultModel model = (BaseResultModel) result;
                if (model == null || model.getResult().equals("N")) {
                    Toast.makeText(BranchInfoActivity.this.getBaseContext(), "\ucfe0\ud3f0 \uc815\ubcf4 \uc694\uccad \uc2e4\ud328", 0).show();
                } else if (model.getResult().equals("Y")) {
                    Toast.makeText(BranchInfoActivity.this.getBaseContext(), "\ucfe0\ud3f0 \ub2e4\uc6b4\ub85c\ub4dc \uc644\ub8cc", 0).show();
                    EventBus.getDefault().post(new CouponUpdateEvent());
                } else if (model.getResult().equals("O")) {
                    Toast.makeText(BranchInfoActivity.this.getBaseContext(), "\uc774\ubbf8 \ubc1c\uae09\ubc1b\uc73c\uc2e0 \ucfe0\ud3f0 \uc785\ub2c8\ub2e4.", 0).show();
                }
            }

            public void onFailure(Exception exception) {
                Toast.makeText(BranchInfoActivity.this.getBaseContext(), "\ucfe0\ud3f0 \uc815\ubcf4 \uc694\uccad \uc2e4\ud328", 0).show();
            }
        });
    }

    private void SetNotification() {
        Notification noti;
        Intent pushIntent = new Intent(getBaseContext(), ExternalBridgeActivity.class);
        pushIntent.setFlags(131072);
        pushIntent.setData(Uri.parse("shareat://shareat.me/store?" + "new_start=ok&partner_sno=" + this.mPartnerSno));
        PendingIntent pi = PendingIntent.getActivity(getBaseContext(), 0, pushIntent, 134217728);
        String content = this.mStoreModel.partnerName1 + "\uc744(\ub97c) \ubc29\ubb38\ud558\uc168\uc2b5\ub2c8\uae4c?";
        NotificationManager notiMgr = (NotificationManager) getBaseContext().getSystemService("notification");
        Builder builder = new Builder(this);
        Notification noti2 = builder.setSmallIcon(R.drawable.noti).setVisibility(1).setTicker("\uc250\uc5b4\uc573").setWhen(System.currentTimeMillis()).setAutoCancel(true).setContentTitle("\uc250\uc5b4\uc573").setContentText(content).setContentIntent(pi).setDefaults(3).setColor(Color.parseColor("#1198f7")).build();
        if (VERSION.SDK_INT >= 18) {
            noti = builder.build();
        } else {
            noti = builder.getNotification();
        }
        notiMgr.notify(5, noti);
    }

    public boolean isRunningProcess(Context context, String packageName) {
        for (RunningAppProcessInfo rap : ((ActivityManager) context.getSystemService("activity")).getRunningAppProcesses()) {
            if (rap.processName.equals(packageName)) {
                return true;
            }
        }
        return false;
    }
}