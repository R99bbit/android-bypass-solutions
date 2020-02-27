package com.nuvent.shareat.dialog;

import android.content.Context;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.TextView;
import android.widget.Toast;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.api.CouponGroupInfoApi;
import com.nuvent.shareat.api.RegistStoreCouponApi;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.event.CouponUpdateEvent;
import com.nuvent.shareat.manager.sns.BaseSnsManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.CouponDetailModel;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import net.xenix.util.FormatUtil;

public class CouponMapDialog extends BaseDialog {
    private String mCouponName;
    private String mCouponSno;
    /* access modifiers changed from: private */
    public onClickDialog mListener;
    /* access modifiers changed from: private */
    public CouponDetailModel mModel;
    /* access modifiers changed from: private */
    public View mRootView;

    public interface onClickDialog {
        void onClickDownload();

        void onClickDownloadSkip();
    }

    public CouponMapDialog(Context context, String couponName, String couponSno) {
        super(context);
        this.mCouponName = couponName;
        this.mCouponSno = couponSno;
        init();
        GAEvent.onGAScreenView((MainActivity) context, R.string.ga_nmap_coupon_download_screen);
    }

    private void init() {
        this.mRootView = View.inflate(getContext(), R.layout.dialog_map_coupon, null);
        this.mRootView.findViewById(R.id.coupon_download).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                CouponMapDialog.this.mListener.onClickDownload();
                CouponMapDialog.this.requestGetCouponApi();
            }
        });
        this.mRootView.findViewById(R.id.coupon_download_skip).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                CouponMapDialog.this.mListener.onClickDownloadSkip();
                CouponMapDialog.this.dismiss();
            }
        });
        setCanceledOnTouchOutside(true);
        setContentView(this.mRootView);
        requestCouponInfoApi();
        this.mRootView.findViewById(R.id.hideView).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                CouponMapDialog.this.dismiss();
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestGetCouponApi() {
        RegistStoreCouponApi request = new RegistStoreCouponApi(getContext());
        request.addParam("coupon_group_sno", this.mCouponSno);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                BaseResultModel model = (BaseResultModel) result;
                if (model == null || model.getResult().equals("N")) {
                    Toast.makeText(CouponMapDialog.this.getContext(), "\ucfe0\ud3f0 \uc815\ubcf4 \uc694\uccad \uc2e4\ud328", 0).show();
                    CouponMapDialog.this.dismiss();
                } else if (model.getResult().equals("Y")) {
                    Toast.makeText(CouponMapDialog.this.getContext(), "\ucfe0\ud3f0 \ub2e4\uc6b4\ub85c\ub4dc \uc644\ub8cc", 0).show();
                    CouponMapDialog.this.dismiss();
                    EventBus.getDefault().post(new CouponUpdateEvent());
                } else if (model.getResult().equals("O")) {
                    Toast.makeText(CouponMapDialog.this.getContext(), "\uc774\ubbf8 \ubc1c\uae09\ubc1b\uc73c\uc2e0 \ucfe0\ud3f0 \uc785\ub2c8\ub2e4.", 0).show();
                    CouponMapDialog.this.dismiss();
                }
            }

            public void onFailure(Exception exception) {
                Toast.makeText(CouponMapDialog.this.getContext(), "\ucfe0\ud3f0 \uc815\ubcf4 \uc694\uccad \uc2e4\ud328", 0).show();
                CouponMapDialog.this.dismiss();
            }
        });
    }

    private void requestCouponInfoApi() {
        CouponGroupInfoApi request = new CouponGroupInfoApi(getContext());
        request.addParam("coupon_group_sno", this.mCouponSno);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                String couponValue;
                CouponMapDialog.this.mModel = (CouponDetailModel) result;
                if (CouponMapDialog.this.mModel == null || !CouponMapDialog.this.mModel.getResult().equals("Y")) {
                    Toast.makeText(CouponMapDialog.this.getContext(), "\ucfe0\ud3f0 \uc815\ubcf4 \uc694\uccad \uc2e4\ud328", 0).show();
                    CouponMapDialog.this.dismiss();
                    return;
                }
                ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.titleLabel)).setText(CouponMapDialog.this.mModel.getCoupon_name());
                ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.descriptionLabel)).setText(FormatUtil.onDecimalFormat(CouponMapDialog.this.mModel.getMin_condition()) + "\uc6d0 \uc774\uc0c1 \uacb0\uc81c\uc2dc, \uc571\uacb0\uc81c\uace0\uac1d\uc5d0 \ud55c\ud568");
                ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.usePlaceLabel)).setText("\ucfe0\ud3f0\uc0ac\uc6a9\ucc98 : " + CouponMapDialog.this.mModel.getUsable_partner_name());
                if (CouponMapDialog.this.mModel.getCoupon_type().equals("10")) {
                    couponValue = "\uc6d0 \ud560\uc778";
                } else {
                    couponValue = "% \ud560\uc778";
                }
                ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.couponPriceLabel)).setText(FormatUtil.onDecimalFormat(CouponMapDialog.this.mModel.getDiscount_value()));
                ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.couponNameLabel)).setText(couponValue);
                try {
                    ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.couponCountLabel)).setText(String.valueOf(CouponMapDialog.this.mModel.getRemain_cnt()));
                } catch (NumberFormatException e) {
                    ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.couponCountLabel)).setText(AppEventsConstants.EVENT_PARAM_VALUE_NO);
                }
                if (CouponMapDialog.this.mModel.getExpire_type() == null || CouponMapDialog.this.mModel.getExpire_type().equals(BaseSnsManager.SNS_LOGIN_TYPE_FACEBOOK)) {
                    ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.dateLabel)).setText("\uc0ac\uc6a9\uae30\ud55c : \ub2e4\uc6b4\ub85c\ub4dc \ud6c4 " + CouponMapDialog.this.mModel.getExpire_period() + "\uc77c \uc774\ub0b4");
                } else {
                    ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.dateLabel)).setText("\uc720\ud6a8\uae30\uac04 : ~ " + CouponMapDialog.this.mModel.getAfter_down_expire_date() + "\uae4c\uc9c0");
                }
                ((TextView) CouponMapDialog.this.mRootView.findViewById(R.id.couponExpireDateLabel)).setText("~ " + CouponMapDialog.this.mModel.getDown_end_date() + "\uae4c\uc9c0");
            }

            public void onFailure(Exception exception) {
                Toast.makeText(CouponMapDialog.this.getContext(), "\ucfe0\ud3f0 \uc815\ubcf4 \uc694\uccad \uc2e4\ud328", 0).show();
                CouponMapDialog.this.dismiss();
            }
        });
    }

    public void setOnClickDialogListener(onClickDialog listener) {
        this.mListener = listener;
    }
}