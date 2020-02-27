package com.nuvent.shareat.widget.view;

import android.app.Activity;
import android.app.AlertDialog.Builder;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.menu.CouponActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.CouponApi;
import com.nuvent.shareat.event.CircleDialogEvent;
import com.nuvent.shareat.event.CouponListEvent;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import net.xenix.android.widget.FontEditTextView;
import net.xenix.android.widget.FontEditTextView.EditTextListener;

public class CouponHeaderView extends FrameLayout {
    FontEditTextView couponFiled01;
    private boolean isChange = false;
    /* access modifiers changed from: private */
    public Context mContext;
    EditTextListener mListener = new EditTextListener() {
        public void onImeBack(FontEditTextView ctrl, String text) {
            CouponHeaderView.this.setHint();
        }

        public boolean onTextContextMenuItem(int id) {
            return false;
        }

        public boolean onSuggestionsEnabled() {
            return false;
        }
    };

    public CouponHeaderView(Context context) {
        super(context);
        init(context);
    }

    public CouponHeaderView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public CouponHeaderView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        this.mContext = context;
        View.inflate(context, R.layout.view_coupon_header, this);
        ((Button) findViewById(R.id.confirmCouponButton)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (CouponHeaderView.this.couponFiled01.getText().toString().isEmpty()) {
                    Toast.makeText(CouponHeaderView.this.getContext(), "\ucfe0\ud3f0 \ucf54\ub4dc\ub97c \uc785\ub825\ud574\uc8fc\uc138\uc694.", 0).show();
                } else {
                    CouponHeaderView.this.requestRegistCouponApi();
                }
            }
        });
        ((TextView) findViewById(R.id.couponLabel)).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                CouponHeaderView.this.findViewById(R.id.couponFiledLayout).setVisibility(0);
                EditText couponFiled01 = (EditText) CouponHeaderView.this.findViewById(R.id.couponFiled01);
                couponFiled01.requestFocus();
                Context access$100 = CouponHeaderView.this.mContext;
                CouponHeaderView.this.mContext;
                ((InputMethodManager) access$100.getSystemService("input_method")).showSoftInput(couponFiled01, 0);
            }
        });
        this.couponFiled01 = (FontEditTextView) findViewById(R.id.couponFiled01);
        this.couponFiled01.setEditTextListener(this.mListener);
    }

    public void setUseableCoupon(int count) {
        ((TextView) findViewById(R.id.countCouponLabel)).setText(count + "");
    }

    /* access modifiers changed from: private */
    public void requestRegistCouponApi() {
        String couponNo = this.couponFiled01.getText().toString();
        if (couponNo.trim().length() == 0) {
            ((BaseActivity) getContext()).showDialog("\ucfe0\ud3f0 \ubc88\ud638\ub97c \uc785\ub825\ud574 \uc8fc\uc138\uc694");
            return;
        }
        CouponApi request = new CouponApi(this.mContext);
        request.addParam("coupon_sn", couponNo);
        request.request(new RequestHandler() {
            public void onStart() {
                EventBus.getDefault().post(new CircleDialogEvent(true));
            }

            public void onResult(Object result) {
                EventBus.getDefault().post(new CircleDialogEvent(false));
                BaseResultModel model = (BaseResultModel) result;
                if ("Y".equals(model.getResult())) {
                    CouponHeaderView.this.showDialog(CouponHeaderView.this.getResources().getString(R.string.COUPON_OK));
                    CouponHeaderView.this.couponFiled01.setText("");
                    EventBus.getDefault().post(new CouponListEvent());
                    GAEvent.onGaEvent((Activity) (CouponActivity) CouponHeaderView.this.getContext(), (int) R.string.ga_my_coupon, (int) R.string.ga_ev_reg, (int) R.string.ga_mycoupon_regist);
                } else if ("N".equals(model.getResult())) {
                    CouponHeaderView.this.showDialog(CouponHeaderView.this.getResources().getString(R.string.COUPON_FAIL));
                } else if (AppEventsConstants.EVENT_PARAM_VALUE_NO.equals(model.getResult())) {
                    CouponHeaderView.this.showDialog(CouponHeaderView.this.getResources().getString(R.string.COUPON_LIMITATION));
                } else if ("D".equals(model.getResult())) {
                    CouponHeaderView.this.showDialog(CouponHeaderView.this.getResources().getString(R.string.COUPON_SAVE));
                }
            }

            public void onFailure(Exception exception) {
                EventBus.getDefault().post(new CircleDialogEvent(false));
            }

            public void onFinish() {
                EventBus.getDefault().post(new CircleDialogEvent(false));
            }
        });
    }

    public void showDialog(String message) {
        try {
            new Builder(this.mContext).setTitle("\uc54c\ub9bc").setMessage(message).setPositiveButton("\ud655\uc778", null).setCancelable(false).create().show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void setHint() {
        if (this.couponFiled01.getText().toString().equals("")) {
            findViewById(R.id.couponFiledLayout).setVisibility(8);
        }
    }
}