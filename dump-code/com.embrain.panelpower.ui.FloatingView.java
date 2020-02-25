package com.embrain.panelpower.ui;

import android.content.Context;
import android.content.Intent;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.animation.Animation;
import android.view.animation.Animation.AnimationListener;
import android.view.animation.AnimationUtils;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.embrain.panelpower.AgreeActivity;
import com.embrain.panelpower.R;
import com.embrain.panelpower.UserInfoManager;

public class FloatingView extends LinearLayout {
    /* access modifiers changed from: private */
    public static boolean mFlagClick = false;
    /* access modifiers changed from: private */
    public int mAgreeType = -1;
    private View mBodyFloat;
    /* access modifiers changed from: private */
    public View mBodyText;
    private View mIcon;
    private TextView mTv1;

    public FloatingView(Context context) {
        super(context);
        init(context);
    }

    public FloatingView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        init(context);
    }

    private void init(Context context) {
        View inflate = ((LayoutInflater) context.getSystemService("layout_inflater")).inflate(R.layout.view_floating, null);
        this.mBodyText = inflate.findViewById(R.id.body_text);
        this.mBodyFloat = inflate.findViewById(R.id.body_float);
        this.mIcon = inflate.findViewById(R.id.ic_float);
        this.mTv1 = (TextView) inflate.findViewById(R.id.tv_float1);
        this.mBodyFloat.setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                FloatingView.mFlagClick = true;
                FloatingView.this.setVisibility(8);
                Intent intent = new Intent(FloatingView.this.getContext(), AgreeActivity.class);
                intent.putExtra(AgreeActivity.EXTRA_AGREE_TYPE, FloatingView.this.mAgreeType);
                intent.putExtra(AgreeActivity.EXTRA_FROM_FLOATING, true);
                FloatingView.this.getContext().startActivity(intent);
            }
        });
        inflate.findViewById(R.id.btn_close).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                FloatingView.mFlagClick = true;
                FloatingView.this.setVisibility(8);
                int access$100 = FloatingView.this.mAgreeType;
                if (access$100 == 1) {
                    UserInfoManager.addFloatDeniedCntPay(FloatingView.this.getContext());
                } else if (access$100 == 2) {
                    UserInfoManager.addFloatDeniedCntUsage(FloatingView.this.getContext());
                } else if (access$100 == 3) {
                    UserInfoManager.addFloatDeniedCntLocation(FloatingView.this.getContext());
                } else if (access$100 == 4) {
                    UserInfoManager.addFloatDeniedCntPush(FloatingView.this.getContext());
                }
            }
        });
        addView(inflate);
    }

    public void show() {
        Context context = getContext();
        if (!mFlagClick) {
            if (AgreeActivity.showPay(context, false) && UserInfoManager.getFloatDeniedCntPay(context) < 2) {
                this.mAgreeType = 1;
                this.mIcon.setBackgroundResource(R.drawable.icon_banner1);
                this.mTv1.setText("\uc18c\ube44\uc790 \uc870\uc0ac");
            } else if (!AgreeActivity.showUsage(context, false) || UserInfoManager.getFloatDeniedCntUsage(context) >= 2) {
                if (AgreeActivity.showLocation(context, false) && UserInfoManager.getFloatDeniedCntLocation(context) < 2) {
                    this.mAgreeType = 3;
                    this.mIcon.setBackgroundResource(R.drawable.icon_banner2);
                    this.mTv1.setText("\uc704\uce58 \uc870\uc0ac");
                }
            } else {
                this.mAgreeType = 2;
                this.mIcon.setBackgroundResource(R.drawable.icon_banner3);
                this.mTv1.setText("\uc571 \uc870\uc0ac");
            }
            setVisibility(0);
            this.mBodyText.setVisibility(0);
            postDelayed(new Runnable() {
                public void run() {
                    FloatingView.this.hide();
                }
            }, 2000);
        }
    }

    public void hide() {
        Animation loadAnimation = AnimationUtils.loadAnimation(getContext(), R.anim.anim_scale);
        loadAnimation.setAnimationListener(new AnimationListener() {
            public void onAnimationRepeat(Animation animation) {
            }

            public void onAnimationStart(Animation animation) {
            }

            public void onAnimationEnd(Animation animation) {
                FloatingView.this.mBodyText.setVisibility(8);
            }
        });
        this.mBodyText.startAnimation(loadAnimation);
    }
}