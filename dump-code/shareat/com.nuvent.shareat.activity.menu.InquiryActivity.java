package com.nuvent.shareat.activity.menu;

import android.animation.ObjectAnimator;
import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.animation.AnimationUtils;
import android.view.animation.DecelerateInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import android.widget.TextView;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.FaqTypeApi;
import com.nuvent.shareat.api.common.RegistInquiryApi;
import com.nuvent.shareat.dialog.InputConfirmDialog;
import com.nuvent.shareat.dialog.InputConfirmDialog.onOkClickListener;
import com.nuvent.shareat.dialog.InquiryTypeDialog;
import com.nuvent.shareat.dialog.InquiryTypeDialog.DialogClickListener;
import com.nuvent.shareat.dialog.TermsDialog;
import com.nuvent.shareat.fragment.WebViewFragment;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.FaqTypeModel;
import com.nuvent.shareat.model.FaqTypeResultModel;
import com.nuvent.shareat.util.GAEvent;

public class InquiryActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public FaqTypeModel mCurrentModel;
    /* access modifiers changed from: private */
    public FaqTypeResultModel mModel;
    private View mSlideView;
    private int mSlideViewWidth;
    private String mUrl;
    private WebViewFragment mWebViewFragment;

    public void onClickTab(View view) {
        switch (view.getId()) {
            case R.id.listTab /*2131296798*/:
                if (findViewById(R.id.listLayout).getVisibility() != 0) {
                    findViewById(R.id.writeLayout).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_out));
                    findViewById(R.id.writeLayout).setVisibility(8);
                    findViewById(R.id.listLayout).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
                    findViewById(R.id.listLayout).setVisibility(0);
                    animateSlideView((float) this.mSlideViewWidth);
                    if (getIntent().hasExtra("url")) {
                        this.mWebViewFragment.setUrl(this.mUrl);
                        this.mWebViewFragment.loadWebView();
                        getIntent().removeExtra("url");
                        return;
                    }
                    this.mWebViewFragment.refresh();
                    return;
                }
                return;
            case R.id.writeTab /*2131297509*/:
                if (findViewById(R.id.writeLayout).getVisibility() != 0) {
                    findViewById(R.id.writeLayout).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
                    findViewById(R.id.writeLayout).setVisibility(0);
                    findViewById(R.id.listLayout).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_out));
                    findViewById(R.id.listLayout).setVisibility(8);
                    animateSlideView(0.0f);
                    return;
                }
                return;
            default:
                return;
        }
    }

    public void onClickMenu(View view) {
        InquiryTypeDialog dialog = new InquiryTypeDialog(this, this.mModel.getResult_list());
        dialog.setOnDialogClickListener(new DialogClickListener() {
            public void onClickType(FaqTypeModel model) {
                InquiryActivity.this.mCurrentModel = model;
                InquiryActivity.this.setFaqTypeView();
            }

            public void onDismiss() {
            }
        });
        dialog.show();
    }

    public void onClickEmailEdit(View view) {
        InputConfirmDialog dialog = new InputConfirmDialog(this, "\uc774\uba54\uc77c\uc744 \uc785\ub825\ud574\uc8fc\uc138\uc694.", ((TextView) findViewById(R.id.emailLabel)).getText().toString().trim());
        dialog.setOnOkClickListener(new onOkClickListener() {
            public void onClick(InputConfirmDialog dialog, String email) {
                ((TextView) InquiryActivity.this.findViewById(R.id.emailLabel)).setText(email);
            }
        });
        dialog.show();
    }

    public void onClickCheck(View view) {
        view.setSelected(!view.isSelected());
    }

    public void onClickTerms(View view) {
        new TermsDialog(this, ApiUrl.TERMS_PAY_04).show();
    }

    public void onClickSend(View view) {
        if (!findViewById(R.id.checkView).isSelected()) {
            Toast.makeText(this, "\uac1c\uc778\uc815\ubcf4 \ucde8\uae09\ubc29\uce68\uc5d0 \ub3d9\uc758\ud558\uc154\uc57c \ud569\ub2c8\ub2e4.", 0).show();
        } else if (((EditText) findViewById(R.id.inputField)).getText().toString().trim().isEmpty()) {
            Toast.makeText(this, "\ubb38\uc758 \ub0b4\uc6a9\uc744 \uc785\ub825\ud574\uc8fc\uc138\uc694.", 0).show();
        } else {
            requestInquiryApi(((EditText) findViewById(R.id.inputField)).getText().toString().trim());
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_inquiry, 2);
        showFavoriteButton(false);
        showSubActionbar();
        setTitle("1:1\ubb38\uc758");
        this.mUrl = String.format(ApiUrl.QNA_URL, new Object[]{SessionManager.getInstance().getAuthToken()});
        setSlideView();
        this.mWebViewFragment = new WebViewFragment();
        if (getIntent().hasExtra("url")) {
            this.mWebViewFragment.setUrl(getIntent().getStringExtra("url"));
        } else {
            this.mWebViewFragment.setUrl(this.mUrl);
        }
        getSupportFragmentManager().beginTransaction().add((int) R.id.listLayout, (Fragment) this.mWebViewFragment).commit();
        findViewById(R.id.listLayout).setVisibility(8);
        ((TextView) findViewById(R.id.emailLabel)).setText(SessionManager.getInstance().getUserModel().getEmail());
        requestFaqTypeApi();
        if (getIntent().hasExtra("url")) {
            findViewById(R.id.writeLayout).setVisibility(8);
            findViewById(R.id.listLayout).setVisibility(0);
            animateSlideView((float) this.mSlideViewWidth);
        }
    }

    /* access modifiers changed from: private */
    public void setFaqTypeView() {
        ((TextView) findViewById(R.id.typeLabel)).setText(this.mCurrentModel.getCode_name());
        ((EditText) findViewById(R.id.inputField)).setText(this.mCurrentModel.getDescription());
    }

    private void setSlideView() {
        DisplayMetrics displaymetrics = new DisplayMetrics();
        getWindowManager().getDefaultDisplay().getMetrics(displaymetrics);
        this.mSlideViewWidth = displaymetrics.widthPixels / 2;
        LayoutParams params = new LayoutParams(this.mSlideViewWidth, -1);
        this.mSlideView = new View(this);
        this.mSlideView.setLayoutParams(params);
        this.mSlideView.setBackgroundColor(Color.parseColor("#ff6385E6"));
        ((FrameLayout) findViewById(R.id.slideLayout)).addView(this.mSlideView);
    }

    private void animateSlideView(float from) {
        ObjectAnimator translationAnimation = ObjectAnimator.ofFloat(this.mSlideView, "translationX", new float[]{this.mSlideView.getX(), from});
        translationAnimation.setDuration(150);
        translationAnimation.setInterpolator(new DecelerateInterpolator());
        translationAnimation.start();
    }

    /* access modifiers changed from: private */
    public void requestInquiryApi(final String inputText) {
        RegistInquiryApi request = new RegistInquiryApi(this);
        request.addParam("board_gubun", "QNA");
        request.addParam("gubun", this.mCurrentModel.getCode_id());
        request.addParam("title", ((TextView) findViewById(R.id.typeLabel)).getText().toString().trim());
        request.addParam("contents", inputText);
        request.request(new RequestHandler() {
            public void onStart() {
                InquiryActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                InquiryActivity.this.showCircleDialog(false);
                if (((BaseResultModel) result).getResult().equals("Y")) {
                    GAEvent.onGaEvent((Activity) InquiryActivity.this, (int) R.string.ga_qna_board, (int) R.string.ga_qnaboard_register, (int) R.string.ga_ev_reg);
                    InquiryActivity.this.setFaqTypeView();
                    ((TextView) InquiryActivity.this.findViewById(R.id.emailLabel)).setText(SessionManager.getInstance().getUserModel().getEmail());
                    InquiryActivity.this.findViewById(R.id.checkView).setSelected(false);
                    InquiryActivity.this.findViewById(R.id.listTab).performClick();
                }
            }

            public void onFailure(Exception exception) {
                InquiryActivity.this.showCircleDialog(false);
                InquiryActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        InquiryActivity.this.requestInquiryApi(inputText);
                    }
                });
            }

            public void onFinish() {
                InquiryActivity.this.showCircleDialog(false);
            }
        });
    }

    private void requestFaqTypeApi() {
        new FaqTypeApi(this).request(new RequestHandler() {
            public void onStart() {
                InquiryActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                InquiryActivity.this.showCircleDialog(false);
                InquiryActivity.this.mModel = (FaqTypeResultModel) result;
                InquiryActivity.this.mCurrentModel = InquiryActivity.this.mModel.getResult_list().get(0);
                InquiryActivity.this.setFaqTypeView();
            }

            public void onFailure(Exception exception) {
                InquiryActivity.this.showCircleDialog(false);
            }

            public void onFinish() {
                InquiryActivity.this.showCircleDialog(false);
            }
        });
    }
}