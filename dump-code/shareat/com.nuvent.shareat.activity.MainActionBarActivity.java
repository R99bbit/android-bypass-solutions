package com.nuvent.shareat.activity;

import android.animation.Animator;
import android.animation.Animator.AnimatorListener;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.BitmapDrawable;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnTouchListener;
import android.view.animation.AnimationUtils;
import android.view.animation.DecelerateInterpolator;
import android.view.inputmethod.InputMethodManager;
import android.widget.FrameLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import android.widget.Toast;
import com.igaworks.adbrix.util.CPEConstant;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.common.CardRegistActivity;
import com.nuvent.shareat.activity.main.ActionGuideActivity;
import com.nuvent.shareat.activity.main.DeliveryActivity;
import com.nuvent.shareat.activity.menu.AddAddressActivity;
import com.nuvent.shareat.event.CardSlideEvent;
import com.nuvent.shareat.event.MainOnEvent;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.view.BarcodeView;
import com.nuvent.shareat.widget.view.CardView;
import de.greenrobot.event.EventBus;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Map;
import net.xenix.android.widget.FontTextView;
import net.xenix.android.widget.LetterSpacingTextView;

public class MainActionBarActivity extends BaseActivity {
    public static final int ACTIONBAR_TYPE_GATEWAY = 6;
    public static final int ACTIONBAR_TYPE_MAIN = 1;
    public static final int ACTIONBAR_TYPE_MODAL = 3;
    public static final int ACTIONBAR_TYPE_NEXT = 2;
    public static final int ACTIONBAR_TYPE_PAYMENT = 4;
    public static final int ACTIONBAR_TYPE_PAYMENT_DETAIL = 5;
    public static final int ACTIONBAR_TYPE_SEARCH = 153;
    public static final int ADD_ADDRESS_INTENT = 17;
    public static final int QUICKPAYACTIVITY_RESULT_CODE = 1100;
    private OnTouchListener cardViewTouch = new OnTouchListener() {
        public boolean onTouch(View v, MotionEvent motionEvent) {
            switch (motionEvent.getActionMasked()) {
                case 0:
                    MainActionBarActivity.this.mDownY = motionEvent.getRawY();
                    return true;
                case 1:
                    if (!SessionManager.getInstance().hasSession()) {
                        MainActionBarActivity.this.showLoginDialog();
                    }
                    float deltaY = motionEvent.getRawY() - MainActionBarActivity.this.mDownY;
                    if (0.0f <= deltaY || MainActionBarActivity.this.isOpenCardView()) {
                        if (0.0f >= deltaY || !MainActionBarActivity.this.isOpenCardView()) {
                            if (!MainActionBarActivity.this.isOpenCardView()) {
                                MainActionBarActivity.this.openCardView();
                                break;
                            } else {
                                MainActionBarActivity.this.closeCardView();
                                break;
                            }
                        } else {
                            MainActionBarActivity.this.closeCardView();
                            break;
                        }
                    } else {
                        MainActionBarActivity.this.openCardView();
                        break;
                    }
                    break;
            }
            return false;
        }
    };
    private boolean isMain = true;
    private boolean isNextFragment;
    private boolean isShowCardView;
    protected OnAnimationListener mAnimationListener;
    /* access modifiers changed from: private */
    public float mDownY;
    /* access modifiers changed from: protected */
    public boolean mIsMapMode = false;
    /* access modifiers changed from: private */
    public PopupWindow mPopupWindow;
    private int mScreenHeight;

    public interface OnAnimationListener {
        void OnOpenCardView();
    }

    public void onClickBack(View view) {
        finish();
    }

    public void onClickLogo(View view) {
        setMainView(false);
        EventBus.getDefault().post(new MainOnEvent());
    }

    public void onClickCloseCard(View view) {
        closeCardView();
        if (!((CardView) findViewById(R.id.cardView)).getStoreClick()) {
            ((CardView) findViewById(R.id.cardView)).clearStoreModel();
        }
        hideKeyboard();
    }

    public void setCardCloseViewVisiblity(boolean isVisibility) {
        findViewById(R.id.closeCardButton).setVisibility(isVisibility ? 0 : 8);
    }

    public void onFriendButton(View view) {
        animActivityForResult(new Intent(this, AddAddressActivity.class), 17, R.anim.slide_from_right, R.anim.slide_out_to_left);
    }

    public void onClickKakaoShare(View view) {
    }

    public void onClickSearch(View view) {
    }

    public void setMain(boolean isMain2) {
        this.isMain = isMain2;
    }

    public void onClickLocation(View view) {
        this.isMain = false;
        setGngButton(view.getId());
        if (8 != findViewById(R.id.cardView).getVisibility()) {
            findViewById(R.id.topButton).setOnClickListener(null);
            findViewById(R.id.cardView).startAnimation(AnimationUtils.loadAnimation(this, R.anim.abc_slide_out_bottom));
            findViewById(R.id.cardView).setVisibility(8);
        }
    }

    public void onClickCategory(View view) {
        this.isMain = false;
        setGngButton(view.getId());
        if (8 != findViewById(R.id.cardView).getVisibility()) {
            findViewById(R.id.topButton).setOnClickListener(null);
            findViewById(R.id.cardView).startAnimation(AnimationUtils.loadAnimation(this, R.anim.abc_slide_out_bottom));
            findViewById(R.id.cardView).setVisibility(8);
        }
    }

    public void onClickTitle(View view) {
        finish();
    }

    public void setMainView(boolean isShowCardView2) {
        findViewById(R.id.locationButton).setSelected(false);
        findViewById(R.id.headerMapBtn).setSelected(false);
        findViewById(R.id.headerListBtn).setSelected(false);
        findViewById(R.id.categoryButton).setSelected(false);
        if (!this.isMain) {
            this.isMain = true;
            if (this.mAnimationListener != null && true == isShowCardView2) {
                this.mAnimationListener.OnOpenCardView();
            }
        }
    }

    public void showCardViewAnimation() {
        if (!this.mIsMapMode) {
            if (!((CardView) findViewById(R.id.cardView)).isPayingMode()) {
                findViewById(R.id.cardView).startAnimation(AnimationUtils.loadAnimation(this, R.anim.abc_slide_in_bottom));
                findViewById(R.id.cardView).setVisibility(0);
                findViewById(R.id.topButton).setOnTouchListener(this.cardViewTouch);
            }
            if (findViewById(R.id.map_btn) != null && 0.0f < findViewById(R.id.map_btn).getY()) {
                findViewById(R.id.map_btn).animate().setDuration(400).translationY(0.0f);
            }
        }
    }

    public void animateCardLayout(boolean isVisible) {
        if (this.isMain) {
            int translationMapBtn = -1;
            if (isVisible) {
                if (findViewById(R.id.cardView).getVisibility() != 0) {
                    findViewById(R.id.cardView).startAnimation(AnimationUtils.loadAnimation(this, R.anim.abc_slide_in_bottom));
                    findViewById(R.id.cardView).setVisibility(0);
                    findViewById(R.id.topButton).setVisibility(0);
                    findViewById(R.id.topButton).setOnTouchListener(this.cardViewTouch);
                    translationMapBtn = 0;
                    if (this.mAnimationListener != null) {
                        this.mAnimationListener.OnOpenCardView();
                    }
                }
            } else if (8 != findViewById(R.id.cardView).getVisibility()) {
                findViewById(R.id.topButton).setOnTouchListener(null);
                findViewById(R.id.cardView).startAnimation(AnimationUtils.loadAnimation(this, R.anim.abc_slide_out_bottom));
                findViewById(R.id.cardView).setVisibility(8);
                translationMapBtn = getResources().getDimensionPixelOffset(R.dimen.ACTIONBAR_HEIGHT);
            }
            if (!this.mIsMapMode && translationMapBtn >= 0 && findViewById(R.id.map_btn) != null && 0.0f < findViewById(R.id.map_btn).getY()) {
                findViewById(R.id.map_btn).animate().setDuration(400).translationY((float) translationMapBtn);
            }
        }
    }

    public void animateActionbarLayout(boolean isVisible) {
        if (isVisible) {
            if (findViewById(R.id.nextLayout).getVisibility() != 0) {
                setIsNextFragment(true);
                findViewById(R.id.nextLayout).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
                findViewById(R.id.nextLayout).setVisibility(0);
            }
        } else if (8 != findViewById(R.id.nextLayout).getVisibility()) {
            setIsNextFragment(false);
            findViewById(R.id.nextLayout).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_out));
            findViewById(R.id.nextLayout).setVisibility(8);
        }
    }

    public void showFavoriteButton(boolean isVisible) {
        if (isVisible) {
            findViewById(R.id.favoriteButton).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
            findViewById(R.id.favoriteButton).setVisibility(0);
            return;
        }
        findViewById(R.id.favoriteButton).setVisibility(8);
    }

    public void setFavoriteButton(boolean isFavorite) {
        findViewById(R.id.favoriteButton).setSelected(isFavorite);
    }

    public void showKakaoButton(boolean isVisible) {
        if (isVisible) {
            findViewById(R.id.kakaoShareButton).setVisibility(0);
        } else {
            findViewById(R.id.kakaoShareButton).setVisibility(8);
        }
    }

    public void showFriendButton(boolean isFriend) {
        if (isFriend) {
            findViewById(R.id.friendButton).setVisibility(0);
        } else {
            findViewById(R.id.friendButton).setVisibility(8);
        }
    }

    public void showBackButton(boolean isVisible) {
        if (isVisible) {
            findViewById(R.id.backButton).setVisibility(0);
        } else {
            findViewById(R.id.backButton).setVisibility(4);
        }
    }

    public void setTitle(String title) {
        ((TextView) findViewById(R.id.titleLabel)).setText(title);
    }

    public void showActionBar() {
        findViewById(R.id.titleLayout).setVisibility(0);
    }

    public void hideActionBar() {
        findViewById(R.id.titleLayout).setVisibility(8);
    }

    public void setFragmentTitle(String title) {
        ((TextView) findViewById(R.id.fragmentTitleLabel)).setText(title);
    }

    public void setIsNextFragment(boolean isNext) {
        this.isNextFragment = isNext;
    }

    public boolean isNextFragment() {
        return this.isNextFragment;
    }

    public boolean isOpenCardView() {
        return this.isShowCardView;
    }

    /* access modifiers changed from: protected */
    public void showSubActionbar() {
        findViewById(R.id.statusView).setBackgroundColor(getResources().getColor(R.color.BASE_COLOR));
        findViewById(R.id.titleLayout).setBackgroundColor(getResources().getColor(R.color.BASE_COLOR));
    }

    /* access modifiers changed from: protected */
    public void setContentView(int laytoutResId, int actionbarType) {
        if (1 == actionbarType) {
            super.setContentView(R.layout.activity_actionbar_main);
        } else if (6 == actionbarType) {
            super.setContentView(R.layout.activity_actionbar_main);
        } else {
            super.setContentView(R.layout.activity_actionbar);
        }
        findViewById(R.id.dimView).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                MainActionBarActivity.this.closeBarcodeView();
            }
        });
        findViewById(R.id.barcodeViewCloseButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                MainActionBarActivity.this.closeBarcodeView();
            }
        });
        DisplayMetrics displaymetrics = new DisplayMetrics();
        getWindowManager().getDefaultDisplay().getMetrics(displaymetrics);
        this.mScreenHeight = displaymetrics.heightPixels;
        if (VERSION.SDK_INT >= 19) {
            findViewById(R.id.statusView).getLayoutParams().height = getStatusBarHeight();
        }
        getLayoutInflater().inflate(laytoutResId, (FrameLayout) findViewById(R.id.containerLayout));
        setActionBarType(actionbarType);
        setCardViewSize();
    }

    public void setCardInfo() {
        ((CardView) findViewById(R.id.cardView)).requestCardListApi();
    }

    public void clearBillingView() {
        ((CardView) findViewById(R.id.cardView)).clearBillingView();
    }

    private boolean isDelivery() {
        StoreModel storeModel = ((CardView) findViewById(R.id.cardView)).getStoreModel();
        Map<String, String> deliveryInfoData = ((CardView) findViewById(R.id.cardView)).getDeliveryInfoData();
        if (storeModel != null && true == CardView.DELIVERY.equals(storeModel.getPaymentMethodType()) && deliveryInfoData == null) {
            return true;
        }
        return false;
    }

    private void setDeliveryActivity() {
        if (!((CardView) findViewById(R.id.cardView)).isRegisterMainCard()) {
            showConfirmDialog(getResources().getString(R.string.CARD_RESIST_COMMENT), (Runnable) new Runnable() {
                public void run() {
                    MainActionBarActivity.this.animActivity(new Intent(MainActionBarActivity.this.getBaseContext(), CardRegistActivity.class), R.anim.fade_in_activity, R.anim.fade_out_activity);
                }
            }, (Runnable) new Runnable() {
                public void run() {
                }
            });
            return;
        }
        StoreModel storeModel = ((CardView) findViewById(R.id.cardView)).getStoreModel();
        Intent i = new Intent(this, DeliveryActivity.class);
        i.putExtra("store_model", storeModel);
        animActivity(i, R.anim.fade_in_activity, R.anim.fade_out_activity);
    }

    public void openCardView() {
        if (SessionManager.getInstance().hasSession()) {
            if (true == isDelivery()) {
                setDeliveryActivity();
                return;
            }
            EventBus.getDefault().post(new CardSlideEvent(true));
            ((CardView) findViewById(R.id.cardView)).showCardCloseGuideView(false);
            this.isShowCardView = true;
            float toY = (float) (getResources().getDimensionPixelOffset(R.dimen.ACTIONBAR_HEIGHT) - getResources().getDimensionPixelOffset(R.dimen.CARD_VIEW_OPEN_MARGIN));
            if (VERSION.SDK_INT >= 19) {
                toY += (float) getStatusBarHeight();
            }
            ObjectAnimator translationAnimation = ObjectAnimator.ofFloat(findViewById(R.id.cardView), "translationY", new float[]{findViewById(R.id.cardView).getY(), toY});
            translationAnimation.setDuration(250);
            translationAnimation.setInterpolator(new DecelerateInterpolator());
            translationAnimation.addListener(new AnimatorListener() {
                public void onAnimationStart(Animator animation) {
                }

                public void onAnimationEnd(Animator animation) {
                    ((CardView) MainActionBarActivity.this.findViewById(R.id.cardView)).showCardGuideView();
                    ((CardView) MainActionBarActivity.this.findViewById(R.id.cardView)).requestAutoBranch();
                    if (true == MainActionBarActivity.this.isMapMode() && !AppSettingManager.getInstance().getCardviewActionGuideStatus()) {
                        MainActionBarActivity.this.animActivity(new Intent(MainActionBarActivity.this.getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "cardview_password"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                    }
                }

                public void onAnimationCancel(Animator animation) {
                }

                public void onAnimationRepeat(Animator animation) {
                }
            });
            translationAnimation.start();
            ((CardView) findViewById(R.id.cardView)).addResizeLayoutListener();
        }
    }

    public void closeCardView() {
        if (!((CardView) findViewById(R.id.cardView)).isPayingMode()) {
            EventBus.getDefault().post(new CardSlideEvent(false));
            ((CardView) findViewById(R.id.cardView)).showCardCloseGuideView(true);
            this.isShowCardView = false;
            ShareatApp.getInstance().setPayFlowing(false);
            ObjectAnimator translationAnimation = ObjectAnimator.ofFloat(findViewById(R.id.cardView), "translationY", new float[]{findViewById(R.id.cardView).getY(), (float) (this.mScreenHeight - getResources().getDimensionPixelOffset(R.dimen.CARD_VIEW_HEIGHT))});
            translationAnimation.setDuration(250);
            translationAnimation.setInterpolator(new DecelerateInterpolator());
            translationAnimation.start();
            if (true == isMapMode()) {
                animateCardLayout(false);
            }
            ((CardView) findViewById(R.id.cardView)).removeResizeLayoutListener();
        }
    }

    public void setBarcodeTimerLabel(String text) {
        ((BarcodeView) findViewById(R.id.barcodeView)).setTimerLabel(text);
    }

    public void setBarcode(String url) {
        ((BarcodeView) findViewById(R.id.barcodeView)).setBarcodeUrl(url);
        ((BarcodeView) findViewById(R.id.barcodeView)).hideDisableView();
    }

    public void openBarcodeView() {
        if (8 == findViewById(R.id.dimView).getVisibility()) {
            findViewById(R.id.dimView).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
            findViewById(R.id.dimView).setVisibility(0);
            findViewById(R.id.barcodeLayout).startAnimation(AnimationUtils.loadAnimation(this, R.anim.slide_from_right_barcode));
            findViewById(R.id.barcodeLayout).setVisibility(0);
        }
    }

    public void closeBarcodeView() {
        if (findViewById(R.id.dimView).getVisibility() == 0) {
            findViewById(R.id.dimView).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_out));
            findViewById(R.id.dimView).setVisibility(8);
            findViewById(R.id.barcodeLayout).startAnimation(AnimationUtils.loadAnimation(this, R.anim.slide_out_to_right_barcode));
            findViewById(R.id.barcodeLayout).setVisibility(8);
        }
    }

    public boolean isOpenBarcodeView() {
        return findViewById(R.id.barcodeLayout).getVisibility() == 0;
    }

    private void setGngButton(int resourceId) {
        findViewById(R.id.locationButton).setSelected(false);
        findViewById(R.id.headerMapBtn).setSelected(false);
        findViewById(R.id.headerListBtn).setSelected(false);
        findViewById(R.id.categoryButton).setSelected(false);
        findViewById(resourceId).setSelected(true);
    }

    private void setActionBarType(int type) {
        switch (type) {
            case 1:
                findViewById(R.id.cardView).setVisibility(8);
                return;
            case 2:
                findViewById(R.id.myCardButton).setVisibility(8);
                findViewById(R.id.cardView).setVisibility(8);
                return;
            case 3:
                findViewById(R.id.myCardButton).setVisibility(8);
                return;
            case 4:
                findViewById(R.id.myCardButton).setVisibility(0);
                findViewById(R.id.cardView).setVisibility(8);
                return;
            case 5:
                findViewById(R.id.emailButton).setVisibility(0);
                findViewById(R.id.myCardButton).setVisibility(8);
                findViewById(R.id.cardView).setVisibility(8);
                return;
            case 153:
                findViewById(R.id.myCardButton).setVisibility(8);
                findViewById(R.id.titleLayout).setVisibility(8);
                findViewById(R.id.cardView).setVisibility(8);
                return;
            default:
                return;
        }
    }

    private void setCardViewSize() {
        findViewById(R.id.cardView).setY((float) (this.mScreenHeight - getResources().getDimensionPixelOffset(R.dimen.CARD_VIEW_HEIGHT)));
        findViewById(R.id.topButton).setOnTouchListener(this.cardViewTouch);
    }

    public void hideLocationGuideView() {
        if (this.mPopupWindow != null) {
            this.mPopupWindow.dismiss();
        }
    }

    public void showLocationGuideView(View view) {
        if (this.mPopupWindow == null) {
            setLocationGuideView();
        }
        ((TextView) this.mPopupWindow.getContentView().findViewById(R.id.gpsGuideLabel)).setText(getString(R.string.STORE_GUIDE_MESSAGE));
        this.mPopupWindow.showAsDropDown(view.findViewById(R.id.gnbLocationImage));
    }

    private void setLocationGuideView() {
        View guideView = View.inflate(this, R.layout.popup_gps_guide, null);
        this.mPopupWindow = new PopupWindow(guideView, -2, -2);
        this.mPopupWindow.setOutsideTouchable(true);
        this.mPopupWindow.setFocusable(true);
        this.mPopupWindow.setBackgroundDrawable(new BitmapDrawable());
        guideView.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                MainActionBarActivity.this.findViewById(R.id.locationButton).performClick();
                MainActionBarActivity.this.mPopupWindow.dismiss();
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if ((requestCode == 1100 || resultCode == -1) && data != null && data.hasExtra("model")) {
            StoreModel sm = (StoreModel) data.getSerializableExtra("model");
            if (sm != null) {
                ((CardView) findViewById(R.id.cardView)).refreshStoreData(sm);
            }
        }
    }

    public boolean isMapMode() {
        return this.mIsMapMode;
    }

    /* access modifiers changed from: protected */
    public void onRestart() {
        super.onRestart();
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
    }

    /* access modifiers changed from: protected */
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    /* access modifiers changed from: protected */
    public void setAnimationListener(OnAnimationListener listener) {
        this.mAnimationListener = listener;
    }

    public void onClickUsePointButton(View view) {
        boolean isChecked;
        int btnTranslateOffset = getResources().getDimensionPixelOffset(R.dimen.CHECK_BUTTON_TRANSLATE_OFFSET);
        if (((int) findViewById(R.id.check_use_point_circle).getTranslationX()) >= 0) {
            isChecked = true;
        } else {
            isChecked = false;
        }
        if (!isChecked) {
            findViewById(R.id.check_use_point_text_on).setVisibility(8);
            findViewById(R.id.check_use_point_text_off).setVisibility(0);
            findViewById(R.id.usable_point_amount).setVisibility(0);
            findViewById(R.id.point_tobe_used).setVisibility(8);
            findViewById(R.id.check_use_point_circle).setBackgroundResource(R.drawable.btn_toggle_off);
            ((FontTextView) findViewById(R.id.point_unit_text)).setTextColor(Color.rgb(CPEConstant.DIALOG_REWARD_HEIGHT_PORTRAIT, 183, 195));
            ((LetterSpacingTextView) findViewById(R.id.point_desc)).setText("(\ubbf8\uc0ac\uc6a9)");
            GAEvent.onGaEvent((Activity) this, (int) R.string.ga_apply_point, (int) R.string.ga_ev_click, (int) R.string.ga_point_not_used);
        } else if (((CardView) findViewById(R.id.cardView)).getIUsablePoint() <= 0) {
            Toast.makeText(this, "\ubcf4\uc720\ud558\uc2e0 \uc801\ub9bd\uae08\uc774 \uc5c6\uc2b5\ub2c8\ub2e4.", 0).show();
            return;
        } else {
            findViewById(R.id.check_use_point_text_on).setVisibility(0);
            findViewById(R.id.check_use_point_text_off).setVisibility(8);
            findViewById(R.id.usable_point_amount).setVisibility(8);
            findViewById(R.id.point_tobe_used).setVisibility(0);
            findViewById(R.id.check_use_point_circle).setBackgroundResource(R.drawable.btn_toggle_on);
            ((FontTextView) findViewById(R.id.point_unit_text)).setTextColor(Color.rgb(99, 133, 230));
            ((LetterSpacingTextView) findViewById(R.id.point_desc)).setText("(\uacb0\uc81c\uc2dc \uc790\ub3d9\uc0ac\uc6a9)");
            btnTranslateOffset *= -1;
            GAEvent.onGaEvent((Activity) this, (int) R.string.ga_apply_point, (int) R.string.ga_ev_click, (int) R.string.ga_point_tobe_used);
        }
        findViewById(R.id.check_use_point_circle).animate().translationX((float) btnTranslateOffset).setDuration(200);
    }

    /* access modifiers changed from: protected */
    public void hideKeyboard() {
        InputMethodManager imm = (InputMethodManager) getSystemService("input_method");
        View view = getCurrentFocus();
        if (view == null) {
            view = new View(this);
        }
        imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
    }

    public static Bundle getQueryBundle(String query) {
        String[] params = query.split("&");
        Bundle data = new Bundle();
        for (String param : params) {
            String name = param.split("=")[0];
            try {
                String decodeValue = URLDecoder.decode(param.split("=")[1], "UTF-8");
                if (decodeValue.equals("$auth_token")) {
                    decodeValue = SessionManager.getInstance().getAuthToken();
                } else if (decodeValue.equals("$user_sno")) {
                    decodeValue = ShareatApp.getInstance().getUserNum();
                }
                data.putString(name, decodeValue);
            } catch (ArrayIndexOutOfBoundsException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e2) {
                e2.printStackTrace();
            }
        }
        return data;
    }
}