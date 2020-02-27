package com.nuvent.shareat.activity.menu;

import android.animation.ObjectAnimator;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.os.Bundle;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.animation.AnimationUtils;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import com.nostra13.universalimageloader.core.assist.FailReason;
import com.nostra13.universalimageloader.core.listener.ImageLoadingListener;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.adapter.InterestAdapter;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.friend.FriendStatusApi;
import com.nuvent.shareat.api.interest.UserProfileApi;
import com.nuvent.shareat.event.FriendAddEvent;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.friend.FriendStatusModel;
import com.nuvent.shareat.model.user.UserProfileModel;
import com.nuvent.shareat.util.BitmapHelper;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import net.xenix.android.widget.PagingEnableViewPager;
import net.xenix.util.ImageDisplay;

public class InterestActivity extends MainActionBarActivity {
    private static final String[] MENU_TAB = {"\ubc29\ubb38", "\uc0ac\uc9c4", "\ub9ac\ubdf0", "\ucc1c"};
    private static final String SUB_TAB_IMAGE = "image";
    private static final String SUB_TAB_LIKE = "like";
    private static final String SUB_TAB_REVIEW = "review";
    private static final String SUB_TAB_STORE = "store";
    /* access modifiers changed from: private */
    public InterestAdapter mInterestAdapter;
    /* access modifiers changed from: private */
    public UserProfileModel mProfileModel;
    private View mSlideView;
    private int mSlideViewWidth;
    /* access modifiers changed from: private */
    public String mTargetUserSno;

    public void onClickTab(View view) {
        if (this.mTargetUserSno == null || this.mTargetUserSno.equals(ShareatApp.getInstance().getUserNum()) || this.mProfileModel.isOpen()) {
            int index = 0;
            switch (view.getId()) {
                case R.id.tab01 /*2131297367*/:
                    index = 0;
                    break;
                case R.id.tab02 /*2131297368*/:
                    index = 1;
                    break;
                case R.id.tab03 /*2131297369*/:
                    index = 2;
                    break;
                case R.id.tab04 /*2131297370*/:
                    index = 3;
                    break;
            }
            ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(index, true);
            setMovePosition(index);
        }
    }

    /* access modifiers changed from: private */
    public void setMovePosition(int index) {
        float movePosition = 0.0f;
        switch (index) {
            case 0:
                movePosition = 0.0f;
                ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(0, true);
                break;
            case 1:
                movePosition = (float) this.mSlideViewWidth;
                ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(1, true);
                break;
            case 2:
                movePosition = (float) (this.mSlideViewWidth * 2);
                ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(2, true);
                break;
            case 3:
                movePosition = (float) (this.mSlideViewWidth * 3);
                ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(3, true);
                break;
        }
        animateSlideView(movePosition);
    }

    private void animateSlideView(float from) {
        ObjectAnimator translationAnimation = ObjectAnimator.ofFloat(this.mSlideView, "translationX", new float[]{this.mSlideView.getX(), from});
        translationAnimation.setDuration(150);
        translationAnimation.setInterpolator(new DecelerateInterpolator());
        translationAnimation.start();
    }

    public void onClickFriends(View view) {
        if (!SessionManager.getInstance().hasSession()) {
            showLoginDialog();
        } else if (findViewById(R.id.privateUserLayout).getVisibility() != 0) {
            Intent intent = new Intent(this, FriendGroupActivity.class);
            String viewType = "friend";
            switch (view.getId()) {
                case R.id.followerButton /*2131296668*/:
                    viewType = "follower";
                    break;
                case R.id.followingButton /*2131296670*/:
                    viewType = "following";
                    break;
                case R.id.friendButton /*2131296681*/:
                    viewType = "friend";
                    break;
            }
            intent.putExtra("inProfile", viewType);
            if (!this.mTargetUserSno.equals(ShareatApp.getInstance().getUserNum())) {
                intent.putExtra("targetUserSno", this.mTargetUserSno);
                intent.putExtra("targetUserName", this.mProfileModel.getTarget_user_name());
            }
            pushActivity(intent);
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_interest, 2);
        setSlideView();
        if (getIntent().hasExtra("inMenu")) {
            showSubActionbar();
        }
        showFavoriteButton(false);
        if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_URL) && getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER)) {
            this.mTargetUserSno = getIntent().getBundleExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER).getString("user_sno");
            setTitle("\ud504\ub85c\ud544");
            GAEvent.onGAScreenView(this, R.string.ga_interest_target_user);
        } else if (getIntent().hasExtra("targetUserSno")) {
            this.mTargetUserSno = getIntent().getStringExtra("targetUserSno");
            setTitle("\ud504\ub85c\ud544");
            GAEvent.onGAScreenView(this, R.string.ga_interest_target_user);
        } else {
            this.mTargetUserSno = null;
            setTitle("\ub098\uc758 \ud65c\ub3d9");
            findViewById(R.id.followButton).setVisibility(8);
            GAEvent.onGAScreenView(this, R.string.ga_interest);
        }
        setViewPager();
        getUserInfo();
    }

    private void setViewPager() {
        this.mInterestAdapter = new InterestAdapter(getSupportFragmentManager());
        this.mInterestAdapter.setTargetUserSno(this.mTargetUserSno);
        ViewPager viewPager = (ViewPager) findViewById(R.id.viewPager);
        viewPager.setOffscreenPageLimit(4);
        viewPager.setAdapter(this.mInterestAdapter);
        if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_SUB_TAB_NAME)) {
            String subTabName = getIntent().getStringExtra(CustomSchemeManager.EXTRA_INTENT_SUB_TAB_NAME);
            if (subTabName.equals(SUB_TAB_STORE)) {
                setMovePosition(0);
            } else if (subTabName.equals("image")) {
                setMovePosition(1);
            } else if (subTabName.equals("review")) {
                setMovePosition(2);
            } else {
                setMovePosition(3);
            }
        }
        viewPager.setOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
                String tabName;
                InterestActivity.this.setMovePosition(position);
                switch (position) {
                    case 1:
                        tabName = InterestActivity.this.getResources().getString(R.string.ga_interest_photo);
                        break;
                    case 2:
                        tabName = InterestActivity.this.getResources().getString(R.string.ga_interest_review);
                        break;
                    case 3:
                        tabName = InterestActivity.this.getResources().getString(R.string.ga_interest_zzim);
                        break;
                    default:
                        tabName = InterestActivity.this.getResources().getString(R.string.ga_interest_visit);
                        break;
                }
                GAEvent.onGaEvent(InterestActivity.this.getResources().getString(InterestActivity.this.mTargetUserSno == null ? R.string.ga_interest : R.string.ga_interest_target_user), InterestActivity.this.getResources().getString(R.string.ga_ev_click), tabName);
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
    }

    private void setSlideView() {
        DisplayMetrics displaymetrics = new DisplayMetrics();
        getWindowManager().getDefaultDisplay().getMetrics(displaymetrics);
        this.mSlideViewWidth = displaymetrics.widthPixels / 4;
        LayoutParams params = new LayoutParams(this.mSlideViewWidth, -1);
        this.mSlideView = new View(this);
        this.mSlideView.setLayoutParams(params);
        this.mSlideView.setBackgroundColor(Color.parseColor("#ff6385E6"));
        ((FrameLayout) findViewById(R.id.slideLayout)).addView(this.mSlideView);
    }

    public void getUserInfo() {
        if (this.mTargetUserSno == null) {
            this.mTargetUserSno = ShareatApp.getInstance().getUserNum();
        }
        new UserProfileApi(this, ApiUrl.PROFILE_INFO + "?target_user_sno=" + this.mTargetUserSno).request(new RequestHandler() {
            public void onStart() {
                InterestActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                InterestActivity.this.showCircleDialog(false);
                InterestActivity.this.mProfileModel = (UserProfileModel) result;
                ImageButton followButton = (ImageButton) InterestActivity.this.findViewById(R.id.followButton);
                if (InterestActivity.this.mProfileModel.getFollow_status().equals("10") || InterestActivity.this.mProfileModel.getFollow_status().equals("20")) {
                    followButton.setSelected(true);
                } else {
                    followButton.setSelected(false);
                }
                followButton.setOnClickListener(new OnClickListener() {
                    public void onClick(final View v) {
                        String message;
                        if (!SessionManager.getInstance().hasSession()) {
                            InterestActivity.this.showLoginDialog();
                        } else if (v.isSelected()) {
                            GAEvent.onGaEvent(InterestActivity.this.getResources().getString(R.string.ga_interest_target_user), InterestActivity.this.getResources().getString(R.string.ga_friends_unfollow), InterestActivity.this.getResources().getString(R.string.ga_friends_unfollow));
                            if (InterestActivity.this.mProfileModel.getFollow_status().equals("20")) {
                                message = InterestActivity.this.mProfileModel.getTarget_user_name() + "\ub2d8\uc5d0 \ub300\ud55c \ud314\ub85c\uc6b0\ub97c \ucde8\uc18c\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?\n(\ub9de\ud314 \ud314\ub85c\uc6b0\ub97c \ucde8\uc18c\ud558\uba74, \uce5c\uad6c\uc18c\uc2dd/\uacb0\uc81c\ucd08\ub300\ub97c \ubc1b\uc744 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4)";
                            } else {
                                message = InterestActivity.this.mProfileModel.getTarget_user_name() + "\ub2d8\uc5d0 \ub300\ud55c \ud314\ub85c\uc6b0\ub97c \ucde8\uc18c\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?";
                            }
                            InterestActivity.this.showConfirmDialog(message, new Runnable() {
                                public void run() {
                                    v.setSelected(!v.isSelected());
                                    InterestActivity.this.requestStateApi();
                                }
                            });
                        } else {
                            GAEvent.onGaEvent(InterestActivity.this.getResources().getString(R.string.ga_interest_target_user), InterestActivity.this.getResources().getString(R.string.ga_friends_follow), InterestActivity.this.getResources().getString(R.string.ga_friends_follow));
                            v.setSelected(!v.isSelected());
                            InterestActivity.this.requestStateApi();
                        }
                    }
                });
                TextView visitLabel = (TextView) InterestActivity.this.findViewById(R.id.visitLabel);
                TextView friendLabel = (TextView) InterestActivity.this.findViewById(R.id.friendLabel);
                TextView followerLabel = (TextView) InterestActivity.this.findViewById(R.id.followerLabel);
                TextView followingLabel = (TextView) InterestActivity.this.findViewById(R.id.followingLabel);
                if (InterestActivity.this.mTargetUserSno == null || InterestActivity.this.mTargetUserSno.equals(ShareatApp.getInstance().getUserNum()) || InterestActivity.this.mProfileModel.isOpen()) {
                    visitLabel.setText(InterestActivity.this.mProfileModel.getCnt_pay());
                    friendLabel.setText(InterestActivity.this.mProfileModel.getCnt_friend());
                    followerLabel.setText(InterestActivity.this.mProfileModel.getCnt_follow());
                    followingLabel.setText(InterestActivity.this.mProfileModel.getCnt_following());
                    InterestActivity.this.mProfileModel.setTarget_user_sno(InterestActivity.this.mTargetUserSno);
                    InterestActivity.this.findViewById(R.id.visitCountLayout).setVisibility(0);
                    InterestActivity.this.setTitle(ShareatApp.getInstance().getUserNum().equals(InterestActivity.this.mProfileModel.getTarget_user_sno()) ? "\ub098\uc758 \ud65c\ub3d9" : InterestActivity.this.mProfileModel.getTarget_user_name());
                    ImageDisplay.getInstance().displayImageLoadRound(InterestActivity.this.mProfileModel.getTarget_user_img(), (ImageView) InterestActivity.this.findViewById(R.id.profileImageView), InterestActivity.this.getResources().getDimensionPixelOffset(R.dimen.AVATAR_ROUND_SIZE_25OPX));
                    InterestActivity.this.getBitmapFromURL();
                    if (InterestActivity.this.getIntent().hasExtra("isReview")) {
                        InterestActivity.this.setMovePosition(2);
                        return;
                    }
                    return;
                }
                InterestActivity.this.setPrivateUser();
                visitLabel.setText("");
                friendLabel.setText("");
                followerLabel.setText("");
                followingLabel.setText("");
            }

            public void onFailure(Exception exception) {
                InterestActivity.this.showCircleDialog(false);
                InterestActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        InterestActivity.this.mInterestAdapter = new InterestAdapter(InterestActivity.this.getSupportFragmentManager());
                        ((ViewPager) InterestActivity.this.findViewById(R.id.viewPager)).setAdapter(InterestActivity.this.mInterestAdapter);
                        InterestActivity.this.getUserInfo();
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void setPrivateUser() {
        ((ImageView) findViewById(R.id.profileImageView)).setImageResource(R.drawable.profile_user_lock);
        setTitle("\ube44\uacf5\uac1c");
        findViewById(R.id.privateUserLayout).setVisibility(0);
        findViewById(R.id.followButton).setVisibility(8);
        ((PagingEnableViewPager) findViewById(R.id.viewPager)).setPagingDisabled();
    }

    public void getBitmapFromURL() {
        if (this.mProfileModel.getTarget_user_img() != null && !this.mProfileModel.getTarget_user_img().isEmpty()) {
            ImageDisplay.getInstance().displayImageLoad(this.mProfileModel.getTarget_user_img(), (ImageView) findViewById(R.id.profile_bg), (ImageLoadingListener) new ImageLoadingListener() {
                public void onLoadingStarted(String imageUri, View view) {
                }

                public void onLoadingFailed(String imageUri, View view, FailReason failReason) {
                }

                public void onLoadingComplete(String imageUri, View view, Bitmap loadedImage) {
                    ((ImageView) view).setImageBitmap(BitmapHelper.getBlurEffectBitmap(InterestActivity.this, loadedImage, 20));
                    view.setAlpha(0.4f);
                    view.startAnimation(AnimationUtils.loadAnimation(InterestActivity.this, R.anim.fade_in));
                    view.setVisibility(0);
                }

                public void onLoadingCancelled(String imageUri, View view) {
                }
            });
        }
    }

    /* access modifiers changed from: private */
    public void requestStateApi() {
        FriendStatusApi request = new FriendStatusApi(this);
        request.addParam("follow_user_sno", this.mProfileModel.getTarget_user_sno());
        request.addParam("follow_status", this.mProfileModel.getFollow_status());
        request.request(new RequestHandler() {
            public void onStart() {
                InterestActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                InterestActivity.this.showCircleDialog(false);
                FriendStatusModel model = (FriendStatusModel) result;
                if (model.getResult().equals("Y")) {
                    InterestActivity.this.mProfileModel.setFollow_status(model.getFollow_status());
                    if (InterestActivity.this.mProfileModel.getFollow_status().equals("10") || InterestActivity.this.mProfileModel.getFollow_status().equals("20")) {
                        InterestActivity.this.findViewById(R.id.followButton).setSelected(true);
                    } else {
                        InterestActivity.this.findViewById(R.id.followButton).setSelected(false);
                    }
                    EventBus.getDefault().post(new FriendAddEvent(InterestActivity.this.mProfileModel.getTarget_user_sno(), model.getFollow_status()));
                }
            }

            public void onFailure(Exception exception) {
                InterestActivity.this.showCircleDialog(false);
                InterestActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        InterestActivity.this.requestStateApi();
                    }
                });
            }

            public void onFinish() {
                InterestActivity.this.showCircleDialog(false);
            }
        });
    }
}