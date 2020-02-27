package com.nuvent.shareat.activity.menu;

import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.adapter.friend.FriendAdapter;
import com.nuvent.shareat.util.GAEvent;

public class FriendGroupActivity extends MainActionBarActivity {
    private static final String[] MENU_TAB = {"\uce5c\uad6c(\ub9de\ud314)", "\ud314\ub85c\uc6cc", "\ud314\ub85c\uc789"};
    private FriendAdapter mFriendAdapter;
    private View mSlideView;
    private int mSlideViewWidth;
    private String mTargetUserSno;

    public void onClickTab(View view) {
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
        }
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(index, true);
        setMovePosition(index);
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
        }
        animateSlideView(movePosition);
    }

    private void animateSlideView(float from) {
        ObjectAnimator translationAnimation = ObjectAnimator.ofFloat(this.mSlideView, "translationX", new float[]{this.mSlideView.getX(), from});
        translationAnimation.setDuration(150);
        translationAnimation.setInterpolator(new DecelerateInterpolator());
        translationAnimation.start();
    }

    public String getTargetUserSno() {
        return this.mTargetUserSno;
    }

    /* access modifiers changed from: protected */
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (intent.hasExtra("inProfile")) {
            final String type = intent.getStringExtra("inProfile");
            findViewById(R.id.viewPager).postDelayed(new Runnable() {
                public void run() {
                    if (type.equals("follower")) {
                        FriendGroupActivity.this.setMovePosition(1);
                    } else if (type.equals("following")) {
                        FriendGroupActivity.this.setMovePosition(2);
                    } else {
                        FriendGroupActivity.this.setMovePosition(0);
                    }
                }
            }, 300);
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_friend_group, 2);
        GAEvent.onGAScreenView(this, R.string.friend_group);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\uce5c\uad6c\ubaa9\ub85d");
        setSlideView();
        this.mFriendAdapter = new FriendAdapter(getSupportFragmentManager());
        ViewPager viewPager = (ViewPager) findViewById(R.id.viewPager);
        viewPager.setOffscreenPageLimit(3);
        viewPager.setAdapter(this.mFriendAdapter);
        if (getIntent().hasExtra("inProfile")) {
            String type = getIntent().getStringExtra("inProfile");
            if (type.equals("follower")) {
                setMovePosition(1);
            } else if (type.equals("following")) {
                setMovePosition(2);
            }
            if (getIntent().hasExtra("targetUserSno")) {
                this.mTargetUserSno = getIntent().getStringExtra("targetUserSno");
                setTitle("\uce5c\uad6c\ubaa9\ub85d : " + getIntent().getStringExtra("targetUserName"));
            }
        }
        ((ViewPager) findViewById(R.id.viewPager)).setOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
                FriendGroupActivity.this.setMovePosition(position);
                int resourceId = R.string.ga_friends_friend_tab;
                switch (position) {
                    case 0:
                        resourceId = R.string.ga_friends_friend_tab;
                        break;
                    case 1:
                        resourceId = R.string.ga_friends_follow_tab;
                        break;
                    case 2:
                        resourceId = R.string.ga_friends_following_tab;
                        break;
                }
                GAEvent.onGaEvent((Activity) FriendGroupActivity.this, (int) R.string.friend_group, (int) R.string.ga_ev_click, resourceId);
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
    }

    private void setSlideView() {
        DisplayMetrics displaymetrics = new DisplayMetrics();
        getWindowManager().getDefaultDisplay().getMetrics(displaymetrics);
        this.mSlideViewWidth = displaymetrics.widthPixels / 3;
        LayoutParams params = new LayoutParams(this.mSlideViewWidth, -1);
        this.mSlideView = new View(this);
        this.mSlideView.setLayoutParams(params);
        this.mSlideView.setBackgroundColor(Color.parseColor("#ff6385E6"));
        ((FrameLayout) findViewById(R.id.slideLayout)).addView(this.mSlideView);
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 17) {
            this.mFriendAdapter.notifyDataSetChanged();
        }
    }
}