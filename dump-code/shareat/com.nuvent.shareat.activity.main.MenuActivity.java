package com.nuvent.shareat.activity.main;

import android.animation.ObjectAnimator;
import android.graphics.Color;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.fragment.menu.MenuFragment;
import com.nuvent.shareat.util.GAEvent;

public class MenuActivity extends MainActionBarActivity {
    private static final String MENU_TYPE_DAY = "D";
    private static final String MENU_TYPE_MONTH = "M";
    private static final String MENU_TYPE_TOTAL = "A";
    private static final String MENU_TYPE_WEEK = "W";
    /* access modifiers changed from: private */
    public String mMenuResultSet = "DB";
    /* access modifiers changed from: private */
    public String mPartnerSno;
    private View mSlideView;
    private int mSlideViewWidth;

    public class FragmentAdapter extends FragmentStatePagerAdapter {
        private static final int MENU_COUNT = 4;

        public FragmentAdapter(FragmentManager fm) {
            super(fm);
        }

        public Fragment getItem(int position) {
            if (MenuActivity.this.mMenuResultSet.equals("DB") || MenuActivity.this.mMenuResultSet.equals("MC")) {
                MenuFragment menuFragment = new MenuFragment();
                menuFragment.setMenuData(MenuActivity.this.mPartnerSno, MenuActivity.MENU_TYPE_DAY, MenuActivity.this.mMenuResultSet);
                return menuFragment;
            }
            switch (position) {
                case 1:
                    MenuFragment menuFragment2 = new MenuFragment();
                    menuFragment2.setMenuData(MenuActivity.this.mPartnerSno, MenuActivity.MENU_TYPE_WEEK, MenuActivity.this.mMenuResultSet);
                    return menuFragment2;
                case 2:
                    MenuFragment menuFragment3 = new MenuFragment();
                    menuFragment3.setMenuData(MenuActivity.this.mPartnerSno, MenuActivity.MENU_TYPE_MONTH, MenuActivity.this.mMenuResultSet);
                    return menuFragment3;
                case 3:
                    MenuFragment menuFragment4 = new MenuFragment();
                    menuFragment4.setMenuData(MenuActivity.this.mPartnerSno, MenuActivity.MENU_TYPE_TOTAL, MenuActivity.this.mMenuResultSet);
                    return menuFragment4;
                default:
                    MenuFragment menuFragment5 = new MenuFragment();
                    menuFragment5.setMenuData(MenuActivity.this.mPartnerSno, MenuActivity.MENU_TYPE_DAY, MenuActivity.this.mMenuResultSet);
                    return menuFragment5;
            }
        }

        public int getCount() {
            return (MenuActivity.this.mMenuResultSet.equals("DB") || MenuActivity.this.mMenuResultSet.equals("MC")) ? 1 : 4;
        }
    }

    public void onBackPressed() {
        finish();
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickTab(View view) {
        String tabName = getResources().getString(R.string.ga_store_detail_menu_more_day);
        int index = 0;
        switch (view.getId()) {
            case R.id.dayTab /*2131296553*/:
                index = 0;
                tabName = getResources().getString(R.string.ga_store_detail_menu_more_day);
                break;
            case R.id.monthTab /*2131296872*/:
                index = 2;
                tabName = getResources().getString(R.string.ga_store_detail_menu_more_month);
                break;
            case R.id.totalTab /*2131297449*/:
                index = 3;
                tabName = getResources().getString(R.string.ga_store_detail_menu_more_all);
                break;
            case R.id.weekTab /*2131297500*/:
                index = 1;
                tabName = getResources().getString(R.string.ga_store_detail_menu_more_week);
                break;
        }
        GAEvent.onGaEvent(getResources().getString(R.string.ga_store_detail_menu_more), getResources().getString(R.string.ga_ev_click), tabName);
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(index, true);
        setMovePosition(index);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_menu, 2);
        setTitle(getIntent().getStringExtra("title"));
        this.mPartnerSno = String.valueOf(getIntent().getIntExtra("partnerSno", 0));
        this.mMenuResultSet = getIntent().getStringExtra("menuResultSet");
        showFavoriteButton(false);
        GAEvent.onGAScreenView(this, R.string.ga_store_detail_menu_more);
        setSlideView();
        ViewPager viewPager = (ViewPager) findViewById(R.id.viewPager);
        viewPager.setAdapter(new FragmentAdapter(getSupportFragmentManager()));
        viewPager.setCurrentItem(0);
        viewPager.setOffscreenPageLimit(4);
        viewPager.setOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
                MenuActivity.this.setTabIndex(position);
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
        if (this.mMenuResultSet.equals("DB") || this.mMenuResultSet.equals("MC")) {
            findViewById(R.id.tabLayout).setVisibility(8);
        }
    }

    private void setMovePosition(int index) {
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(index, true);
        animateSlideView((float) (this.mSlideViewWidth * index));
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

    private void animateSlideView(float from) {
        ObjectAnimator translationAnimation = ObjectAnimator.ofFloat(this.mSlideView, "translationX", new float[]{this.mSlideView.getX(), from});
        translationAnimation.setDuration(150);
        translationAnimation.setInterpolator(new DecelerateInterpolator());
        translationAnimation.start();
    }

    /* access modifiers changed from: private */
    public void setTabIndex(int index) {
        setMovePosition(index);
    }
}