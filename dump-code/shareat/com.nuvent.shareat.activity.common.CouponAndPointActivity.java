package com.nuvent.shareat.activity.common;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.support.design.widget.TabLayout;
import android.support.design.widget.TabLayout.OnTabSelectedListener;
import android.support.design.widget.TabLayout.Tab;
import android.support.design.widget.TabLayout.TabLayoutOnPageChangeListener;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.view.View;
import android.widget.Toast;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.view.CouponAndPointInlineCouponFragment;
import com.nuvent.shareat.widget.view.CouponAndPointInlinePointFragment;

public class CouponAndPointActivity extends MainActionBarActivity {
    public static final int GENDER_FEMALE = 2;
    public static final int GENDER_MALE = 1;
    private TabLayout mTabLayout;
    /* access modifiers changed from: private */
    public ViewPager mViewPager;

    public class CouponAndPointPagerAdapter extends FragmentStatePagerAdapter {
        private int tabCount;

        public CouponAndPointPagerAdapter(FragmentManager fm, int tabCount2) {
            super(fm);
            this.tabCount = tabCount2;
        }

        public Fragment getItem(int position) {
            switch (position) {
                case 0:
                    return new CouponAndPointInlineCouponFragment();
                case 1:
                    return new CouponAndPointInlinePointFragment();
                default:
                    return null;
            }
        }

        public int getCount() {
            return this.tabCount;
        }
    }

    public void onBackPressed() {
        finish(R.anim.scale_up, R.anim.modal_exit_animation);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickTitle(View view) {
        onBackPressed();
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_coupon_and_point, 2);
        GAEvent.onGAScreenView(this, R.string.ga_slide_my_coupon);
        setTitle("\ub0b4 \ucfe0\ud3f0/\uc801\ub9bd\uae08 \uad00\ub9ac");
        showSubActionbar();
        showFavoriteButton(false);
        this.mTabLayout = (TabLayout) findViewById(R.id.tabLayout);
        this.mTabLayout.addTab(this.mTabLayout.newTab().setText((int) R.string.coupon_point_tab_coupon));
        this.mTabLayout.addTab(this.mTabLayout.newTab().setText((int) R.string.coupon_point_tab_point));
        this.mTabLayout.setTabGravity(0);
        this.mTabLayout.setSelectedTabIndicatorHeight(9);
        this.mTabLayout.setSelectedTabIndicatorColor(Color.parseColor("#6385e6"));
        this.mTabLayout.setTabTextColors(Color.parseColor("#757b8c"), Color.parseColor("#6385e6"));
        this.mViewPager = (ViewPager) findViewById(R.id.couponAndPointPager);
        this.mViewPager.setAdapter(new CouponAndPointPagerAdapter(getSupportFragmentManager(), this.mTabLayout.getTabCount()));
        this.mViewPager.addOnPageChangeListener(new TabLayoutOnPageChangeListener(this.mTabLayout));
        this.mViewPager.addOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
        this.mTabLayout.setOnTabSelectedListener(new OnTabSelectedListener() {
            public void onTabSelected(Tab tab) {
                if (tab.getPosition() != CouponAndPointActivity.this.mViewPager.getCurrentItem()) {
                    CouponAndPointActivity.this.mViewPager.setCurrentItem(tab.getPosition());
                }
                GAEvent.onGaEvent((Activity) CouponAndPointActivity.this, (int) R.string.ga_slide_my_coupon, (int) R.string.ga_slide_my_coupon, tab.getText().toString());
            }

            public void onTabUnselected(Tab tab) {
            }

            public void onTabReselected(Tab tab) {
                if (tab.getPosition() != CouponAndPointActivity.this.mViewPager.getCurrentItem()) {
                    CouponAndPointActivity.this.mViewPager.setCurrentItem(tab.getPosition());
                }
            }
        });
        Bundle parameters = getIntent().getBundleExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER);
        if (parameters != null) {
            String type = parameters.getString(KakaoTalkLinkProtocol.ACTION_TYPE);
            if (type != null) {
                char c = 65535;
                switch (type.hashCode()) {
                    case -1354573786:
                        if (type.equals(Param.COUPON)) {
                            c = 1;
                            break;
                        }
                        break;
                    case 106845584:
                        if (type.equals("point")) {
                            c = 0;
                            break;
                        }
                        break;
                }
                switch (c) {
                    case 0:
                        this.mViewPager.setCurrentItem(1);
                        return;
                    case 1:
                        this.mViewPager.setCurrentItem(0);
                        return;
                    default:
                        return;
                }
            }
        }
    }

    public void onClickPointToBeExpiredInfo(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_slide_my_coupon, (int) R.string.ga_ev_click, (int) R.string.ga_my_point_tobe_expired);
        Toast.makeText(this, "30\uc77c\ub0b4 \uc720\ud6a8\uae30\uac04\uc774 \ub9cc\ub8cc\ub418\ub294 \uc801\ub9bd\uae08\uc744 \ud569\uc0b0\ud55c \uae08\uc561\uc785\ub2c8\ub2e4. \uc720\ud6a8\uae30\uac04 \ub0b4\uc5d0 \uc0ac\uc6a9\ub418\uc9c0 \uc54a\uc740 \uc801\ub9bd\uae08\uc740 \ub9cc\ub8cc\uc77c \ub2e4\uc74c\ub0a0 \uc790\ub3d9 \uc18c\uba78\ub429\ub2c8\ub2e4.", 0).show();
    }
}