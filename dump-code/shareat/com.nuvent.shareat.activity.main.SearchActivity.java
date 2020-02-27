package com.nuvent.shareat.activity.main;

import android.animation.ObjectAnimator;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.DisplayMetrics;
import android.view.KeyEvent;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;
import com.google.android.gms.maps.model.LatLng;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.event.MainResumeEvent;
import com.nuvent.shareat.fragment.SearchPartnerFragment;
import com.nuvent.shareat.fragment.SearchTagFragment;
import com.nuvent.shareat.fragment.SearchUserFragment;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import java.util.HashMap;
import java.util.Map;

public class SearchActivity extends MainActionBarActivity {
    private Handler mPostHandler;
    /* access modifiers changed from: private */
    public SearchPartnerFragment mSearchPartnerFragment;
    /* access modifiers changed from: private */
    public SearchTagFragment mSearchTagFragment;
    /* access modifiers changed from: private */
    public SearchUserFragment mSearchUserFragment;
    /* access modifiers changed from: private */
    public int mSelectSearchMode = R.string.GA_SEARCH_EV_LABEL_1;
    private View mSlideView;
    private int mSlideViewWidth;

    private class FragmentViewPagerAdapter extends FragmentPagerAdapter {
        private static final int FRAGMENT_ITEM_COUNT = 3;

        public FragmentViewPagerAdapter(FragmentManager fragmentManager) {
            super(fragmentManager);
        }

        public int getCount() {
            return 3;
        }

        public Fragment getItem(int position) {
            switch (position) {
                case 0:
                    return SearchActivity.this.mSearchPartnerFragment;
                case 1:
                    return SearchActivity.this.mSearchUserFragment;
                case 2:
                    return SearchActivity.this.mSearchTagFragment;
                default:
                    return null;
            }
        }
    }

    public void onBackPressed() {
        EventBus.getDefault().post(new MainResumeEvent());
        finish();
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickTab(View view) {
        int index = 0;
        switch (view.getId()) {
            case R.id.partnerTab /*2131296998*/:
                index = 0;
                break;
            case R.id.tagTab /*2131297374*/:
                index = 2;
                break;
            case R.id.userTab /*2131297481*/:
                index = 1;
                break;
        }
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(index, true);
        setMovePosition(index);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_search, 153);
        GAEvent.onGAScreenView(this, R.string.ga_search);
        setSlideView();
        this.mPostHandler = new Handler();
        this.mSearchPartnerFragment = new SearchPartnerFragment();
        this.mSearchUserFragment = new SearchUserFragment();
        this.mSearchTagFragment = new SearchTagFragment();
        ViewPager viewPager = (ViewPager) findViewById(R.id.viewPager);
        viewPager.setAdapter(new FragmentViewPagerAdapter(getSupportFragmentManager()));
        viewPager.setCurrentItem(0);
        viewPager.setOffscreenPageLimit(3);
        viewPager.setOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
                SearchActivity.this.setTabIndex(position);
                SearchActivity.this.getKeyword();
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
        ((EditText) findViewById(R.id.searchField)).setOnEditorActionListener(new OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                if (actionId != 3) {
                    return false;
                }
                SearchActivity.this.hideKeyboard(SearchActivity.this.findViewById(R.id.searchField));
                SearchActivity.this.getKeyword();
                return true;
            }
        });
        ((EditText) findViewById(R.id.searchField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                SearchActivity.this.getKeyword();
            }
        });
        Map<Integer, String> dimensions = new HashMap<>();
        dimensions.put(Integer.valueOf(8), "");
        dimensions.put(Integer.valueOf(14), "");
        dimensions.put(Integer.valueOf(15), "");
        GAEvent.onGACustomDimensions(this, getString(R.string.Store_Search), dimensions);
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
        if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_URL)) {
            String subTabName = getIntent().getStringExtra(CustomSchemeManager.EXTRA_INTENT_SUB_TAB_NAME);
            if (subTabName.equals("store")) {
                onClickTab(findViewById(R.id.partnerTab));
            } else if (subTabName.equals("user")) {
                onClickTab(findViewById(R.id.userTab));
            } else {
                onClickTab(findViewById(R.id.tagTab));
            }
            Bundle bundle = getIntent().getBundleExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER);
            ((EditText) findViewById(R.id.searchField)).setText(bundle.getString("keyword"));
            ((EditText) findViewById(R.id.searchField)).setSelection(bundle.getString("keyword").length());
        }
    }

    private void setMovePosition(int index) {
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

    /* access modifiers changed from: private */
    public void getKeyword() {
        final String keyword = ((EditText) findViewById(R.id.searchField)).getText().toString().trim();
        if (keyword.isEmpty()) {
            this.mPostHandler.removeMessages(0);
            switch (((ViewPager) findViewById(R.id.viewPager)).getCurrentItem()) {
                case 0:
                    this.mSearchPartnerFragment.clearList();
                    return;
                case 1:
                    this.mSearchUserFragment.clearList();
                    return;
                case 2:
                    this.mSearchTagFragment.clearList();
                    return;
                default:
                    return;
            }
        } else {
            this.mPostHandler.removeMessages(0);
            this.mPostHandler = null;
            this.mPostHandler = new Handler();
            this.mPostHandler.postDelayed(new Runnable() {
                public void run() {
                    LatLng latLng;
                    switch (((ViewPager) SearchActivity.this.findViewById(R.id.viewPager)).getCurrentItem()) {
                        case 0:
                            try {
                                latLng = new LatLng(ShareatApp.getInstance().getGpsManager().getLatitude(), ShareatApp.getInstance().getGpsManager().getLongitude());
                            } catch (Exception e) {
                                e.printStackTrace();
                                latLng = new LatLng(37.4986366d, 127.027021d);
                            }
                            SearchActivity.this.mSearchPartnerFragment.postSearch(keyword, latLng);
                            break;
                        case 1:
                            SearchActivity.this.mSearchUserFragment.postSearch(keyword);
                            break;
                        case 2:
                            SearchActivity.this.mSearchTagFragment.postSearch(keyword);
                            break;
                    }
                    GAEvent.onGaEvent(SearchActivity.this, R.string.ga_search_ev_category, R.string.ga_search_ev_action, SearchActivity.this.mSelectSearchMode, keyword);
                }
            }, 300);
        }
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

    private void animateSlideView(float from) {
        ObjectAnimator translationAnimation = ObjectAnimator.ofFloat(this.mSlideView, "translationX", new float[]{this.mSlideView.getX(), from});
        translationAnimation.setDuration(150);
        translationAnimation.setInterpolator(new DecelerateInterpolator());
        translationAnimation.start();
    }

    /* access modifiers changed from: private */
    public void setTabIndex(int index) {
        setMovePosition(index);
        switch (index) {
            case 0:
                ((EditText) findViewById(R.id.searchField)).setHint(getResources().getString(R.string.SEARCH_FIELD_HINT_01));
                this.mSelectSearchMode = R.string.GA_SEARCH_EV_LABEL_1;
                return;
            case 1:
                ((EditText) findViewById(R.id.searchField)).setHint(getResources().getString(R.string.SEARCH_FIELD_HINT_02));
                this.mSelectSearchMode = R.string.GA_SEARCH_EV_LABEL_2;
                return;
            case 2:
                ((EditText) findViewById(R.id.searchField)).setHint(getResources().getString(R.string.SEARCH_FIELD_HINT_03));
                this.mSelectSearchMode = R.string.GA_SEARCH_EV_LABEL_3;
                return;
            default:
                return;
        }
    }
}