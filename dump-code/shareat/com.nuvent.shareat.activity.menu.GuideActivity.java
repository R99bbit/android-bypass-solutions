package com.nuvent.shareat.activity.menu;

import android.content.Context;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.support.v4.view.ViewPager.PageTransformer;
import android.util.TypedValue;
import android.view.KeyCharacterMap;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.LinearLayout;
import android.widget.RelativeLayout.LayoutParams;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.event.GuideCloseEvent;
import com.nuvent.shareat.manager.app.AppSettingManager;
import de.greenrobot.event.EventBus;

public class GuideActivity extends BaseActivity {
    public boolean mHasBackKey = false;
    public boolean mHasMenuKey = false;

    public class TutorialAdapter extends PagerAdapter {
        private int[] introImages = {R.drawable.helppage_step_01, R.drawable.helppage_step_02, R.drawable.helppage_step_03, R.drawable.helppage_step_04, R.drawable.helppage_step_05, R.drawable.helppage_step_06};
        private Context mContext;

        public TutorialAdapter(Context context) {
            this.mContext = context;
        }

        public int getCount() {
            return this.introImages.length;
        }

        public boolean isViewFromObject(View view, Object object) {
            return view == object;
        }

        public Object instantiateItem(ViewGroup container, int position) {
            ImageView imageView = new ImageView(this.mContext);
            if (GuideActivity.this.mHasMenuKey || GuideActivity.this.mHasBackKey) {
                imageView.setScaleType(ScaleType.CENTER_CROP);
            } else {
                imageView.setScaleType(ScaleType.FIT_XY);
            }
            imageView.setImageResource(this.introImages[position]);
            container.addView(imageView);
            return imageView;
        }

        public void destroyItem(ViewGroup container, int position, Object object) {
            container.removeView((View) object);
        }
    }

    public class TutorialPageTransformer implements PageTransformer {
        public TutorialPageTransformer() {
        }

        public void transformPage(View page, float position) {
            if (position >= -1.0f && position > 0.0f && position <= 1.0f) {
                float normalizedposition = Math.abs(Math.abs(position) - 1.0f);
                page.setScaleX((normalizedposition / 2.0f) + 0.5f);
                page.setScaleY((normalizedposition / 2.0f) + 0.5f);
                page.setAlpha(normalizedposition);
            }
        }
    }

    public void onBackPressed() {
        if (!getIntent().hasExtra("menuRequest")) {
            EventBus.getDefault().post(new GuideCloseEvent());
        }
        finish(R.anim.scale_up, R.anim.modal_exit_animation);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_guide);
        if (VERSION.SDK_INT >= 19) {
            findViewById(R.id.statusView).getLayoutParams().height = getStatusBarHeight();
        }
        AppSettingManager.getInstance().setGuideViewingOff(true);
        ViewPager viewPager = (ViewPager) findViewById(R.id.viewPager);
        viewPager.setAdapter(new TutorialAdapter(this));
        viewPager.setPageTransformer(true, new TutorialPageTransformer());
        viewPager.setOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
                switch (position) {
                    case 0:
                        GuideActivity.this.setPageIndicator(R.id.pageIndicator01);
                        return;
                    case 1:
                        GuideActivity.this.setPageIndicator(R.id.pageIndicator02);
                        return;
                    case 2:
                        GuideActivity.this.setPageIndicator(R.id.pageIndicator03);
                        return;
                    case 3:
                        GuideActivity.this.setPageIndicator(R.id.pageIndicator04);
                        return;
                    case 4:
                        GuideActivity.this.setPageIndicator(R.id.pageIndicator05);
                        return;
                    case 5:
                        GuideActivity.this.setPageIndicator(R.id.pageIndicator06);
                        return;
                    default:
                        return;
                }
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
        setPageIndicator(R.id.pageIndicator01);
        findViewById(R.id.closeButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GuideActivity.this.onBackPressed();
            }
        });
    }

    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        this.mHasMenuKey = ViewConfiguration.get(getBaseContext()).hasPermanentMenuKey();
        this.mHasBackKey = KeyCharacterMap.deviceHasKey(4);
        if (!this.mHasMenuKey && !this.mHasBackKey && VERSION.SDK_INT >= 19) {
            int barHeightDP = Math.round(((float) Math.round((float) (getStatusBarHeight() / 2))) / (getBaseContext().getResources().getDisplayMetrics().xdpi / 160.0f));
            LinearLayout lIndicator = (LinearLayout) findViewById(R.id.indicatorLayout);
            if (lIndicator != null) {
                LayoutParams lpIndicator = (LayoutParams) lIndicator.getLayoutParams();
                if (lpIndicator != null) {
                    lpIndicator.topMargin = (int) TypedValue.applyDimension(1, (float) (160 - barHeightDP), getBaseContext().getResources().getDisplayMetrics());
                    lIndicator.setLayoutParams(lpIndicator);
                }
            }
        }
    }

    /* access modifiers changed from: private */
    public void setPageIndicator(int resourceId) {
        findViewById(R.id.pageIndicator01).setSelected(false);
        findViewById(R.id.pageIndicator02).setSelected(false);
        findViewById(R.id.pageIndicator03).setSelected(false);
        findViewById(R.id.pageIndicator04).setSelected(false);
        findViewById(R.id.pageIndicator05).setSelected(false);
        findViewById(R.id.pageIndicator06).setSelected(false);
        findViewById(resourceId).setSelected(true);
    }
}