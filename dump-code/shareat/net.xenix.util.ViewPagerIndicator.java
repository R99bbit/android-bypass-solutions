package net.xenix.util;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.CornerPathEffect;
import android.graphics.Paint;
import android.graphics.Paint.Style;
import android.graphics.Path;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.TextView;
import com.nuvent.shareat.R;
import net.xenix.android.widget.FontTextView;

public class ViewPagerIndicator extends LinearLayout {
    private static final int COLOR_TEXT_HIGHLIGHT = -9077876;
    private static final int COLOR_TEXT_NORMAL = -9077876;
    private static final int COUNT_DEFAULT_TAB = 4;
    private static final float RADIO_TRIANGLE_WIDTH = 0.16666667f;
    private int mInitTranslationX;
    public PageOnchangeListener mListener;
    private Paint mPaint;
    private Path mPath;
    private int mScreenWidth;
    /* access modifiers changed from: private */
    public int mTabVisibleCount;
    private String[] mTitles;
    private int mTranslationX;
    private int mTriangleHeight;
    private int mTriangleWidth;
    /* access modifiers changed from: private */
    public ViewPager mViewPager;

    public interface PageOnchangeListener {
        void onPageScrollStateChanged(int i);

        void onPageScrolled(int i, float f, int i2);

        void onPageSelected(int i);
    }

    public ViewPagerIndicator(Context context) {
        this(context, null);
    }

    public ViewPagerIndicator(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mTabVisibleCount = 4;
        this.mPaint = new Paint();
        this.mPaint.setAntiAlias(true);
        this.mPaint.setColor(context.getResources().getColor(R.color.BASE_COLOR));
        this.mPaint.setStyle(Style.FILL);
        this.mPaint.setPathEffect(new CornerPathEffect(3.0f));
    }

    /* access modifiers changed from: protected */
    public void dispatchDraw(Canvas canvas) {
        if (!(this.mPath == null || this.mPaint == null)) {
            canvas.save();
            canvas.translate((float) (this.mInitTranslationX + this.mTranslationX), (float) (getHeight() + 2));
            canvas.drawPath(this.mPath, this.mPaint);
            canvas.restore();
        }
        super.dispatchDraw(canvas);
    }

    /* access modifiers changed from: protected */
    public void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        this.mScreenWidth = w;
        if (this.mTabVisibleCount > 0) {
            setVisibleTabCount(this.mTabVisibleCount);
        }
    }

    /* access modifiers changed from: protected */
    public void onFinishInflate() {
        super.onFinishInflate();
        int cCount = getChildCount();
        if (cCount != 0) {
            for (int i = 0; i < cCount; i++) {
                View view = getChildAt(i);
                LayoutParams lp = (LayoutParams) view.getLayoutParams();
                lp.weight = 0.0f;
                lp.width = getScreenWidth() / this.mTabVisibleCount;
                view.setLayoutParams(lp);
            }
            setItemClickEvent();
        }
    }

    private int getScreenWidth() {
        DisplayMetrics outMetrics = new DisplayMetrics();
        ((WindowManager) getContext().getSystemService("window")).getDefaultDisplay().getMetrics(outMetrics);
        return outMetrics.widthPixels;
    }

    private void initTriangle() {
        this.mTriangleHeight = this.mTriangleWidth;
        this.mPath = new Path();
        this.mPath.moveTo(0.0f, 0.0f);
        this.mPath.lineTo((float) this.mTriangleWidth, 0.0f);
        this.mPath.lineTo((float) this.mTriangleWidth, (float) ((-this.mTriangleHeight) / 20));
        this.mPath.lineTo(0.0f, (float) ((-this.mTriangleHeight) / 20));
        this.mPath.close();
    }

    public void scroll(int position, float offset) {
        if (this.mTabVisibleCount > 0) {
            int tabWidth = getWidth() / this.mTabVisibleCount;
            this.mTranslationX = (int) (((float) tabWidth) * (((float) position) + offset));
            if (position >= this.mTabVisibleCount - 2 && offset > 0.0f && getChildCount() > this.mTabVisibleCount) {
                if (this.mTabVisibleCount != 1) {
                    Log.e("TAG", (((position - (this.mTabVisibleCount - 2)) * tabWidth) + ((int) (((float) tabWidth) * offset))) + "");
                    scrollTo(((position - (this.mTabVisibleCount - 2)) * tabWidth) + ((int) (((float) tabWidth) * offset)), 0);
                } else {
                    scrollTo((position * tabWidth) + ((int) (((float) tabWidth) * offset)), 0);
                }
            }
        }
        invalidate();
    }

    public void setTabItemTitles(String[] lists) {
        setVisibleTabCount(lists.length);
        if (lists != null && lists.length > 0) {
            removeAllViews();
            this.mTitles = lists;
            for (String model : this.mTitles) {
                addView(generateTextView(model));
            }
            setItemClickEvent();
        }
    }

    public void setVisibleTabCount(int count) {
        this.mTabVisibleCount = count;
        this.mTriangleWidth = getScreenWidth() / this.mTabVisibleCount;
        this.mInitTranslationX = ((this.mScreenWidth / this.mTabVisibleCount) / 2) - (this.mTriangleWidth / 2);
        initTriangle();
    }

    private View generateTextView(String title) {
        FontTextView tv = new FontTextView(getContext(), getContext().getString(R.string.FONT_NANUM_BARUN_GOTHIC_BOLD));
        LayoutParams lp = new LayoutParams(-1, -1);
        lp.width = getScreenWidth() / this.mTabVisibleCount;
        tv.setText(title);
        tv.setGravity(17);
        tv.setInputType(1);
        tv.setTextSize(1, 13.0f);
        tv.setTextColor(-9077876);
        tv.setLayoutParams(lp);
        highLightTextView(0);
        return tv;
    }

    public void setOnPageChangeListener(PageOnchangeListener listener) {
        this.mListener = listener;
    }

    public void setViewPager(ViewPager viewPager, int pos) {
        this.mViewPager = viewPager;
        this.mViewPager.setOnPageChangeListener(new OnPageChangeListener() {
            public void onPageSelected(int position) {
                if (ViewPagerIndicator.this.mListener != null) {
                    ViewPagerIndicator.this.mListener.onPageSelected(position);
                }
                ViewPagerIndicator.this.highLightTextView(position);
                if (position <= ViewPagerIndicator.this.mTabVisibleCount - 2) {
                    ViewPagerIndicator.this.scrollTo(0, 0);
                }
            }

            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                ViewPagerIndicator.this.scroll(position, positionOffset);
                if (ViewPagerIndicator.this.mListener != null) {
                    ViewPagerIndicator.this.mListener.onPageScrolled(position, positionOffset, positionOffsetPixels);
                }
            }

            public void onPageScrollStateChanged(int state) {
                if (ViewPagerIndicator.this.mListener != null) {
                    ViewPagerIndicator.this.mListener.onPageScrollStateChanged(state);
                }
            }
        });
        this.mViewPager.setCurrentItem(pos);
        highLightTextView(pos);
    }

    private void resetTextViewColor() {
        for (int i = 0; i < getChildCount(); i++) {
            View view = getChildAt(i);
            if (view instanceof TextView) {
                ((TextView) view).setTextColor(-9077876);
            }
        }
    }

    /* access modifiers changed from: private */
    public void highLightTextView(int pos) {
        resetTextViewColor();
        View view = getChildAt(pos);
        if (view instanceof TextView) {
            ((TextView) view).setTextColor(-9077876);
        }
    }

    private void setItemClickEvent() {
        int cCount = getChildCount();
        for (int i = 0; i < cCount; i++) {
            final int j = i;
            getChildAt(i).setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    if (ViewPagerIndicator.this.mViewPager != null) {
                        ViewPagerIndicator.this.mViewPager.setCurrentItem(j);
                    }
                }
            });
        }
    }
}