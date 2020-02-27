package com.igaworks.adbrix.cpe.common;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Paint.Style;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.support.v4.view.MotionEventCompat;
import android.support.v4.view.ViewConfigurationCompat;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.BaseSavedState;
import android.view.View.MeasureSpec;
import android.view.ViewConfiguration;
import com.igaworks.adbrix.util.CPEConstant;

public class CirclePageIndicator extends View implements PageIndicator {
    private static final int INVALID_POINTER = -1;
    private int mActivePointerId;
    private boolean mCentered;
    private int mCurrentPage;
    private boolean mIsDragging;
    private float mLastMotionX;
    private OnPageChangeListener mListener;
    private int mOrientation;
    private float mPageOffset;
    private final Paint mPaintFill;
    private final Paint mPaintPageFill;
    private final Paint mPaintStroke;
    private float mRadius;
    private int mScrollState;
    private boolean mSnap;
    private int mSnapPage;
    private int mTouchSlop;
    private ViewPager mViewPager;

    static class SavedState extends BaseSavedState {
        public static final Creator<SavedState> CREATOR = new Creator<SavedState>() {
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, null);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        int currentPage;

        public SavedState(Parcelable superState) {
            super(superState);
        }

        /* synthetic */ SavedState(Parcel parcel, SavedState savedState) {
            this(parcel);
        }

        private SavedState(Parcel in) {
            super(in);
            this.currentPage = in.readInt();
        }

        public void writeToParcel(Parcel dest, int flags) {
            super.writeToParcel(dest, flags);
            dest.writeInt(this.currentPage);
        }
    }

    public CirclePageIndicator(Context context) {
        this(context, null);
    }

    public CirclePageIndicator(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public CirclePageIndicator(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        this.mPaintPageFill = new Paint(1);
        this.mPaintStroke = new Paint(1);
        this.mPaintFill = new Paint(1);
        this.mLastMotionX = -1.0f;
        this.mActivePointerId = -1;
        if (!isInEditMode()) {
            Resources resources = getResources();
            int defaultPageColor = Color.parseColor("#eeeeee");
            int defaultFillColor = Color.parseColor("#ff0000");
            int defaultStrokeColor = Color.parseColor("#000000");
            float defaultStrokeWidth = (float) CPEConstant.convertPixelToDP(context, 1, true);
            this.mCentered = true;
            this.mOrientation = 0;
            this.mPaintPageFill.setStyle(Style.FILL);
            this.mPaintPageFill.setColor(defaultPageColor);
            this.mPaintStroke.setStyle(Style.STROKE);
            this.mPaintStroke.setColor(defaultStrokeColor);
            this.mPaintStroke.setStrokeWidth(defaultStrokeWidth);
            this.mPaintFill.setStyle(Style.FILL);
            this.mPaintFill.setColor(defaultFillColor);
            this.mPaintFill.setStrokeWidth(defaultStrokeWidth);
            this.mRadius = (float) CPEConstant.convertPixelToDP(context, 6, true);
            this.mSnap = true;
            Drawable background = new ColorDrawable(0);
            if (background != null) {
                setBackgroundDrawable(background);
            }
            this.mTouchSlop = ViewConfigurationCompat.getScaledPagingTouchSlop(ViewConfiguration.get(context));
        }
    }

    public void setCentered(boolean centered) {
        this.mCentered = centered;
        invalidate();
    }

    public boolean isCentered() {
        return this.mCentered;
    }

    public void setPageColor(int pageColor) {
        this.mPaintPageFill.setColor(pageColor);
        invalidate();
    }

    public int getPageColor() {
        return this.mPaintPageFill.getColor();
    }

    public void setFillColor(int fillColor) {
        this.mPaintFill.setColor(fillColor);
        invalidate();
    }

    public int getFillColor() {
        return this.mPaintFill.getColor();
    }

    public void setOrientation(int orientation) {
        switch (orientation) {
            case 0:
            case 1:
                this.mOrientation = orientation;
                requestLayout();
                return;
            default:
                throw new IllegalArgumentException("Orientation must be either HORIZONTAL or VERTICAL.");
        }
    }

    public int getOrientation() {
        return this.mOrientation;
    }

    public void setStrokeColor(int strokeColor) {
        this.mPaintStroke.setColor(strokeColor);
        invalidate();
    }

    public int getStrokeColor() {
        return this.mPaintStroke.getColor();
    }

    public void setStrokeWidth(float strokeWidth) {
        this.mPaintStroke.setStrokeWidth(strokeWidth);
        invalidate();
    }

    public float getStrokeWidth() {
        return this.mPaintStroke.getStrokeWidth();
    }

    public void setRadius(float radius) {
        this.mRadius = radius;
        invalidate();
    }

    public float getRadius() {
        return this.mRadius;
    }

    public void setSnap(boolean snap) {
        this.mSnap = snap;
        invalidate();
    }

    public boolean isSnap() {
        return this.mSnap;
    }

    /* access modifiers changed from: protected */
    public void onDraw(Canvas canvas) {
        int longSize;
        int longPaddingBefore;
        int longPaddingAfter;
        int shortPaddingBefore;
        float dX;
        float dY;
        float dX2;
        float dY2;
        super.onDraw(canvas);
        if (this.mViewPager != null) {
            int count = this.mViewPager.getAdapter().getCount();
            if (count == 0) {
                return;
            }
            if (this.mCurrentPage >= count) {
                setCurrentItem(count - 1);
                return;
            }
            if (this.mOrientation == 0) {
                longSize = getWidth();
                longPaddingBefore = getPaddingLeft();
                longPaddingAfter = getPaddingRight();
                shortPaddingBefore = getPaddingTop();
            } else {
                longSize = getHeight();
                longPaddingBefore = getPaddingTop();
                longPaddingAfter = getPaddingBottom();
                shortPaddingBefore = getPaddingLeft();
            }
            float threeRadius = this.mRadius * 3.0f;
            float shortOffset = ((float) shortPaddingBefore) + this.mRadius;
            float longOffset = ((float) longPaddingBefore) + this.mRadius;
            if (this.mCentered) {
                longOffset += (((float) ((longSize - longPaddingBefore) - longPaddingAfter)) / 2.0f) - ((((float) count) * threeRadius) / 2.0f);
            }
            float pageFillRadius = this.mRadius;
            if (this.mPaintStroke.getStrokeWidth() > 0.0f) {
                pageFillRadius -= this.mPaintStroke.getStrokeWidth() / 2.0f;
            }
            for (int iLoop = 0; iLoop < count; iLoop++) {
                float drawLong = longOffset + (((float) iLoop) * threeRadius);
                if (this.mOrientation == 0) {
                    dX2 = drawLong;
                    dY2 = shortOffset;
                } else {
                    dX2 = shortOffset;
                    dY2 = drawLong;
                }
                if (this.mPaintPageFill.getAlpha() > 0) {
                    canvas.drawCircle(dX2, dY2, pageFillRadius, this.mPaintPageFill);
                }
                if (pageFillRadius != this.mRadius) {
                    canvas.drawCircle(dX2, dY2, this.mRadius, this.mPaintStroke);
                }
            }
            float cx = ((float) (this.mSnap ? this.mSnapPage : this.mCurrentPage)) * threeRadius;
            if (!this.mSnap) {
                cx += this.mPageOffset * threeRadius;
            }
            if (this.mOrientation == 0) {
                dX = longOffset + cx;
                dY = shortOffset;
            } else {
                dX = shortOffset;
                dY = longOffset + cx;
            }
            canvas.drawCircle(dX, dY, pageFillRadius, this.mPaintFill);
        }
    }

    public boolean onTouchEvent(MotionEvent ev) {
        if (super.onTouchEvent(ev)) {
            return true;
        }
        if (this.mViewPager == null || this.mViewPager.getAdapter().getCount() == 0) {
            return false;
        }
        int action = ev.getAction() & 255;
        switch (action) {
            case 0:
                this.mActivePointerId = MotionEventCompat.getPointerId(ev, 0);
                this.mLastMotionX = ev.getX();
                break;
            case 1:
            case 3:
                if (!this.mIsDragging) {
                    int count = this.mViewPager.getAdapter().getCount();
                    int width = getWidth();
                    float halfWidth = ((float) width) / 2.0f;
                    float sixthWidth = ((float) width) / 6.0f;
                    if (this.mCurrentPage > 0 && ev.getX() < halfWidth - sixthWidth) {
                        if (action != 3) {
                            this.mViewPager.setCurrentItem(this.mCurrentPage - 1);
                        }
                        return true;
                    } else if (this.mCurrentPage < count - 1 && ev.getX() > halfWidth + sixthWidth) {
                        if (action != 3) {
                            this.mViewPager.setCurrentItem(this.mCurrentPage + 1);
                        }
                        return true;
                    }
                }
                this.mIsDragging = false;
                this.mActivePointerId = -1;
                if (this.mViewPager.isFakeDragging()) {
                    this.mViewPager.endFakeDrag();
                    break;
                }
                break;
            case 2:
                float x = MotionEventCompat.getX(ev, MotionEventCompat.findPointerIndex(ev, this.mActivePointerId));
                float deltaX = x - this.mLastMotionX;
                if (!this.mIsDragging && Math.abs(deltaX) > ((float) this.mTouchSlop)) {
                    this.mIsDragging = true;
                }
                if (this.mIsDragging) {
                    this.mLastMotionX = x;
                    if (this.mViewPager.isFakeDragging() || this.mViewPager.beginFakeDrag()) {
                        this.mViewPager.fakeDragBy(deltaX);
                        break;
                    }
                }
                break;
            case 5:
                int index = MotionEventCompat.getActionIndex(ev);
                this.mLastMotionX = MotionEventCompat.getX(ev, index);
                this.mActivePointerId = MotionEventCompat.getPointerId(ev, index);
                break;
            case 6:
                int pointerIndex = MotionEventCompat.getActionIndex(ev);
                if (MotionEventCompat.getPointerId(ev, pointerIndex) == this.mActivePointerId) {
                    this.mActivePointerId = MotionEventCompat.getPointerId(ev, pointerIndex == 0 ? 1 : 0);
                }
                this.mLastMotionX = MotionEventCompat.getX(ev, MotionEventCompat.findPointerIndex(ev, this.mActivePointerId));
                break;
        }
        return true;
    }

    public void setViewPager(ViewPager view) {
        if (this.mViewPager != view) {
            if (this.mViewPager != null) {
                this.mViewPager.setOnPageChangeListener(null);
            }
            if (view.getAdapter() == null) {
                throw new IllegalStateException("ViewPager does not have adapter instance.");
            }
            this.mViewPager = view;
            this.mViewPager.setOnPageChangeListener(this);
            invalidate();
        }
    }

    public void setViewPager(ViewPager view, int initialPosition) {
        setViewPager(view);
        setCurrentItem(initialPosition);
    }

    public void setCurrentItem(int item) {
        if (this.mViewPager == null) {
            throw new IllegalStateException("ViewPager has not been bound.");
        }
        this.mViewPager.setCurrentItem(item);
        this.mCurrentPage = item;
        invalidate();
    }

    public void notifyDataSetChanged() {
        invalidate();
    }

    public void onPageScrollStateChanged(int state) {
        this.mScrollState = state;
        if (this.mListener != null) {
            this.mListener.onPageScrollStateChanged(state);
        }
    }

    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
        this.mCurrentPage = position;
        this.mPageOffset = positionOffset;
        invalidate();
        if (this.mListener != null) {
            this.mListener.onPageScrolled(position, positionOffset, positionOffsetPixels);
        }
    }

    public void onPageSelected(int position) {
        if (this.mSnap || this.mScrollState == 0) {
            this.mCurrentPage = position;
            this.mSnapPage = position;
            invalidate();
        }
        if (this.mListener != null) {
            this.mListener.onPageSelected(position);
        }
    }

    public void setOnPageChangeListener(OnPageChangeListener listener) {
        this.mListener = listener;
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        if (this.mOrientation == 0) {
            setMeasuredDimension(measureLong(widthMeasureSpec), measureShort(heightMeasureSpec));
        } else {
            setMeasuredDimension(measureShort(widthMeasureSpec), measureLong(heightMeasureSpec));
        }
    }

    private int measureLong(int measureSpec) {
        int specMode = MeasureSpec.getMode(measureSpec);
        int specSize = MeasureSpec.getSize(measureSpec);
        if (specMode == 1073741824 || this.mViewPager == null) {
            return specSize;
        }
        int count = this.mViewPager.getAdapter().getCount();
        int result = (int) (((float) (getPaddingLeft() + getPaddingRight())) + (((float) (count * 2)) * this.mRadius) + (((float) (count - 1)) * this.mRadius) + 1.0f);
        if (specMode == Integer.MIN_VALUE) {
            return Math.min(result, specSize);
        }
        return result;
    }

    private int measureShort(int measureSpec) {
        int specMode = MeasureSpec.getMode(measureSpec);
        int specSize = MeasureSpec.getSize(measureSpec);
        if (specMode == 1073741824) {
            return specSize;
        }
        int result = (int) ((2.0f * this.mRadius) + ((float) getPaddingTop()) + ((float) getPaddingBottom()) + 1.0f);
        if (specMode == Integer.MIN_VALUE) {
            return Math.min(result, specSize);
        }
        return result;
    }

    public void onRestoreInstanceState(Parcelable state) {
        SavedState savedState = (SavedState) state;
        super.onRestoreInstanceState(savedState.getSuperState());
        this.mCurrentPage = savedState.currentPage;
        this.mSnapPage = savedState.currentPage;
        requestLayout();
    }

    public Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        savedState.currentPage = this.mCurrentPage;
        return savedState;
    }
}