package com.nuvent.shareat.widget.view;

import android.content.Context;
import android.support.v4.widget.SwipeRefreshLayout;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.ViewConfiguration;

public class CustomSwipeToRefresh extends SwipeRefreshLayout {
    private float mPrevX;
    private int mTouchSlop;

    public CustomSwipeToRefresh(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mTouchSlop = ViewConfiguration.get(context).getScaledTouchSlop();
    }

    public boolean onInterceptTouchEvent(MotionEvent event) {
        switch (event.getAction()) {
            case 0:
                this.mPrevX = MotionEvent.obtain(event).getX();
                break;
            case 2:
                if (Math.abs(event.getX() - this.mPrevX) > ((float) this.mTouchSlop)) {
                    return false;
                }
                break;
        }
        return super.onInterceptTouchEvent(event);
    }
}