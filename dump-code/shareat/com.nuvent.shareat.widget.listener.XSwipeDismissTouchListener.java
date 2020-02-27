package com.nuvent.shareat.widget.listener;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.Context;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.View.OnTouchListener;
import android.view.ViewConfiguration;
import com.nuvent.shareat.R;

public class XSwipeDismissTouchListener implements OnTouchListener {
    public static final String TAG = XSwipeDismissTouchListener.class.getSimpleName();
    private boolean isOpen = false;
    private boolean isValidCard = false;
    private long mAnimationTime;
    public IMainCardViewDismiss mCallbacks;
    private Context mContext;
    private float mDownX;
    private float mDownY;
    private Boolean mIsRight;
    private int mMaxFlingVelocity;
    private int mMinFlingVelocity;
    private int mSlop;
    private boolean mSwiping;
    private int mSwipingSlop;
    private int mToken;
    private float mTranslationX;
    private VelocityTracker mVelocityTracker;
    private View mView;
    private int mViewWidth = 1;

    public interface IMainCardViewDismiss {
        boolean canDismiss(int i);

        void onDismiss(View view);

        boolean onDismiss(int i, Boolean bool);
    }

    public XSwipeDismissTouchListener(Context context, View view, Object token, IMainCardViewDismiss callBacks) {
        ViewConfiguration vc = ViewConfiguration.get(view.getContext());
        this.mSlop = vc.getScaledTouchSlop();
        this.mMinFlingVelocity = vc.getScaledMinimumFlingVelocity() * 16;
        this.mMaxFlingVelocity = vc.getScaledMaximumFlingVelocity();
        this.mAnimationTime = (long) view.getContext().getResources().getInteger(17694720);
        this.mView = view;
        this.mToken = ((Integer) token).intValue();
        this.mCallbacks = callBacks;
        this.mContext = context;
    }

    public void setValidCard(boolean isValidCard2) {
        this.isValidCard = isValidCard2;
    }

    public boolean onTouch(View view, MotionEvent motionEvent) {
        int i;
        if (!this.isValidCard) {
            return false;
        }
        if (this.mViewWidth < 2) {
            this.mViewWidth = this.mView.findViewById(R.id.cardShadowView).getWidth() - this.mContext.getResources().getDimensionPixelOffset(R.dimen.STORE_PAGE_INDICATOR_MARGIN);
        }
        motionEvent.offsetLocation(this.mTranslationX, 0.0f);
        switch (motionEvent.getActionMasked()) {
            case 0:
                this.mDownX = motionEvent.getRawX();
                this.mDownY = motionEvent.getRawY();
                if (this.mCallbacks.canDismiss(this.mToken)) {
                    this.mVelocityTracker = VelocityTracker.obtain();
                    this.mVelocityTracker.addMovement(motionEvent);
                    break;
                }
                break;
            case 1:
                if (this.mVelocityTracker != null) {
                    float deltaX = motionEvent.getRawX() - this.mDownX;
                    this.mVelocityTracker.addMovement(motionEvent);
                    this.mVelocityTracker.computeCurrentVelocity(1000);
                    float velocityX = this.mVelocityTracker.getXVelocity();
                    float absVelocityX = Math.abs(velocityX);
                    float absVelocityY = Math.abs(this.mVelocityTracker.getYVelocity());
                    boolean dismiss = false;
                    boolean dismissRight = false;
                    if (Math.abs(deltaX) > ((float) (this.mViewWidth / 2)) && this.mSwiping) {
                        dismiss = true;
                        dismissRight = deltaX > 0.0f;
                    } else if (((float) this.mMinFlingVelocity) <= absVelocityX && absVelocityX <= ((float) this.mMaxFlingVelocity) && absVelocityY < absVelocityX && absVelocityY < absVelocityX && this.mSwiping) {
                        dismiss = ((velocityX > 0.0f ? 1 : (velocityX == 0.0f ? 0 : -1)) < 0) == ((deltaX > 0.0f ? 1 : (deltaX == 0.0f ? 0 : -1)) < 0);
                        dismissRight = this.mVelocityTracker.getXVelocity() > 0.0f;
                    }
                    this.mIsRight = Boolean.valueOf(dismissRight);
                    if (dismiss) {
                        this.mView.animate().translationX(dismissRight ? 0.0f : (float) (-this.mViewWidth)).setDuration(this.mAnimationTime).setListener(new AnimatorListenerAdapter() {
                            public void onAnimationEnd(Animator animation) {
                                XSwipeDismissTouchListener.this.mCallbacks.onDismiss(0, Boolean.valueOf(true));
                            }
                        });
                    } else if (this.mSwiping) {
                        onCancelAnimateView();
                        touchInit();
                        return true;
                    }
                    touchInit();
                    break;
                } else {
                    return true;
                }
            case 2:
                if (this.mVelocityTracker != null) {
                    this.mVelocityTracker.addMovement(motionEvent);
                    float deltaX2 = motionEvent.getRawX() - this.mDownX;
                    float deltaY = motionEvent.getRawY() - this.mDownY;
                    if (Math.abs(deltaX2) > ((float) this.mSlop) && Math.abs(deltaY) < Math.abs(deltaX2) / 2.0f) {
                        this.mSwiping = true;
                        if (deltaX2 > 0.0f) {
                            onCancelAnimateView();
                            touchInit();
                            return true;
                        }
                        this.isOpen = true;
                        if (deltaX2 > 0.0f) {
                            i = this.mSlop;
                        } else {
                            i = -this.mSlop;
                        }
                        this.mSwipingSlop = i;
                        this.mView.getParent().requestDisallowInterceptTouchEvent(true);
                        MotionEvent cancelEvent = MotionEvent.obtain(motionEvent);
                        cancelEvent.setAction((motionEvent.getActionIndex() << 8) | 3);
                        this.mView.onTouchEvent(cancelEvent);
                        cancelEvent.recycle();
                    }
                    if (this.mSwiping) {
                        this.mTranslationX = deltaX2;
                        this.mView.setTranslationX(deltaX2 - ((float) this.mSwipingSlop));
                        return true;
                    }
                }
                break;
            case 3:
                if (this.mVelocityTracker != null) {
                    onCancelAnimateView();
                    touchInit();
                    break;
                }
                break;
            case 254:
                if (this.mView != null) {
                    if (!this.isOpen) {
                        this.mSwiping = true;
                        this.isOpen = true;
                        this.mView.animate().translationX((float) (-this.mViewWidth)).setDuration(this.mAnimationTime).setListener(new AnimatorListenerAdapter() {
                            public void onAnimationEnd(Animator animation) {
                                XSwipeDismissTouchListener.this.mCallbacks.onDismiss(0, Boolean.valueOf(true));
                            }
                        });
                        break;
                    } else {
                        return true;
                    }
                }
                break;
        }
        return false;
    }

    public Boolean isPayingState() {
        return this.mIsRight;
    }

    private void touchInit() {
        this.mVelocityTracker.recycle();
        this.mVelocityTracker = null;
        this.mTranslationX = 0.0f;
        this.mDownX = 0.0f;
        this.mDownY = 0.0f;
        this.mSwiping = false;
    }

    public void onCancelAnimateView() {
        try {
            if (this.isOpen) {
                this.mView.animate().translationX(0.0f).alpha(1.0f).setDuration(this.mAnimationTime).setListener(null);
                this.mCallbacks.onDismiss(0, Boolean.valueOf(false));
                this.mIsRight = Boolean.valueOf(true);
                this.isOpen = false;
                this.mSwiping = false;
            }
        } catch (Exception e) {
        }
    }
}