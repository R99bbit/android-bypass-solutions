package com.nuvent.shareat.widget.crop;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.MotionEvent;
import com.nuvent.shareat.activity.crop.CropActivity;
import com.nuvent.shareat.util.crop.camera.RotateBitmap;
import com.nuvent.shareat.widget.crop.ImageViewTouchBase.Recycler;
import java.util.ArrayList;
import java.util.Iterator;

public class CropImageView extends ImageViewTouchBase {
    public ArrayList<HighlightView> mHighlightViews = new ArrayList<>();
    float mLastX;
    float mLastY;
    int mMotionEdge;
    HighlightView mMotionHighlightView = null;

    public /* bridge */ /* synthetic */ void center(boolean x0, boolean x1) {
        super.center(x0, x1);
    }

    public /* bridge */ /* synthetic */ void clear() {
        super.clear();
    }

    public /* bridge */ /* synthetic */ float getScale() {
        return super.getScale();
    }

    public /* bridge */ /* synthetic */ boolean onKeyDown(int x0, KeyEvent x1) {
        return super.onKeyDown(x0, x1);
    }

    public /* bridge */ /* synthetic */ boolean onKeyUp(int x0, KeyEvent x1) {
        return super.onKeyUp(x0, x1);
    }

    public /* bridge */ /* synthetic */ void setImageBitmap(Bitmap x0) {
        super.setImageBitmap(x0);
    }

    public /* bridge */ /* synthetic */ void setImageBitmapResetBase(Bitmap x0, boolean x1) {
        super.setImageBitmapResetBase(x0, x1);
    }

    public /* bridge */ /* synthetic */ void setImageRotateBitmapResetBase(RotateBitmap x0, boolean x1) {
        super.setImageRotateBitmapResetBase(x0, x1);
    }

    public /* bridge */ /* synthetic */ void setRecycler(Recycler x0) {
        super.setRecycler(x0);
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        if (this.mBitmapDisplayed.getBitmap() != null) {
            Iterator<HighlightView> it = this.mHighlightViews.iterator();
            while (it.hasNext()) {
                HighlightView hv = it.next();
                hv.mMatrix.set(getImageMatrix());
                hv.invalidate();
                if (hv.mIsFocused) {
                    centerBasedOnHighlightView(hv);
                }
            }
        }
    }

    public CropImageView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    /* access modifiers changed from: protected */
    public void zoomTo(float scale, float centerX, float centerY) {
        super.zoomTo(scale, centerX, centerY);
        Iterator<HighlightView> it = this.mHighlightViews.iterator();
        while (it.hasNext()) {
            HighlightView hv = it.next();
            hv.mMatrix.set(getImageMatrix());
            hv.invalidate();
        }
    }

    /* access modifiers changed from: protected */
    public void zoomIn() {
        super.zoomIn();
        Iterator<HighlightView> it = this.mHighlightViews.iterator();
        while (it.hasNext()) {
            HighlightView hv = it.next();
            hv.mMatrix.set(getImageMatrix());
            hv.invalidate();
        }
    }

    /* access modifiers changed from: protected */
    public void zoomOut() {
        super.zoomOut();
        Iterator<HighlightView> it = this.mHighlightViews.iterator();
        while (it.hasNext()) {
            HighlightView hv = it.next();
            hv.mMatrix.set(getImageMatrix());
            hv.invalidate();
        }
    }

    /* access modifiers changed from: protected */
    public void postTranslate(float deltaX, float deltaY) {
        super.postTranslate(deltaX, deltaY);
        for (int i = 0; i < this.mHighlightViews.size(); i++) {
            HighlightView hv = this.mHighlightViews.get(i);
            hv.mMatrix.postTranslate(deltaX, deltaY);
            hv.invalidate();
        }
    }

    private void recomputeFocus(MotionEvent event) {
        for (int i = 0; i < this.mHighlightViews.size(); i++) {
            HighlightView hv = this.mHighlightViews.get(i);
            hv.setFocus(false);
            hv.invalidate();
        }
        int i2 = 0;
        while (true) {
            if (i2 >= this.mHighlightViews.size()) {
                break;
            }
            HighlightView hv2 = this.mHighlightViews.get(i2);
            if (hv2.getHit(event.getX(), event.getY()) == 1) {
                i2++;
            } else if (!hv2.hasFocus()) {
                hv2.setFocus(true);
                hv2.invalidate();
            }
        }
        invalidate();
    }

    public boolean onTouchEvent(MotionEvent event) {
        CropActivity cropActivity = (CropActivity) getContext();
        if (cropActivity.mSaving) {
            return false;
        }
        switch (event.getAction()) {
            case 0:
                if (!cropActivity.mWaitingToPick) {
                    int i = 0;
                    while (true) {
                        if (i >= this.mHighlightViews.size()) {
                            break;
                        } else {
                            HighlightView hv = this.mHighlightViews.get(i);
                            int edge = hv.getHit(event.getX(), event.getY());
                            if (edge != 1) {
                                this.mMotionEdge = edge;
                                this.mMotionHighlightView = hv;
                                this.mLastX = event.getX();
                                this.mLastY = event.getY();
                                this.mMotionHighlightView.setMode(edge == 32 ? ModifyMode.Move : ModifyMode.Grow);
                                break;
                            } else {
                                i++;
                            }
                        }
                    }
                } else {
                    recomputeFocus(event);
                    break;
                }
            case 1:
                if (cropActivity.mWaitingToPick) {
                    for (int i2 = 0; i2 < this.mHighlightViews.size(); i2++) {
                        HighlightView hv2 = this.mHighlightViews.get(i2);
                        if (hv2.hasFocus()) {
                            cropActivity.mCrop = hv2;
                            for (int j = 0; j < this.mHighlightViews.size(); j++) {
                                if (j != i2) {
                                    this.mHighlightViews.get(j).setHidden(true);
                                }
                            }
                            centerBasedOnHighlightView(hv2);
                            ((CropActivity) getContext()).mWaitingToPick = false;
                            return true;
                        }
                    }
                } else if (this.mMotionHighlightView != null) {
                    centerBasedOnHighlightView(this.mMotionHighlightView);
                    this.mMotionHighlightView.setMode(ModifyMode.None);
                }
                this.mMotionHighlightView = null;
                break;
            case 2:
                if (!cropActivity.mWaitingToPick) {
                    if (this.mMotionHighlightView != null) {
                        this.mMotionHighlightView.handleMotion(this.mMotionEdge, event.getX() - this.mLastX, event.getY() - this.mLastY);
                        this.mLastX = event.getX();
                        this.mLastY = event.getY();
                        ensureVisible(this.mMotionHighlightView);
                        break;
                    }
                } else {
                    recomputeFocus(event);
                    break;
                }
                break;
        }
        switch (event.getAction()) {
            case 1:
                center(true, true);
                break;
            case 2:
                if (getScale() == 1.0f) {
                    center(true, true);
                    break;
                }
                break;
        }
        return true;
    }

    private void ensureVisible(HighlightView hv) {
        int panDeltaX;
        int panDeltaY;
        Rect r = hv.mDrawRect;
        int panDeltaX1 = Math.max(0, getLeft() - r.left);
        int panDeltaX2 = Math.min(0, getRight() - r.right);
        int panDeltaY1 = Math.max(0, getTop() - r.top);
        int panDeltaY2 = Math.min(0, getBottom() - r.bottom);
        if (panDeltaX1 != 0) {
            panDeltaX = panDeltaX1;
        } else {
            panDeltaX = panDeltaX2;
        }
        if (panDeltaY1 != 0) {
            panDeltaY = panDeltaY1;
        } else {
            panDeltaY = panDeltaY2;
        }
        if (panDeltaX != 0 || panDeltaY != 0) {
            panBy((float) panDeltaX, (float) panDeltaY);
        }
    }

    private void centerBasedOnHighlightView(HighlightView hv) {
        Rect drawRect = hv.mDrawRect;
        float thisWidth = (float) getWidth();
        float thisHeight = (float) getHeight();
        float zoom = Math.max(1.0f, Math.min((thisWidth / ((float) drawRect.width())) * 0.6f, (thisHeight / ((float) drawRect.height())) * 0.6f) * getScale());
        if (((double) (Math.abs(zoom - getScale()) / zoom)) > 0.1d) {
            float[] coordinates = {hv.mCropRect.centerX(), hv.mCropRect.centerY()};
            getImageMatrix().mapPoints(coordinates);
            zoomTo(zoom, coordinates[0], coordinates[1], 300.0f);
        }
        ensureVisible(hv);
    }

    /* access modifiers changed from: protected */
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        for (int i = 0; i < this.mHighlightViews.size(); i++) {
            this.mHighlightViews.get(i).draw(canvas);
        }
    }

    public void add(HighlightView hv) {
        this.mHighlightViews.add(hv);
        invalidate();
    }
}