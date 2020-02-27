package com.nuvent.shareat.util;

import android.app.Activity;
import android.content.res.Resources;
import android.graphics.Rect;
import android.os.Build.VERSION;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.KeyCharacterMap;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import java.lang.reflect.Method;

public class AndroidBug5497Workaround {
    private LayoutParams frameLayoutParams;
    private View mChildOfContent;
    private int realHeight = 0;
    private int softKeyHeight = 0;
    private int usableHeightPrevious;

    public static void assistActivity(Activity activity, int rootId) {
        new AndroidBug5497Workaround(activity, rootId);
    }

    private AndroidBug5497Workaround(final Activity activity, int rootId) {
        FrameLayout content = (FrameLayout) activity.findViewById(16908290);
        this.softKeyHeight = true == isIncludeSoftKey(activity) ? getSoftMenuHeight(activity) : 0;
        this.mChildOfContent = content.getChildAt(0);
        this.mChildOfContent.getViewTreeObserver().addOnGlobalLayoutListener(new OnGlobalLayoutListener() {
            public void onGlobalLayout() {
                AndroidBug5497Workaround.this.possiblyResizeChildOfContent(activity);
            }
        });
        this.frameLayoutParams = (LayoutParams) this.mChildOfContent.getLayoutParams();
    }

    /* access modifiers changed from: private */
    public void possiblyResizeChildOfContent(Activity activity) {
        int usableHeightNow = computeUsableHeight(activity);
        if (usableHeightNow != this.usableHeightPrevious) {
            int usableHeightSansKeyboard = this.mChildOfContent.getRootView().getHeight() - this.softKeyHeight;
            int heightDifference = usableHeightSansKeyboard - usableHeightNow;
            if (heightDifference > usableHeightSansKeyboard / 4) {
                this.frameLayoutParams.height = usableHeightSansKeyboard - heightDifference;
            } else {
                this.frameLayoutParams.height = usableHeightSansKeyboard;
            }
            this.mChildOfContent.requestLayout();
            this.usableHeightPrevious = usableHeightNow;
        }
    }

    private int computeUsableHeight(Activity activity) {
        Rect frame = new Rect();
        activity.getWindow().getDecorView().getWindowVisibleDisplayFrame(frame);
        int statusBarHeight = frame.top;
        Rect r = new Rect();
        this.mChildOfContent.getWindowVisibleDisplayFrame(r);
        if (VERSION.SDK_INT >= 19) {
            return (r.bottom - r.top) + statusBarHeight;
        }
        return r.bottom - r.top;
    }

    private int getSoftMenuHeight(Activity activity) {
        Resources resources = activity.getResources();
        int resourceId = resources.getIdentifier("navigation_bar_height", "dimen", "android");
        if (resourceId > 0) {
            return resources.getDimensionPixelSize(resourceId);
        }
        return 0;
    }

    private boolean isIncludeSoftKey(Activity activity) {
        boolean bHasMenuKey = ViewConfiguration.get(activity).hasPermanentMenuKey();
        boolean bHasBackKey = KeyCharacterMap.deviceHasKey(4);
        if (bHasMenuKey || bHasBackKey) {
            return false;
        }
        return true;
    }

    private int getRealHeight(Activity activity) {
        boolean bHasMenuKey = ViewConfiguration.get(activity).hasPermanentMenuKey();
        boolean bHasBackKey = KeyCharacterMap.deviceHasKey(4);
        if (bHasMenuKey || bHasBackKey) {
            return 0;
        }
        Display display = ((WindowManager) activity.getSystemService("window")).getDefaultDisplay();
        if (VERSION.SDK_INT >= 17) {
            DisplayMetrics realMetrics = new DisplayMetrics();
            display.getRealMetrics(realMetrics);
            int realWidth = realMetrics.widthPixels;
            return realMetrics.heightPixels;
        } else if (VERSION.SDK_INT >= 14) {
            try {
                Method mGetRawH = Display.class.getMethod("getRawHeight", new Class[0]);
                int realWidth2 = ((Integer) Display.class.getMethod("getRawWidth", new Class[0]).invoke(display, new Object[0])).intValue();
                return ((Integer) mGetRawH.invoke(display, new Object[0])).intValue();
            } catch (Exception e) {
                int realWidth3 = display.getWidth();
                return display.getHeight();
            }
        } else {
            int realWidth4 = display.getWidth();
            return display.getHeight();
        }
    }
}