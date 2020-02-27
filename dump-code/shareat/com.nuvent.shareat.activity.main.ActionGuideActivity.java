package com.nuvent.shareat.activity.main;

import android.graphics.Rect;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.KeyCharacterMap;
import android.view.MotionEvent;
import android.view.ViewConfiguration;
import android.widget.FrameLayout.LayoutParams;
import android.widget.LinearLayout;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.manager.LoplatManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import java.lang.reflect.Method;

public class ActionGuideActivity extends BaseActivity {
    private boolean mResizeLayout = false;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        setContentView(R.layout.activity_action_guide);
        LoplatManager.getInstance(this).setRunningActionGuideActivity(true);
        String strType = getIntent().getStringExtra(KakaoTalkLinkProtocol.ACTION_TYPE);
        if (strType == null) {
            return;
        }
        if (true == strType.equals("main")) {
            boolean bHasMenuKey = ViewConfiguration.get(getBaseContext()).hasPermanentMenuKey();
            boolean bHasBackKey = KeyCharacterMap.deviceHasKey(4);
            if (bHasMenuKey || bHasBackKey) {
                findViewById(R.id.action_guide).setBackgroundResource(R.drawable.main_list_action_guide);
            } else {
                findViewById(R.id.action_guide).setBackgroundResource(R.drawable.main_list_action_guide_softkey);
            }
            AppSettingManager.getInstance().setMainListActionGuideStatus(true);
            this.mResizeLayout = false;
        } else if (strType.equals("cardview_normal")) {
            findViewById(R.id.action_guide).setBackgroundResource(R.drawable.card_view_normal_action_guide);
            AppSettingManager.getInstance().setCardviewActionGuideStatus(true);
            this.mResizeLayout = true;
        } else if (strType.equals("cardview_research")) {
            findViewById(R.id.action_guide).setBackgroundResource(R.drawable.card_view_research_action_guide);
            AppSettingManager.getInstance().setCardviewActionGuideStatus(true);
            this.mResizeLayout = true;
        } else if (strType.equals("cardview_search")) {
            findViewById(R.id.action_guide).setBackgroundResource(R.drawable.card_view_search_action_guide);
            AppSettingManager.getInstance().setCardviewActionGuideStatus(true);
            this.mResizeLayout = true;
        } else if (strType.equals("cardview_password")) {
            findViewById(R.id.action_guide).setBackgroundResource(R.drawable.card_view_password_action_guide);
            AppSettingManager.getInstance().setCardviewActionGuideStatus(true);
            this.mResizeLayout = true;
        } else if (strType.equals("naver_map")) {
            boolean bHasMenuKey2 = ViewConfiguration.get(getBaseContext()).hasPermanentMenuKey();
            boolean bHasBackKey2 = KeyCharacterMap.deviceHasKey(4);
            if (bHasMenuKey2 || bHasBackKey2) {
                findViewById(R.id.action_guide).setBackgroundResource(R.drawable.naver_map_action_guide);
            } else {
                findViewById(R.id.action_guide).setBackgroundResource(R.drawable.naver_map_action_guide_softkey);
            }
            AppSettingManager.getInstance().setNaverMapActionGuideStatus(true);
            this.mResizeLayout = false;
        } else {
            finish(R.anim.fade_in_activity, R.anim.fade_out_activity);
        }
    }

    public void onBackPressed() {
        super.onBackPressed();
        LoplatManager.getInstance(this).setRunningActionGuideActivity(false);
        finish(R.anim.fade_in_activity, R.anim.fade_out_activity);
    }

    public boolean onTouchEvent(MotionEvent event) {
        if (event.getAction() != 1) {
            return super.onTouchEvent(event);
        }
        LoplatManager.getInstance(this).setRunningActionGuideActivity(false);
        finish(R.anim.fade_in_activity, R.anim.fade_out_activity);
        return false;
    }

    public void onWindowFocusChanged(boolean hasFocus) {
        int realHeight;
        super.onWindowFocusChanged(hasFocus);
        boolean bHasMenuKey = ViewConfiguration.get(getBaseContext()).hasPermanentMenuKey();
        boolean bHasBackKey = KeyCharacterMap.deviceHasKey(4);
        if (this.mResizeLayout && !bHasMenuKey && !bHasBackKey) {
            this.mResizeLayout = false;
            Display display = getWindowManager().getDefaultDisplay();
            if (VERSION.SDK_INT >= 17) {
                DisplayMetrics realMetrics = new DisplayMetrics();
                display.getRealMetrics(realMetrics);
                int realWidth = realMetrics.widthPixels;
                realHeight = realMetrics.heightPixels;
            } else if (VERSION.SDK_INT >= 14) {
                try {
                    Method mGetRawH = Display.class.getMethod("getRawHeight", new Class[0]);
                    int realWidth2 = ((Integer) Display.class.getMethod("getRawWidth", new Class[0]).invoke(display, new Object[0])).intValue();
                    realHeight = ((Integer) mGetRawH.invoke(display, new Object[0])).intValue();
                } catch (Exception e) {
                    int realWidth3 = display.getWidth();
                    realHeight = display.getHeight();
                }
            } else {
                int realWidth4 = display.getWidth();
                realHeight = display.getHeight();
            }
            LinearLayout lIndicator = (LinearLayout) findViewById(R.id.action_guide);
            if (lIndicator != null) {
                LayoutParams lpIndicator = (LayoutParams) lIndicator.getLayoutParams();
                if (lpIndicator != null) {
                    Rect rect = new Rect();
                    getWindow().getDecorView().getWindowVisibleDisplayFrame(rect);
                    lpIndicator.height = realHeight - (realHeight - rect.bottom);
                    lIndicator.setLayoutParams(lpIndicator);
                }
            }
        }
    }
}