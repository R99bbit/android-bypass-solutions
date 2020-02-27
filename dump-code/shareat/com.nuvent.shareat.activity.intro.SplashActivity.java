package com.nuvent.shareat.activity.intro;

import android.app.Dialog;
import android.content.ActivityNotFoundException;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnKeyListener;
import android.content.Intent;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.support.v7.app.AlertDialog;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.widget.FrameLayout.LayoutParams;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.adpick.advertiser.sdk.AdPickAdvertiser;
import com.crashlytics.android.answers.Answers;
import com.crashlytics.android.answers.LoginEvent;
import com.facebook.appevents.AppEventsConstants;
import com.google.android.gms.analytics.HitBuilders.ScreenViewBuilder;
import com.google.android.gms.analytics.Tracker;
import com.gun0912.tedpermission.PermissionListener;
import com.gun0912.tedpermission.TedPermission;
import com.gun0912.tedpermission.TedPermission.Builder;
import com.igaworks.adbrix.IgawAdbrix;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.ShareatApp.TrackerName;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.common.ConfirmPasswordActivity;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.intro.SignedCheckApi;
import com.nuvent.shareat.api.intro.VersionCheckApi;
import com.nuvent.shareat.event.MainActivityEvent;
import com.nuvent.shareat.event.SuccessCheckIntegrityEvent;
import com.nuvent.shareat.event.UpdateEvent;
import com.nuvent.shareat.event.UpdateLaterEvent;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.SignedModel;
import com.nuvent.shareat.model.VersionModel;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.List;

public class SplashActivity extends BaseActivity {
    public static final int REQUEST_CODE_REQUEST_SETTING = 32;
    public static final int REQUEST_TYPE_PASSWORD_CHECK = 1;
    private boolean isFirstRun = true;
    PermissionListener permissionlistener = new PermissionListener() {
        public void onPermissionGranted() {
            AppSettingManager.getInstance().setPermissionConfirm(true);
            SplashActivity.this.requestSignedCheckApiRelay();
        }

        public void onPermissionDenied(List<String> deniedPermissions) {
            AppSettingManager.getInstance().setPermissionConfirm(true);
            boolean requiredPermissionDenied = false;
            Iterator<String> it = deniedPermissions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                String permission = it.next();
                if (true != permission.equals("android.permission.READ_EXTERNAL_STORAGE")) {
                    if (true == permission.equals("android.permission.WRITE_EXTERNAL_STORAGE")) {
                        break;
                    }
                } else {
                    break;
                }
            }
            requiredPermissionDenied = true;
            if (!requiredPermissionDenied) {
                SplashActivity.this.requestSignedCheckApiRelay();
            } else {
                SplashActivity.this.permissionDeniedGuide("\uc800\uc7a5\uc18c \uc77d\uae30/\uc4f0\uae30");
            }
        }
    };
    /* access modifiers changed from: private */
    public long sTime;

    public void onEventMainThread(UpdateEvent event) {
        finish(false);
    }

    public void onEventMainThread(MainActivityEvent event) {
        finish(false);
    }

    public void onEventMainThread(UpdateLaterEvent event) {
        requestSignedCheckApi();
    }

    public void onEventMainThread(SuccessCheckIntegrityEvent event) {
        if (!event.getCode().equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            String message = "\uace0\uac1d\ub2d8\uc758 \ub514\ubc14\uc774\uc2a4\ub294 \ubb34\uacb0\uc131 \uac80\uc0ac\uc5d0 \uc2e4\ud328 \ud558\uc600\uc2b5\ub2c8\ub2e4.\n\uc6d0\ud65c\ud55c \uc0ac\uc6a9\uc744 \uc704\ud574, \uad6c\uae00 \uc2a4\ud1a0\uc5b4\uc5d0\uc11c \uc571\uc744 \ub2e4\uc2dc \ub2e4\uc6b4\ub85c\ub4dc \ud6c4 \uc774\uc6a9\ud574 \uc8fc\uc138\uc694";
            if (event.getCode().equals("-1")) {
                message = "\uace0\uac1d\ub2d8 \ud3f0\uc758 \uc778\ud130\ub137\uc774 \ube44\ud65c\uc131\ud654 \ub610\ub294, \uc778\ud130\ub137\uc774 \ubd88\uac00\ud55c \uc0c1\ud0dc \uc785\ub2c8\ub2e4.\n\uc778\ud130\ub137\uc744 \ud655\uc778 \ud558\uc2e0\ud6c4 \ub2e4\uc2dc \uc2e4\ud589\ud574 \uc8fc\uc138\uc694.";
            }
            showDialog(message, new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    SplashActivity.this.finish(false);
                }
            });
        }
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (1 == requestCode) {
            if (-1 == resultCode) {
                AppSettingManager.getInstance().setPasswordCheck(true);
                findViewById(R.id.loadingProgress).setVisibility(8);
                Intent intent = new Intent(this, MainActivity.class);
                if (getIntent().hasExtra("push")) {
                    intent.putExtra("push", getIntent().getSerializableExtra("push"));
                }
                Answers.getInstance().logLogin(new LoginEvent());
                IgawAdbrix.retention("login");
                onStartMainActivity(intent);
                return;
            }
            finish(false);
        } else if (32 == requestCode) {
            checkPermission();
        }
    }

    /* access modifiers changed from: protected */
    public void onStop() {
        super.onStop();
    }

    /* access modifiers changed from: protected */
    public void onRestart() {
        super.onRestart();
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
        if (this.isFirstRun) {
            startLoading();
            this.isFirstRun = false;
        }
    }

    private void CheckIntegrity() {
        notiIntegrityMsg(AppEventsConstants.EVENT_PARAM_VALUE_NO);
    }

    private void notiIntegrityMsg(String result) {
        if (!result.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            String message = "\uace0\uac1d\ub2d8\uc758 \ub514\ubc14\uc774\uc2a4\ub294 \ubb34\uacb0\uc131 \uac80\uc0ac\uc5d0 \uc2e4\ud328 \ud558\uc600\uc2b5\ub2c8\ub2e4.\n\uc6d0\ud65c\ud55c \uc0ac\uc6a9\uc744 \uc704\ud574, \uad6c\uae00 \uc2a4\ud1a0\uc5b4\uc5d0\uc11c \uc571\uc744 \ub2e4\uc2dc \ub2e4\uc6b4\ub85c\ub4dc \ud6c4 \uc774\uc6a9\ud574 \uc8fc\uc138\uc694";
            if (result.equals("-1")) {
                message = "\uace0\uac1d\ub2d8 \ud3f0\uc758 \uc778\ud130\ub137\uc774 \ube44\ud65c\uc131\ud654 \ub610\ub294, \uc778\ud130\ub137\uc774 \ubd88\uac00\ud55c \uc0c1\ud0dc \uc785\ub2c8\ub2e4.\n\uc778\ud130\ub137\uc744 \ud655\uc778 \ud558\uc2e0\ud6c4 \ub2e4\uc2dc \uc2e4\ud589\ud574 \uc8fc\uc138\uc694.";
            }
            showDialog(message, new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    SplashActivity.this.finish(false);
                }
            });
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_splash);
        this.sTime = System.currentTimeMillis();
        ShareatApp.getInstance().setAppStartTime(this.sTime);
        IgawAdbrix.firstTimeExperience(getResources().getString(R.string.ga_intro_chk));
        AdPickAdvertiser.init(this, "a5be44042488409735722c615310b5d3");
        try {
            Uri uri = getIntent().getData();
            if (uri != null) {
                Tracker t = ShareatApp.getInstance().getTracker(TrackerName.APP_TRACKER);
                String uriString = uri.toString();
                t.setScreenName(getResources().getString(R.string.ga_intro_chk));
                t.send(((ScreenViewBuilder) new ScreenViewBuilder().setCampaignParamsFromUrl(uriString)).build());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }

    private void startLoading() {
        ((TextView) findViewById(R.id.versionLabel)).setText(getResources().getString(R.string.VERSION_LABEL) + " " + ShareatApp.getInstance().getAppVersionName());
        requestVersionCheckApi();
        ShareatApp.getInstance();
        ShareatApp.requestSocketUrlUpdate();
    }

    public void onWindowFocusChanged(boolean hasFocus) {
        int realHeight;
        super.onWindowFocusChanged(hasFocus);
        boolean bHasMenuKey = ViewConfiguration.get(getBaseContext()).hasPermanentMenuKey();
        boolean bHasBackKey = KeyCharacterMap.deviceHasKey(4);
        if (!bHasMenuKey && !bHasBackKey) {
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
            RelativeLayout lIndicator = (RelativeLayout) findViewById(R.id.splash_backgroud);
            if (lIndicator != null) {
                LayoutParams lpIndicator = (LayoutParams) lIndicator.getLayoutParams();
                if (lpIndicator != null) {
                    Rect rect = new Rect();
                    getWindow().getDecorView().getWindowVisibleDisplayFrame(rect);
                    lpIndicator.height = realHeight - (realHeight - rect.bottom);
                    if (VERSION.SDK_INT >= 16) {
                        lIndicator.setBackground(getBaseContext().getResources().getDrawable(R.drawable.splash_backgroud_softkey));
                    } else {
                        lIndicator.setBackgroundDrawable(getBaseContext().getResources().getDrawable(R.drawable.splash_backgroud_softkey));
                    }
                    lIndicator.setLayoutParams(lpIndicator);
                }
            }
        }
    }

    /* access modifiers changed from: private */
    public boolean checkUpdate(String appVersion, String serverVersion) {
        try {
            String[] cv = appVersion.split("\\.");
            String[] lv = serverVersion.split("\\.");
            int i = 0;
            while (i < cv.length) {
                if (cv[i].equals(lv[i])) {
                    i++;
                } else if (Integer.parseInt(cv[i]) < Integer.parseInt(lv[i])) {
                    return true;
                } else {
                    return false;
                }
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /* access modifiers changed from: private */
    public void requestVersionCheckApi() {
        VersionCheckApi request = new VersionCheckApi(this);
        request.addGetParam("?gubun=U");
        request.request(new RequestHandler() {
            public void onStart() {
            }

            public void onResult(Object result) {
                final VersionModel model = (VersionModel) result;
                if (!model.isSuccess() || !SplashActivity.this.checkUpdate(ShareatApp.getInstance().getAppVersionName(), model.getVersion())) {
                    SplashActivity.this.requestSignedCheckApi();
                } else {
                    new Handler().postDelayed(new Runnable() {
                        public void run() {
                            Intent intent = new Intent(SplashActivity.this, UpdateActivity.class);
                            intent.putExtra("currentVersionName", ShareatApp.getInstance().getAppVersionName());
                            intent.putExtra("serverVersionName", model.getVersion());
                            intent.putExtra("url", model.getUrl());
                            SplashActivity.this.animActivity(intent, R.anim.fade_in_activity, R.anim.fade_out_activity);
                        }
                    }, 0);
                }
            }

            public void onFailure(Exception exception) {
                SplashActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        SplashActivity.this.requestVersionCheckApi();
                    }
                });
            }

            public void onFinish() {
                if (SplashActivity.this.sTime != -1) {
                    GAEvent.onUserTimings(SplashActivity.this, R.string.app_loading_time, System.currentTimeMillis() - SplashActivity.this.sTime, R.string.app_intro_loading_time, R.string.app_loading_time_version);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestSignedCheckApiRelay() {
        String parameter = String.format("?user_phone=%s&guid=%s", new Object[]{ShareatApp.getInstance().getPhonenumber(), ShareatApp.getInstance().getGUID()});
        SignedCheckApi request = new SignedCheckApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                SignedModel model = (SignedModel) result;
                if (!model.isSuccess() || !model.getResult().equals("Y")) {
                    SessionManager.getInstance().setHasSession(false);
                    SessionManager.getInstance().setJoinUser(false);
                    if (!(model == null || model.getAuth_token() == null || model.getAuth_token().isEmpty())) {
                        SessionManager.getInstance().setAuthToken(model.getAuth_token());
                    }
                    if (model != null && model.getResult().equals("A")) {
                        SessionManager.getInstance().setJoinUser(true);
                    }
                    SplashActivity.this.findViewById(R.id.loadingProgress).setVisibility(8);
                    if (AppSettingManager.getInstance().isStartActivity()) {
                        SplashActivity.this.onStartMainActivity();
                        return;
                    }
                    GAEvent.sessionCustomDimensions(SplashActivity.this.getResources().getString(R.string.ga_tutorial), "\ube44\ud68c\uc6d0");
                    SplashActivity.this.animActivity(new Intent(SplashActivity.this, TutorialActivity.class), R.anim.fade_in_activity, R.anim.fade_out_activity);
                    SplashActivity.this.finish(false);
                } else if (model.getAuth_token() != null && !model.getAuth_token().isEmpty()) {
                    GAEvent.sessionCustomDimensions(SplashActivity.this.getResources().getString(R.string.ga_intro_chk), "\ud68c\uc6d0");
                    SessionManager.getInstance().setAuthToken(model.getAuth_token());
                    SessionManager.getInstance().setJoinUser(false);
                    SessionManager.getInstance().setHasSession(true);
                    if (SessionManager.getInstance().getUserModel() == null || !SessionManager.getInstance().getUserModel().isEnablePassword()) {
                        SplashActivity.this.findViewById(R.id.loadingProgress).setVisibility(8);
                        Intent intent = new Intent(SplashActivity.this, MainActivity.class);
                        if (SplashActivity.this.getIntent().hasExtra("push")) {
                            intent.putExtra("push", SplashActivity.this.getIntent().getSerializableExtra("push"));
                        }
                        Answers.getInstance().logLogin(new LoginEvent());
                        IgawAdbrix.retention("login");
                        SplashActivity.this.onStartMainActivity(intent);
                        return;
                    }
                    SplashActivity.this.animActivityForResult(new Intent(SplashActivity.this, ConfirmPasswordActivity.class), 1, R.anim.modal_animation, R.anim.scale_down);
                }
            }

            public void onFinish() {
                if (SplashActivity.this.sTime != -1) {
                    GAEvent.onUserTimings(SplashActivity.this, R.string.app_loading_time, System.currentTimeMillis() - SplashActivity.this.sTime, R.string.app_intro_loading_time, R.string.app_loading_time_userchk);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void checkPermission() {
        ((Builder) ((Builder) TedPermission.with(this).setPermissionListener(this.permissionlistener)).setPermissions("android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE")).check();
    }

    /* access modifiers changed from: private */
    public void requestSignedCheckApi() {
        if (!AppSettingManager.getInstance().getPermissionConfirm()) {
            final Dialog permissionNotiDlg = new Dialog(this, 16973836);
            permissionNotiDlg.requestWindowFeature(1);
            permissionNotiDlg.getWindow().clearFlags(2);
            permissionNotiDlg.getWindow().setDimAmount(0.5f);
            permissionNotiDlg.getWindow().setFlags(32, 32);
            permissionNotiDlg.setContentView(R.layout.shareat_permission_dlg);
            permissionNotiDlg.show();
            permissionNotiDlg.setOnKeyListener(new OnKeyListener() {
                public boolean onKey(DialogInterface dialog, int keyCode, KeyEvent event) {
                    if (keyCode == 4) {
                        return true;
                    }
                    return false;
                }
            });
            permissionNotiDlg.findViewById(R.id.permission_confirm_btn).setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    permissionNotiDlg.dismiss();
                    SplashActivity.this.checkPermission();
                }
            });
            return;
        }
        checkPermission();
    }

    /* access modifiers changed from: private */
    public void permissionDeniedGuide(String guideMessage) {
        new AlertDialog.Builder(this, 2131820904).setMessage((CharSequence) getString(R.string.permission_denied_common_message, new Object[]{guideMessage})).setCancelable(false).setNegativeButton((CharSequence) "\ub2eb\uae30", (OnClickListener) new OnClickListener() {
            public void onClick(DialogInterface dialogInterface, int i) {
                SplashActivity.this.finish();
                SplashActivity.this.overridePendingTransition(0, 0);
            }
        }).setPositiveButton((CharSequence) getString(R.string.tedpermission_setting), (OnClickListener) new OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                try {
                    SplashActivity.this.startActivityForResult(new Intent("android.settings.APPLICATION_DETAILS_SETTINGS").setData(Uri.parse("package:" + SplashActivity.this.getPackageName())), 32);
                } catch (ActivityNotFoundException e) {
                    e.printStackTrace();
                    SplashActivity.this.startActivityForResult(new Intent("android.settings.MANAGE_APPLICATIONS_SETTINGS"), 32);
                }
            }
        }).show();
    }
}