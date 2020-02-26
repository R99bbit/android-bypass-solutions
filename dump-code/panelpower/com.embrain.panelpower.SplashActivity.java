package com.embrain.panelpower;

import android.app.AlarmManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.webkit.WebSettings;
import android.webkit.WebSettings.LayoutAlgorithm;
import android.webkit.WebView;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.NotificationCompat;
import com.embrain.panelbigdata.utils.DeviceUtils;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.hybrid.IntroWebviewJavaScript;
import com.embrain.panelpower.networks.HttpManager;
import com.embrain.panelpower.networks.vo.AppVersionVO;
import com.embrain.panelpower.networks.vo.LoginVo;
import com.embrain.panelpower.networks.vo.ResponseCheckAppVersion;
import com.embrain.panelpower.networks.vo.ResponseLogin;
import com.embrain.panelpower.utils.GoogleADIDUtils;
import com.embrain.panelpower.utils.LogUtil;
import com.embrain.panelpower.utils.PanelPreferenceUtils;
import com.embrain.panelpower.views.PanelDialog;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack.RESULT_CODE;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.InstanceIdResult;
import com.google.gson.Gson;
import com.stericson.RootShell.RootShell;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Queue;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class SplashActivity extends AppCompatActivity {
    private static final int CONFIRM_ACCESS = 20;
    private static final int EXIT = 99;
    private static final String HTML_FIRST_ACCESS = "access_android.html";
    private static final String HTML_INTRO = "intro.html";
    private static final String HTML_SPLASH = "splash.html";
    private static final int INTRO_FINISH = 60;
    private static final String LOCATION = "file:///android_asset/html/intro/";
    private static final int REQUEST_PERMISSION_NORMAL = 1002;
    private static final int SHOW_EXIT_POPUP = 82;
    private static final int SHOW_PERMISSION_DENIED_POPUP = 81;
    private static final int SHOW_TOAST = 80;
    private static final int SHOW_UPDATE_POPUP = 83;
    private List<String> ESSENTIAL_PERMISSIONS = Arrays.asList(new String[]{"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_PHONE_STATE"});
    private String[] NEED_PERMISSIONS = {"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_PHONE_STATE"};
    /* access modifiers changed from: private */
    public Queue<PROCESS> SEQUENCE;
    private boolean isFinished = false;
    private OnCompleteListener<InstanceIdResult> mCompleteListener = new OnCompleteListener<InstanceIdResult>() {
        public void onComplete(@NonNull Task<InstanceIdResult> task) {
            if (!task.isSuccessful()) {
                StringBuilder sb = new StringBuilder();
                sb.append("getInstanceId scheduleJobiled : ");
                sb.append(task.getException());
                LogUtil.write(sb.toString());
                SplashActivity.this.loginProcess();
                return;
            }
            String token = ((InstanceIdResult) task.getResult()).getToken();
            if (!StringUtils.isEmpty(token)) {
                PanelPreferenceUtils.setPushToken(SplashActivity.this.getApplicationContext(), token);
            }
        }
    };
    /* access modifiers changed from: private */
    public final ResultHandler mHandler = new ResultHandler(this);
    private IntroWebviewJavaScript mInterface = new IntroWebviewJavaScript() {
        public void onPageLoadComplete() {
            LogUtil.write("onPageLoadComplete");
        }

        public void onConfirmAccess() {
            LogUtil.write("onConfirmAccess");
            SplashActivity.this.mHandler.sendEmptyMessage(20);
        }

        public void onIntroFinish() {
            SplashActivity.this.mHandler.sendEmptyMessage(60);
        }
    };
    private Callback mLoginCallback = new Callback() {
        public void onFailure(Call call, IOException iOException) {
            StringBuilder sb = new StringBuilder();
            sb.append("Splash : Login failed : ");
            sb.append(iOException.getMessage());
            LogUtil.write(sb.toString());
        }

        public void onResponse(Call call, Response response) throws IOException {
            try {
                ResponseLogin responseLogin = (ResponseLogin) new Gson().fromJson(response.body().string(), ResponseLogin.class);
                if (responseLogin.isSuccess()) {
                    LogUtil.write("Splash : Login success");
                    return;
                }
                StringBuilder sb = new StringBuilder();
                sb.append("Splash : Login failed : ");
                sb.append(responseLogin.errorMsg);
                LogUtil.write(sb.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    };
    private WebView mWebView;

    private enum PROCESS {
        CHECK_ROOTING,
        CHECK_OLD_USER_DB,
        CHECK_APP_VERSION,
        FIRST_ACCESS,
        PERMISSION,
        AGREE,
        INTRO,
        PUSH_TOKEN,
        ADID
    }

    static class ResultHandler extends Handler {
        private final WeakReference<SplashActivity> mActivity;

        ResultHandler(SplashActivity splashActivity) {
            this.mActivity = new WeakReference<>(splashActivity);
        }

        public void handleMessage(Message message) {
            SplashActivity splashActivity = (SplashActivity) this.mActivity.get();
            if (splashActivity != null) {
                splashActivity.handleMessage(message);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        initView();
        login();
        setProcess();
        new Handler().postDelayed(new Runnable() {
            public void run() {
                SplashActivity.this.loginProcess();
            }
        }, 3000);
    }

    private void checkOldDummy() {
        AlarmManager alarmManager = (AlarmManager) getSystemService(NotificationCompat.CATEGORY_ALARM);
    }

    private void initView() {
        setContentView((int) R.layout.activity_splash);
        this.mWebView = (WebView) findViewById(R.id.webview_splash);
        WebSettings settings = this.mWebView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setSupportMultipleWindows(false);
        settings.setJavaScriptCanOpenWindowsAutomatically(false);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setSupportZoom(false);
        settings.setBuiltInZoomControls(false);
        settings.setLayoutAlgorithm(LayoutAlgorithm.SINGLE_COLUMN);
        settings.setCacheMode(2);
        settings.setDomStorageEnabled(true);
        this.mWebView.addJavascriptInterface(this.mInterface, IntroWebviewJavaScript.getName());
        loadHtml(HTML_SPLASH);
    }

    /* access modifiers changed from: private */
    public void loadHtml(String str) {
        WebView webView = this.mWebView;
        StringBuilder sb = new StringBuilder();
        sb.append(LOCATION);
        sb.append(str);
        webView.loadUrl(sb.toString());
    }

    private void setProcess() {
        this.SEQUENCE = new PriorityQueue();
        this.SEQUENCE.offer(PROCESS.CHECK_ROOTING);
        this.SEQUENCE.offer(PROCESS.CHECK_APP_VERSION);
        if (PanelPreferenceUtils.getFirstStart(getApplicationContext())) {
            this.SEQUENCE.offer(PROCESS.FIRST_ACCESS);
        }
        this.SEQUENCE.offer(PROCESS.CHECK_OLD_USER_DB);
        this.SEQUENCE.offer(PROCESS.PERMISSION);
        if (AgreeActivity.showAgree(getBaseContext())) {
            this.SEQUENCE.offer(PROCESS.AGREE);
        }
        if (PanelPreferenceUtils.getFirstStart(getApplicationContext())) {
            this.SEQUENCE.offer(PROCESS.INTRO);
        }
        this.SEQUENCE.offer(PROCESS.PUSH_TOKEN);
        this.SEQUENCE.offer(PROCESS.ADID);
    }

    /* access modifiers changed from: private */
    public synchronized void loginProcess() {
        runOnUiThread(new Runnable() {
            public void run() {
                PROCESS process = (PROCESS) SplashActivity.this.SEQUENCE.poll();
                if (process == null) {
                    SplashActivity.this.goMain();
                    return;
                }
                switch (process) {
                    case CHECK_ROOTING:
                        SplashActivity.this.checkRooting();
                        break;
                    case CHECK_OLD_USER_DB:
                        SplashActivity.this.checkOldUserDB();
                        break;
                    case CHECK_APP_VERSION:
                        SplashActivity.this.checkAppVersion();
                        break;
                    case FIRST_ACCESS:
                        SplashActivity.this.loadHtml(SplashActivity.HTML_FIRST_ACCESS);
                        break;
                    case PERMISSION:
                        SplashActivity.this.checkPermission();
                        break;
                    case AGREE:
                        SplashActivity splashActivity = SplashActivity.this;
                        splashActivity.startActivityForResult(new Intent(splashActivity, AgreeActivity.class), AgreeActivity.REQUEST_CODE_AGREE_ACTIVITY);
                        break;
                    case INTRO:
                        SplashActivity.this.loadHtml(SplashActivity.HTML_INTRO);
                        break;
                    case PUSH_TOKEN:
                        SplashActivity.this.checkToken();
                        break;
                    case ADID:
                        SplashActivity.this.checkAdId();
                        break;
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void checkRooting() {
        if (DeviceUtils.rootCheck() || RootShell.isRootAvailable()) {
            PanelDialog panelDialog = new PanelDialog((Context) this, (String) "[\uc54c\ub9bc]", (String) "\ub8e8\ud305\ub41c \uae30\uae30\uc5d0\uc11c\ub294 \uc571\uc744\n\uc2e4\ud589\ud558\uc2e4 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4.", (String) null, (String) "\uc885\ub8cc", (IDialogCallBack) new IDialogCallBack() {
                public void onCallBack(RESULT_CODE result_code) {
                    SplashActivity.this.exitPanelPower();
                }
            });
            panelDialog.show();
            return;
        }
        loginProcess();
    }

    /* access modifiers changed from: private */
    public void checkOldUserDB() {
        loginProcess();
    }

    public void checkAppVersion() {
        AppVersionVO appVersionVO = new AppVersionVO();
        appVersionVO.osTpCd = "A";
        appVersionVO.version = DeviceUtils.getAppVersion(this);
        HttpManager.getInstance().requestVersionCheck(appVersionVO, new Callback() {
            public void onFailure(Call call, IOException iOException) {
                StringBuilder sb = new StringBuilder();
                sb.append("=========");
                sb.append(iOException.toString());
                LogUtil.write(sb.toString());
                SplashActivity.this.showExitPopup((int) R.string.common_app_network_fail);
            }

            public void onResponse(Call call, Response response) throws IOException {
                try {
                    if (response.code() == 200) {
                        ResponseCheckAppVersion responseCheckAppVersion = (ResponseCheckAppVersion) new Gson().fromJson(response.body().string(), ResponseCheckAppVersion.class);
                        if (!responseCheckAppVersion.isSuccess()) {
                            SplashActivity.this.showExitPopup((int) R.string.common_app_version_check_fail);
                        } else if (responseCheckAppVersion.appVersion == null) {
                            StringBuilder sb = new StringBuilder();
                            sb.append("=========");
                            sb.append(response.toString());
                            LogUtil.write(sb.toString());
                            SplashActivity.this.showToast((int) R.string.common_app_version_check_fail);
                            SplashActivity.this.exitPanelPower();
                        } else {
                            String str = responseCheckAppVersion.appVersion.latestVersion;
                            if (StringUtils.isYn(responseCheckAppVersion.appVersion.updYn)) {
                                SplashActivity.this.mHandler.sendEmptyMessage(83);
                            } else {
                                SplashActivity.this.loginProcess();
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    SplashActivity.this.showExitPopup((int) R.string.common_app_version_check_fail);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void showExitPopup(int i) {
        showExitPopup(getString(i));
    }

    private void showExitPopup(String str) {
        Message obtainMessage = this.mHandler.obtainMessage();
        obtainMessage.what = 82;
        obtainMessage.obj = str;
        this.mHandler.sendMessage(obtainMessage);
    }

    /* access modifiers changed from: private */
    public void showToast(int i) {
        showToast(getString(i));
    }

    private void showToast(String str) {
        Message obtainMessage = this.mHandler.obtainMessage();
        obtainMessage.what = 80;
        obtainMessage.obj = str;
        this.mHandler.sendMessage(obtainMessage);
    }

    /* access modifiers changed from: private */
    public void checkPermission() {
        String[] strArr;
        if (VERSION.SDK_INT >= 23) {
            ArrayList arrayList = new ArrayList();
            for (String str : this.NEED_PERMISSIONS) {
                if (checkSelfPermission(str) != 0) {
                    arrayList.add(str);
                }
            }
            if (arrayList.size() > 0) {
                requestPermissions((String[]) arrayList.toArray(new String[arrayList.size()]), 1002);
                return;
            }
            loginProcess();
        } else {
            loginProcess();
        }
    }

    public void onRequestPermissionsResult(int i, @NonNull String[] strArr, @NonNull int[] iArr) {
        super.onRequestPermissionsResult(i, strArr, iArr);
        if (i == 1002) {
            int i2 = 0;
            while (i2 < strArr.length) {
                if (!this.ESSENTIAL_PERMISSIONS.contains(strArr[i2]) || iArr[i2] != -1) {
                    i2++;
                } else {
                    this.mHandler.sendEmptyMessage(81);
                    return;
                }
            }
            loginProcess();
        }
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int i, int i2, @Nullable Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i == 8099) {
            loginProcess();
        }
    }

    /* access modifiers changed from: private */
    public void checkToken() {
        GoogleApiAvailability.getInstance().makeGooglePlayServicesAvailable(this).addOnFailureListener(new OnFailureListener() {
            public void onFailure(@NonNull Exception exc) {
                StringBuilder sb = new StringBuilder();
                sb.append("getInstanceId scheduleJobiled : ");
                sb.append(exc.getMessage());
                LogUtil.write(sb.toString());
            }
        });
        FirebaseInstanceId.getInstance().getInstanceId().addOnCompleteListener(this.mCompleteListener);
        loginProcess();
    }

    /* access modifiers changed from: private */
    public void checkAdId() {
        GoogleADIDUtils.getGoogleADID(getApplicationContext());
        loginProcess();
    }

    private void login() {
        LoginVo loginInfo = LoginVo.getLoginInfo(getBaseContext());
        if (loginInfo != null) {
            HttpManager.getInstance().requestLogin(loginInfo, this.mLoginCallback);
        }
    }

    public void onBackPressed() {
        if ("file:///android_asset/html/intro/user_access.html".equals(this.mWebView.getUrl())) {
            this.mWebView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    /* access modifiers changed from: private */
    public void goMain() {
        if (!this.isFinished) {
            Intent intent = new Intent(this, MainActivity.class);
            try {
                Bundle extras = getIntent().getExtras();
                if (extras != null) {
                    intent.putExtras(extras);
                }
            } catch (Exception unused) {
            }
            startActivity(intent);
            finish();
        }
    }

    public void finish() {
        super.finish();
        this.isFinished = true;
    }

    /* access modifiers changed from: private */
    public void exitPanelPower() {
        this.mHandler.sendEmptyMessageDelayed(99, 1500);
    }

    /* access modifiers changed from: private */
    public void handleMessage(Message message) {
        try {
            int i = message.what;
            if (i == 20) {
                PanelPreferenceUtils.setFirstStart(getApplicationContext());
                this.mWebView.goBack();
                loginProcess();
            } else if (i == 60) {
                loginProcess();
            } else if (i != 99) {
                switch (i) {
                    case 80:
                        Toast.makeText(getApplicationContext(), (String) message.obj, 0).show();
                        return;
                    case 81:
                        PanelDialog panelDialog = new PanelDialog((Context) this, (String) "[\uc54c\ub9bc]", (String) "\ud544\uc218 \uad8c\ud55c\uc5d0 \ub3d9\uc758\ud558\uc9c0 \uc54a\uc740 \uacbd\uc73c\uc2dc\ub294 \uacbd\uc6b0 \n \uc571\uc744 \uc0ac\uc6a9\ud558\uc2e4 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4.", (String) null, (String) "\uc885\ub8cc", (IDialogCallBack) new IDialogCallBack() {
                            public void onCallBack(RESULT_CODE result_code) {
                                SplashActivity.this.exitPanelPower();
                            }
                        });
                        panelDialog.show();
                        return;
                    case 82:
                        PanelDialog panelDialog2 = new PanelDialog((Context) this, (String) "[\uc54c\ub9bc]", (String) message.obj, (String) null, (String) "\uc885\ub8cc", (IDialogCallBack) new IDialogCallBack() {
                            public void onCallBack(RESULT_CODE result_code) {
                                SplashActivity.this.exitPanelPower();
                            }
                        });
                        panelDialog2.show();
                        return;
                    case 83:
                        PanelDialog panelDialog3 = new PanelDialog((Context) this, (String) "\uc5c5\ub370\uc774\ud2b8", (String) "\uc6d0\ud65c\ud55c \uc870\uc0ac\ucc38\uc5ec\ub97c \uc704\ud574\n\ucd5c\uc2e0\ubc84\uc804\uc73c\ub85c \uc5c5\ub370\uc774\ud2b8 \ud6c4 \uc774\uc6a9\uc774 \uac00\ub2a5\ud569\ub2c8\ub2e4. \n\uc5c5\ub370\uc774\ud2b8 \ud558\uc2dc\uaca0\uc5b4\uc694?", (String) "\uc885\ub8cc", (String) "\uc5c5\ub370\uc774\ud2b8", (IDialogCallBack) new IDialogCallBack() {
                            public void onCallBack(RESULT_CODE result_code) {
                                if (result_code == RESULT_CODE.RIGHT_CLICK) {
                                    DeviceUtils.goMarket(SplashActivity.this);
                                    SplashActivity.this.exitPanelPower();
                                    return;
                                }
                                SplashActivity.this.exitPanelPower();
                            }
                        });
                        panelDialog3.show();
                        return;
                    default:
                        return;
                }
            } else {
                System.exit(0);
            }
        } catch (Exception unused) {
        }
    }
}