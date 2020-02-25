package com.embrain.panelpower;

import android.annotation.SuppressLint;
import android.app.DownloadManager;
import android.app.DownloadManager.Request;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Message;
import android.view.View;
import android.webkit.DownloadListener;
import android.webkit.MimeTypeMap;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebSettings.LayoutAlgorithm;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.UserInfoManager.UserInfo;
import com.embrain.panelpower.fcm.FireBaseMessagingService;
import com.embrain.panelpower.hybrid.MainWebViewJavaScript;
import com.embrain.panelpower.hybrid.PanelWebChromeClient;
import com.embrain.panelpower.networks.vo.LoginVo;
import com.embrain.panelpower.ui.FloatingView;
import com.embrain.panelpower.utils.FirebaseAnalyticsLog;
import com.embrain.panelpower.utils.LogUtil;
import com.embrain.panelpower.utils.OtherPackageUtils;
import com.embrain.panelpower.views.PanelDialog;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack.RESULT_CODE;
import com.embrain.panelpower.views.SharePopup;
import com.embrain.panelpower.views.SharePopup.OnShareClickListener;
import com.embrain.panelpower.vo.DeviceInfo;
import com.embrain.panelpower.vo.ShareInfo;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.lang.ref.WeakReference;
import java.net.URISyntaxException;
import java.util.ArrayList;

@SuppressLint({"SetJavaScriptEnabled"})
public class MainActivity extends AppCompatActivity {
    private static final int EXIT_APP = 999;
    private static final int LOAD_MAIN = 101;
    private static final int LOAD_URL = 100;
    public static final int REQUEST_SETTINGS = 999;
    public static final int REQUEST_SURVEY = 777;
    private static ArrayList<String> URL_EXCEPTION_JOIN = new ArrayList<>();
    private static final String URL_EXCEPT_EVENT_LIST = "/user/survey/online/list";
    private static final String URL_EXCEPT_RELOAD_INFORM = "https://www.panel.co.kr/mobile/main/inform.do";
    private static final String URL_EXCEPT_RESUME_EVENT = "https://www.panel.co.kr/mobile/event";
    private static final String URL_EXCEPT_RESUME_SURVEY = "https://www.panel.co.kr/mobile/symposium";
    private static final String URL_EXCEPT_SURVEY = "http://isurvey.panel.co.kr";
    public static final String URL_EXCEPT_SURVEY2 = "https://www.panel.co.kr/athnt";
    private static final String URL_EXCEPT_SURVEY_S = "https://isurvey.panel.co.kr";
    private static final String URL_JOIN_FIND_ID = "https://www.panel.co.kr/mobile/login/findId.do";
    private static final String URL_JOIN_FINISH = "https://www.panel.co.kr/mobile/join/join_finish.do";
    private static final String URL_JOIN_HOST = "https://www.panel.co.kr/mobile/join";
    public static final String URL_MAIN = "https://www.panel.co.kr/mobile/main/main.do";
    public static final String URL_MEMBER_TEMP = "https://www.panel.co.kr/mobile/login/login_human_mail.do";
    private static final String URL_NICE_AUTH_FINISH = "https://nice.checkplus.co.kr/CheckPlusSafeModel/checkplus.cb";
    /* access modifiers changed from: private */
    public static boolean isFirst = true;
    /* access modifiers changed from: private */
    public static boolean loading = false;
    private DownloadListener mDownloadListener = new DownloadListener() {
        public void onDownloadStart(String str, String str2, String str3, String str4, long j) {
            try {
                str4 = MimeTypeMap.getSingleton().getMimeTypeFromExtension(str3.substring(str3.lastIndexOf(".") + 1));
            } catch (Exception e) {
                e.printStackTrace();
            }
            Request request = new Request(Uri.parse(str));
            request.allowScanningByMediaScanner();
            request.setNotificationVisibility(1);
            request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, "");
            request.setMimeType(str4);
            ((DownloadManager) MainActivity.this.getSystemService("download")).enqueue(request);
            Toast.makeText(MainActivity.this.getApplicationContext(), "\ud30c\uc77c\uc744 \ub2e4\uc6b4\ub85c\ub4dc \ud569\ub2c8\ub2e4.", 1).show();
        }
    };
    /* access modifiers changed from: private */
    public FloatingView mFloatingView;
    /* access modifiers changed from: private */
    public final ResultHandler mHandler = new ResultHandler(this);
    private MainWebViewJavaScript mInterface = new MainWebViewJavaScript() {
        public int clickShareBtn() {
            return 0;
        }

        public void onPageLoadComplete() {
            LogUtil.write("onPageLoadComplete");
        }

        public void finishApp() {
            MainActivity.this.mHandler.sendEmptyMessage(999);
        }

        public void onCallSettings() {
            MainActivity.this.callSetting();
        }

        public void onCallOtherPage(String str) {
            if (str.contains(MainActivity.URL_EXCEPT_EVENT_LIST)) {
                OtherPackageUtils.goBrowser(MainActivity.this, str);
            } else if (str.startsWith(MainActivity.URL_EXCEPT_SURVEY) || str.startsWith(MainActivity.URL_EXCEPT_SURVEY_S) || str.startsWith(MainActivity.URL_EXCEPT_SURVEY2)) {
                Intent intent = new Intent(MainActivity.this.getBaseContext(), SurveyActivity.class);
                intent.putExtra(SurveyActivity.EXTRA_SURVEY_URL, str);
                MainActivity.this.startActivityForResult(intent, MainActivity.REQUEST_SURVEY);
            } else if (str.startsWith(PanelApplication.URL_SURVEY_DEFAULT)) {
                Intent intent2 = new Intent(MainActivity.this.getBaseContext(), SurveyActivity.class);
                intent2.putExtra(SurveyActivity.EXTRA_SURVEY_URL, str);
                MainActivity.this.startActivityForResult(intent2, MainActivity.REQUEST_SURVEY);
            } else {
                Intent intent3 = new Intent(MainActivity.this, PopupBrowserActivity.class);
                intent3.putExtra(PopupBrowserActivity.EXTRA_URL, str);
                MainActivity.this.startActivity(intent3);
            }
        }

        public void onCallOtherBrowser(String str) {
            OtherPackageUtils.goBrowser(MainActivity.this.getBaseContext(), str);
        }

        public void onCallSurvey(String str, String str2) {
            if (StringUtils.isEmpty(str2) || StringUtils.isEmpty(str)) {
                MainActivity.this.toast((String) "\uc798\ubabb\ub41c \uc870\uc0ac \uc815\ubcf4\uc785\ub2c8\ub2e4.");
                return;
            }
            Intent intent = new Intent(MainActivity.this.getBaseContext(), SurveyActivity.class);
            intent.putExtra(SurveyActivity.EXTRA_SURVEY_ID, str2);
            MainActivity.this.startActivityForResult(intent, MainActivity.REQUEST_SURVEY);
        }

        public void onCallSurveyWithUrl(String str) {
            Intent intent = new Intent(MainActivity.this.getBaseContext(), SurveyActivity.class);
            intent.putExtra(SurveyActivity.EXTRA_SURVEY_URL, str);
            MainActivity.this.startActivityForResult(intent, MainActivity.REQUEST_SURVEY);
        }

        public boolean onLogin(String str) {
            try {
                if (!UserInfoManager.LOGIN_FAILED_INVALID_LOGIN.equals(str) && !UserInfoManager.LOGIN_FAILED_INVALID_CAPTCHA.equals(str)) {
                    if (!UserInfoManager.LOGIN_FAILED_INVALID_ETC.equals(str)) {
                        return UserInfoManager.getInstance(MainActivity.this.getBaseContext()).setUserInfo((UserInfo) new Gson().fromJson(str, UserInfo.class));
                    }
                }
                UserInfoManager.getInstance(MainActivity.this.getBaseContext()).deleteUserInfo();
                return false;
            } catch (Exception e) {
                MainActivity mainActivity = MainActivity.this;
                StringBuilder sb = new StringBuilder();
                sb.append("\ub85c\uadf8\uc778 \uc815\ubcf4 \uc800\uc7a5\uc5d0 \uc2e4\ud328\ud588\uc2b5\ub2c8\ub2e4. : ");
                sb.append(str);
                mainActivity.toast(sb.toString());
                e.printStackTrace();
                return false;
            }
        }

        public void onChangePassword(String str) {
            UserInfoManager.getInstance(MainActivity.this.getBaseContext()).setPassword(str);
        }

        public void onLogout() {
            try {
                UserInfoManager.getInstance(MainActivity.this.getBaseContext()).deleteUserInfo();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public String onRequestLoginInfo() {
            LoginVo loginInfo = LoginVo.getLoginInfo(MainActivity.this);
            if (loginInfo == null) {
                return new DeviceInfo(MainActivity.this.getApplicationContext()).toJson();
            }
            return loginInfo.toJson();
        }

        public String onRequestDeviceInfo() {
            return new DeviceInfo(MainActivity.this.getApplicationContext()).toJson();
        }

        public void showSharePopup(ShareInfo shareInfo) {
            new SharePopup(MainActivity.this, shareInfo, new OnShareClickListener() {
                public void onClickBtn(String str) {
                    MainActivity.this.callbackSharePopup(str);
                }
            }).show();
        }

        public void firebaseLogEvent(String str) {
            FirebaseAnalyticsLog.getInstance(MainActivity.this).logEvent(str);
        }

        public void onToast(String str) {
            MainActivity.this.toast(str);
        }
    };
    private WebSettings mSettings;
    /* access modifiers changed from: private */
    public View mTempView;
    public String mUrlForReload;
    /* access modifiers changed from: private */
    public WebView mWebView;
    private WebViewClient mWebviewClient = new WebViewClient() {
        private static final String URL_ALRAM = "https://www.panel.co.kr/mobile/main/inform.do";

        public boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest webResourceRequest) {
            String uri = webResourceRequest.getUrl().toString();
            if (uri.startsWith("tel:")) {
                MainActivity.this.startActivity(new Intent("android.intent.action.DIAL", Uri.parse(uri)));
                return true;
            } else if (uri.startsWith("sms:")) {
                MainActivity.this.startActivity(new Intent("android.intent.action.SENDTO", Uri.parse(uri)));
                return true;
            } else if (uri.startsWith(MainActivity.URL_EXCEPT_SURVEY2)) {
                Intent intent = new Intent(MainActivity.this.getBaseContext(), SurveyActivity.class);
                intent.putExtra(SurveyActivity.EXTRA_SURVEY_URL, uri);
                MainActivity.this.startActivityForResult(intent, MainActivity.REQUEST_SURVEY);
                return true;
            } else if (uri.startsWith("intent://sktauth")) {
                Intent intent2 = null;
                try {
                    Intent parseUri = Intent.parseUri(uri, 1);
                    if (parseUri != null) {
                        webView.getContext().startActivity(parseUri);
                    }
                } catch (URISyntaxException unused) {
                } catch (ActivityNotFoundException unused2) {
                    String str = intent2.getPackage();
                    if (!str.equals("")) {
                        Context context = webView.getContext();
                        StringBuilder sb = new StringBuilder();
                        sb.append("market://details?id=");
                        sb.append(str);
                        context.startActivity(new Intent("android.intent.action.VIEW", Uri.parse(sb.toString())));
                    }
                }
                return true;
            } else if (!uri.startsWith("https://play.google.com/store/apps/details?id=") && !uri.startsWith("market://details?id=")) {
                return false;
            } else {
                String queryParameter = Uri.parse(uri).getQueryParameter("id");
                if (queryParameter != null && !queryParameter.equals("")) {
                    MainActivity mainActivity = MainActivity.this;
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("market://details?id=");
                    sb2.append(queryParameter);
                    mainActivity.startActivity(new Intent("android.intent.action.VIEW", Uri.parse(sb2.toString())));
                }
                return true;
            }
        }

        public void onPageStarted(WebView webView, String str, Bitmap bitmap) {
            super.onPageStarted(webView, str, bitmap);
            MainActivity.this.mUrlForReload = str;
            MainActivity.loading = true;
        }

        public void onPageFinished(WebView webView, String str) {
            super.onPageFinished(webView, str);
            MainActivity.loading = false;
            try {
                if (MainActivity.this.mTempView.getVisibility() == 0) {
                    MainActivity.this.mTempView.setVisibility(8);
                }
                if (MainActivity.URL_MAIN.equals(str)) {
                    setBlue();
                    webView.clearHistory();
                    if (MainActivity.this.mFloatingView != null) {
                        MainActivity.this.mFloatingView.show();
                    }
                    if (MainActivity.isFirst) {
                        MainActivity.isFirst = false;
                        MainActivity.this.callGetLogin();
                        MainActivity.this.callResetSession();
                        return;
                    }
                    return;
                }
                setWhite();
                if (!(MainActivity.this.mFloatingView == null || MainActivity.this.mFloatingView.getVisibility() == 8)) {
                    MainActivity.this.mFloatingView.setVisibility(8);
                }
                if (URL_ALRAM.equals(str)) {
                    FireBaseMessagingService.clearBadge(MainActivity.this.getBaseContext());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void setBlue() {
            if (VERSION.SDK_INT >= 23) {
                MainActivity.this.getWindow().getDecorView().setSystemUiVisibility(MainActivity.this.getWindow().getDecorView().getSystemUiVisibility() ^ 8192);
                MainActivity.this.getWindow().setStatusBarColor(Color.parseColor("#225ce3"));
            }
        }

        private void setWhite() {
            if (VERSION.SDK_INT >= 23) {
                MainActivity.this.getWindow().getDecorView().setSystemUiVisibility(MainActivity.this.getWindow().getDecorView().getSystemUiVisibility() | 8192);
                MainActivity.this.getWindow().setStatusBarColor(-1);
            }
        }
    };

    static class ResultHandler extends Handler {
        private final WeakReference<MainActivity> mActivity;

        ResultHandler(MainActivity mainActivity) {
            this.mActivity = new WeakReference<>(mainActivity);
        }

        public void handleMessage(Message message) {
            MainActivity mainActivity = (MainActivity) this.mActivity.get();
            if (mainActivity != null) {
                mainActivity.handleMessage(message);
            }
        }
    }

    private void initNative() {
    }

    /* access modifiers changed from: protected */
    public void onCreate(@Nullable Bundle bundle) {
        super.onCreate(bundle);
        isFirst = true;
        setContentView((int) R.layout.activity_main);
        initUI();
        loadMain();
        initNative();
    }

    /* access modifiers changed from: protected */
    public void onRestart() {
        super.onRestart();
        try {
            String url = this.mWebView.getUrl();
            if (!url.startsWith(URL_EXCEPT_RESUME_EVENT) && !url.startsWith(URL_EXCEPT_RESUME_SURVEY)) {
                String user_id = UserInfoManager.getInstance(getBaseContext()).getUserInfo().getUser_id();
                if (!StringUtils.isEmpty(user_id)) {
                    callResetSession(user_id);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initUI() {
        this.mWebView = (WebView) findViewById(R.id.webview_main);
        this.mFloatingView = (FloatingView) findViewById(R.id.view_floating);
        this.mTempView = findViewById(R.id.temp);
        initWebView();
    }

    private void initWebView() {
        this.mSettings = this.mWebView.getSettings();
        this.mSettings.setJavaScriptEnabled(true);
        this.mSettings.setLoadWithOverviewMode(true);
        this.mSettings.setUseWideViewPort(true);
        this.mSettings.setLayoutAlgorithm(LayoutAlgorithm.SINGLE_COLUMN);
        this.mSettings.setCacheMode(2);
        this.mSettings.setDomStorageEnabled(true);
        this.mSettings.setLoadsImagesAutomatically(true);
        this.mSettings.setSupportMultipleWindows(true);
        this.mSettings.setJavaScriptCanOpenWindowsAutomatically(true);
        this.mWebView.setWebChromeClient(new PanelWebChromeClient(this));
        this.mWebView.setWebViewClient(this.mWebviewClient);
        this.mWebView.setDownloadListener(this.mDownloadListener);
        WebView webView = this.mWebView;
        MainWebViewJavaScript mainWebViewJavaScript = this.mInterface;
        webView.addJavascriptInterface(mainWebViewJavaScript, mainWebViewJavaScript.getName());
    }

    private void loadMain() {
        this.mHandler.sendEmptyMessage(101);
    }

    static {
        URL_EXCEPTION_JOIN.add("https://www.panel.co.kr/mobile/join/terms/terms_access.do");
        URL_EXCEPTION_JOIN.add("https://www.panel.co.kr/mobile/join/terms/terms_privacy.do");
        URL_EXCEPTION_JOIN.add("https://www.panel.co.kr/mobile/join/terms/terms_privacy_add.do");
    }

    /* JADX WARNING: Code restructure failed: missing block: B:14:0x003f, code lost:
        return;
     */
    public synchronized void onBackPressed() {
        if (!loading) {
            try {
                if (this.mWebView.getUrl().startsWith(URL_JOIN_HOST)) {
                    if (URL_EXCEPTION_JOIN.contains(this.mWebView.getUrl())) {
                        callTermBack();
                    } else {
                        PanelDialog panelDialog = new PanelDialog((Context) this, (String) "[\uc54c\ub9bc]", (String) "\ud328\ub110 \uac00\uc785\uc744 \uc911\ub2e8\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?", (String) "\ucde8\uc18c", (String) "\ud655\uc778", (IDialogCallBack) new IDialogCallBack() {
                            public void onCallBack(RESULT_CODE result_code) {
                                if (RESULT_CODE.RIGHT_CLICK.equals(result_code)) {
                                    MainActivity.this.mHandler.sendEmptyMessage(101);
                                }
                            }
                        });
                        panelDialog.show();
                    }
                } else if (this.mWebView.canGoBackOrForward(-1)) {
                    this.mWebView.goBackOrForward(-1);
                } else {
                    finishAapplication();
                }
            } catch (Exception e) {
                e.printStackTrace();
                super.onBackPressed();
            }
        } else {
            return;
        }
        return;
    }

    /* access modifiers changed from: private */
    public void handleMessage(Message message) {
        int i = message.what;
        if (i == 100) {
            loadURL(message.obj);
        } else if (i == 101) {
            loadURL(URL_MAIN);
        } else if (i == 999) {
            finishAapplication();
        }
    }

    private void loadURL(final Object obj) {
        if (obj instanceof String) {
            runOnUiThread(new Runnable() {
                public void run() {
                    MainActivity.this.mWebView.loadUrl((String) obj);
                }
            });
        }
    }

    private void finishAapplication() {
        PanelDialog panelDialog = new PanelDialog((Context) this, getString(R.string.app_name), getString(R.string.main_exit_dialog_msg), getString(R.string.common_dialog_cancel), getString(R.string.common_dialog_confirm), (IDialogCallBack) new IDialogCallBack() {
            public void onCallBack(RESULT_CODE result_code) {
                if (RESULT_CODE.RIGHT_CLICK.equals(result_code)) {
                    MainActivity.this.finish();
                    System.exit(0);
                }
            }
        });
        panelDialog.show();
    }

    /* access modifiers changed from: private */
    public void callbackSharePopup(String str) {
        if (!loading) {
            Message obtainMessage = this.mHandler.obtainMessage(100);
            StringBuilder sb = new StringBuilder();
            sb.append("javascript:openPop('");
            sb.append(str);
            sb.append("');");
            obtainMessage.obj = sb.toString();
            this.mHandler.handleMessage(obtainMessage);
        }
    }

    /* access modifiers changed from: private */
    public void callGetLogin() {
        String str;
        try {
            str = LoginVo.getLoginInfo(getBaseContext()).toJson();
        } catch (Exception e) {
            e.printStackTrace();
            str = "";
        }
        Message obtainMessage = this.mHandler.obtainMessage(100);
        StringBuilder sb = new StringBuilder();
        sb.append("javascript:CmmnJs.getLogin('");
        sb.append(str);
        sb.append("');");
        obtainMessage.obj = sb.toString();
        this.mHandler.handleMessage(obtainMessage);
    }

    /* access modifiers changed from: private */
    public void callResetSession() {
        try {
            callResetSession(UserInfoManager.getInstance(getBaseContext()).getUserInfo().userId);
        } catch (Exception unused) {
        }
    }

    private void callResetSession(String str) {
        try {
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty((String) "userId", str);
            Message obtainMessage = this.mHandler.obtainMessage(100);
            StringBuilder sb = new StringBuilder();
            sb.append("javascript:CmmnJs.resetUserSessionFromApp('");
            sb.append(jsonObject.toString());
            sb.append("');");
            obtainMessage.obj = sb.toString();
            this.mHandler.handleMessage(obtainMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private synchronized void callTermBack() {
        if (!loading) {
            Message obtainMessage = this.mHandler.obtainMessage(100);
            obtainMessage.obj = "javascript:CmmnJs.submitToUrl('../agree.do');";
            this.mHandler.handleMessage(obtainMessage);
        }
    }

    /* access modifiers changed from: private */
    public void callSetting() {
        startActivityForResult(new Intent(this, PanelSettingsActivity.class), 999);
    }

    private void reLoad() {
        if (!URL_EXCEPT_RELOAD_INFORM.equals(this.mUrlForReload) && !StringUtils.isEmpty(this.mUrlForReload)) {
            loadURL(this.mUrlForReload);
        }
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int i, int i2, @Nullable Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i == 777) {
            reLoad();
        } else if (i == 999) {
            reLoad();
        }
    }

    private synchronized void toast(int i) {
        toast(getString(i));
    }

    /* access modifiers changed from: private */
    public synchronized void toast(final String str) {
        runOnUiThread(new Runnable() {
            public void run() {
                Toast.makeText(MainActivity.this, str, 0).show();
            }
        });
    }
}