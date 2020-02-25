package com.embrain.panelpower;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningTaskInfo;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnKeyListener;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings.LayoutAlgorithm;
import android.webkit.WebSettings.TextSize;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.UserInfoManager.UserInfo;
import com.embrain.panelpower.hybrid.PanelWebChromeClient;
import com.embrain.panelpower.hybrid.SurveyWebViewJavaScript;
import com.embrain.panelpower.utils.LogUtil;
import com.embrain.panelpower.views.PanelDialog;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack.RESULT_CODE;
import com.kakao.util.helper.FileUtils;

public class SurveyActivity extends AppCompatActivity {
    private static final String DEFAULT_SURVEY_URL = "https://s.panel.co.kr/?a=";
    public static final String EXTRA_SURVEY_ID = "survey_id";
    public static final String EXTRA_SURVEY_URL = "survey_url";
    public static final String URL_FINISH = "file:///android_asset/html/intro/research_end.html";
    private SurveyWebViewJavaScript mInterface = new SurveyWebViewJavaScript() {
        public void onPageLoadComplete() {
        }

        public void finishSurvey() {
            SurveyActivity.this.finish();
        }
    };
    /* access modifiers changed from: private */
    public WebView mWebView;

    private class SurveyWebViewClient extends WebViewClient {
        private SurveyWebViewClient() {
        }

        public void onPageStarted(WebView webView, String str, Bitmap bitmap) {
            super.onPageStarted(webView, str, bitmap);
            StringBuilder sb = new StringBuilder();
            sb.append("onPageStarted url = ");
            sb.append(str);
            LogUtil.write(sb.toString());
            if (str.endsWith("/reserves_end.asp") || str.endsWith("/Complete_m.asp") || str.endsWith("/reserves_end_2018.asp") || str.endsWith("/Reserves_End") || str.endsWith("/Reserves_end") || str.endsWith("/reserves_end_m.asp") || str.endsWith("/Complete.asp") || str.endsWith("/Error.asp") || str.endsWith("/Error") || str.endsWith("/error.asp") || str.endsWith("/error")) {
                SurveyActivity.this.mWebView.loadUrl(SurveyActivity.URL_FINISH);
            }
        }

        public void onPageFinished(WebView webView, String str) {
            super.onPageFinished(webView, str);
        }

        public boolean shouldOverrideUrlLoading(WebView webView, String str) {
            StringBuilder sb = new StringBuilder();
            sb.append("shouldOverrideUrlLoading url = ");
            sb.append(str);
            LogUtil.write(sb.toString());
            if (str.endsWith("/reserves_end.asp") || str.endsWith("/Complete_m.asp") || str.endsWith("/reserves_end_2018.asp") || str.contains("/Reserves_End") || str.contains("/Reserves_end") || str.endsWith("/reserves_end_m.asp") || str.endsWith("/Complete.asp") || str.endsWith("/Error.asp") || str.contains("/Error") || str.endsWith("/error.asp") || str.endsWith("/error")) {
                SurveyActivity.this.mWebView.loadUrl(SurveyActivity.URL_FINISH);
            } else if ("about:blank".equals(str)) {
                SurveyActivity.this.finishSurvey(true);
            } else {
                webView.loadUrl(str);
            }
            return true;
        }

        public void onLoadResource(WebView webView, String str) {
            if (str.endsWith("/reserves_end.asp") || str.endsWith("/Complete_m.asp") || str.endsWith("/reserves_end_2018.asp") || str.contains("/Reserves_End") || str.contains("/Reserves_end") || str.endsWith("/reserves_end_m.asp") || str.endsWith("/Complete.asp") || str.endsWith("/Error.asp") || str.contains("/Error") || str.endsWith("/error.asp") || str.endsWith("/error")) {
                SurveyActivity.this.mWebView.loadUrl(SurveyActivity.URL_FINISH);
            } else if ("about:blank".equals(str)) {
                SurveyActivity.this.finishSurvey(true);
            } else {
                super.onLoadResource(webView, str);
            }
        }

        @Nullable
        public WebResourceResponse shouldInterceptRequest(WebView webView, WebResourceRequest webResourceRequest) {
            return super.shouldInterceptRequest(webView, webResourceRequest);
        }
    }

    private void hideHeader() {
    }

    /* access modifiers changed from: protected */
    public void onCreate(@Nullable Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) R.layout.activity_agree);
        initView();
        initData();
    }

    private void initView() {
        hideHeader();
        this.mWebView = (WebView) findViewById(R.id.webview_agree);
        initWebView();
    }

    private void initWebView() {
        this.mWebView.setHorizontalScrollBarEnabled(false);
        this.mWebView.setVerticalScrollBarEnabled(false);
        this.mWebView.getSettings().setJavaScriptEnabled(true);
        this.mWebView.getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
        this.mWebView.getSettings().setUseWideViewPort(true);
        this.mWebView.getSettings().setLoadWithOverviewMode(true);
        this.mWebView.getSettings().setLayoutAlgorithm(LayoutAlgorithm.NORMAL);
        this.mWebView.getSettings().setTextSize(TextSize.NORMAL);
        WebView webView = this.mWebView;
        SurveyWebViewJavaScript surveyWebViewJavaScript = this.mInterface;
        webView.addJavascriptInterface(surveyWebViewJavaScript, surveyWebViewJavaScript.getName());
        this.mWebView.setWebViewClient(new SurveyWebViewClient());
        this.mWebView.setWebChromeClient(new PanelWebChromeClient(this));
        this.mWebView.setOnKeyListener(new OnKeyListener() {
            public boolean onKey(View view, int i, KeyEvent keyEvent) {
                if (keyEvent.getAction() != 0) {
                    return true;
                }
                if (i != 4) {
                    return false;
                }
                if (SurveyActivity.URL_FINISH.equals(SurveyActivity.this.mWebView.getUrl())) {
                    SurveyActivity.this.finish();
                } else {
                    SurveyActivity.this.finishSurvey(false);
                }
                return true;
            }
        });
    }

    private void initData() {
        Intent intent = getIntent();
        String stringExtra = intent.getStringExtra(EXTRA_SURVEY_ID);
        String stringExtra2 = intent.getStringExtra(EXTRA_SURVEY_URL);
        UserInfo userInfo = UserInfoManager.getInstance(getBaseContext()).getUserInfo();
        if (userInfo == null) {
            showErrorPopup("\ub85c\uadf8\uc778 \ub418\uc9c0 \uc54a\uc740 \uc0ac\uc6a9\uc790\uc785\ub2c8\ub2e4.");
            return;
        }
        if (!StringUtils.isEmpty(stringExtra)) {
            String panelId = userInfo.getPanelId();
            StringBuilder sb = new StringBuilder();
            sb.append("https://s.panel.co.kr/?a=");
            sb.append(stringExtra);
            sb.append(FileUtils.FILE_NAME_AVAIL_CHARACTER);
            sb.append(panelId);
            stringExtra2 = sb.toString();
        } else if (StringUtils.isEmpty(stringExtra2)) {
            showErrorPopup("\uc870\uc0ac \ucc38\uc5ec\ub97c \uc704\ud55c \ud544\uc218 \uc815\ubcf4\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.");
            return;
        }
        this.mWebView.loadUrl(stringExtra2);
    }

    private void showErrorPopup(String str) {
        PanelDialog panelDialog = new PanelDialog((Context) this, (String) "[\uc54c\ub9bc]", str, (String) null, (String) "\ud655\uc778", (IDialogCallBack) new IDialogCallBack() {
            public void onCallBack(RESULT_CODE result_code) {
                SurveyActivity.this.finish();
            }
        });
        panelDialog.show();
    }

    /* access modifiers changed from: private */
    public void finishSurvey(boolean z) {
        if (z) {
            PanelDialog panelDialog = new PanelDialog((Context) this, (String) "[\uc54c\ub9bc]", (String) "\uc870\uc0ac\uac00 \uc885\ub8cc\ub418\uc5c8\uc2b5\ub2c8\ub2e4.\n \uc774\uc804 \ud398\uc774\uc9c0\ub85c \uc774\ub3d9\ud569\ub2c8\ub2e4.", (String) null, (String) "\ud655\uc778", (IDialogCallBack) new IDialogCallBack() {
                public void onCallBack(RESULT_CODE result_code) {
                    SurveyActivity.this.finish();
                }
            });
            panelDialog.show();
            return;
        }
        PanelDialog panelDialog2 = new PanelDialog((Context) this, (String) "[\uc54c\ub9bc]", (String) "\uc870\uc0ac\uac00 \uc9c4\ud589 \uc911\uc785\ub2c8\ub2e4.\n \uc870\uc0ac\ub97c \uc885\ub8cc\ud560\uae4c\uc694?", (String) "\ucde8\uc18c", (String) "\ud655\uc778", (IDialogCallBack) new IDialogCallBack() {
            public void onCallBack(RESULT_CODE result_code) {
                if (RESULT_CODE.RIGHT_CLICK.equals(result_code)) {
                    SurveyActivity.this.finish();
                }
            }
        });
        panelDialog2.show();
    }

    public void finish() {
        if (applicationIsRunning()) {
            setResult(-1);
        } else {
            startActivity(new Intent(getBaseContext(), SplashActivity.class));
        }
        super.finish();
    }

    private boolean applicationIsRunning() {
        try {
            for (RunningTaskInfo runningTaskInfo : ((ActivityManager) getSystemService("activity")).getRunningTasks(10)) {
                if (MainActivity.class.getName().equals(runningTaskInfo.baseActivity.getClassName())) {
                    return true;
                }
            }
        } catch (Exception unused) {
        }
        return false;
    }
}