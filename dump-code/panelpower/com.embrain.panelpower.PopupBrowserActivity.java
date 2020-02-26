package com.embrain.panelpower;

import android.content.Context;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebSettings.LayoutAlgorithm;
import android.webkit.WebView;
import android.widget.Toast;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.hybrid.PanelWebChromeClient;
import com.embrain.panelpower.hybrid.PopupBrowserWebViewJavaScript;
import com.embrain.panelpower.utils.OtherPackageUtils;
import com.embrain.panelpower.utils.ShareUtils;
import com.embrain.panelpower.views.SharePopup;
import com.embrain.panelpower.views.SharePopup.OnShareClickListener;
import com.embrain.panelpower.vo.ShareInfo;

public class PopupBrowserActivity extends AppCompatActivity {
    public static final String EXTRA_URL = "popup_url";
    private PopupBrowserWebViewJavaScript mInterface = new PopupBrowserWebViewJavaScript() {
        private static final String MAP_TYPE_DAUM = "daum";
        private static final String MAP_TYPE_GOOGLE = "google";
        private static final String MAP_TYPE_NAVER = "naver";

        public void onPageLoadComplete() {
        }

        public void showSharePopup(final ShareInfo shareInfo) {
            try {
                if ("location".equals(shareInfo.type)) {
                    new SharePopup(PopupBrowserActivity.this, shareInfo, new OnShareClickListener() {
                        public void onClickBtn(String str) {
                            ShareUtils.shareSNS(PopupBrowserActivity.this.getBaseContext(), str, shareInfo);
                        }
                    }).show();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void goMap(String str) {
            if (MAP_TYPE_NAVER.equals(str)) {
                OtherPackageUtils.goBrowser(PopupBrowserActivity.this.getBaseContext(), PanelApplication.URL_MAP_NAVER_HOME);
            } else if (MAP_TYPE_DAUM.equals(str)) {
                OtherPackageUtils.goBrowser(PopupBrowserActivity.this.getBaseContext(), PanelApplication.URL_MAP_DAUM_HOME);
            } else if (MAP_TYPE_GOOGLE.equals(str)) {
                OtherPackageUtils.goBrowser(PopupBrowserActivity.this.getBaseContext(), PanelApplication.URL_MAP_GOOGLE_HOME);
            }
        }

        public void onPageFinish() {
            PopupBrowserActivity.this.finish();
        }
    };
    private WebView mWebView;

    /* access modifiers changed from: protected */
    public void onCreate(@Nullable Bundle bundle) {
        super.onCreate(bundle);
        String stringExtra = getIntent().getStringExtra(EXTRA_URL);
        if (StringUtils.isEmpty(stringExtra)) {
            Context baseContext = getBaseContext();
            StringBuilder sb = new StringBuilder();
            sb.append("\uc798\ubabb\ub41c \ud398\uc774\uc9c0 \ud638\ucd9c\uc785\ub2c8\ub2e4. url : ");
            sb.append(stringExtra);
            Toast.makeText(baseContext, sb.toString(), 0).show();
            finish();
            return;
        }
        setContentView((int) R.layout.activity_main);
        this.mWebView = (WebView) findViewById(R.id.webview_main);
        initWebView();
        this.mWebView.loadUrl(stringExtra);
    }

    private void initWebView() {
        WebSettings settings = this.mWebView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setLayoutAlgorithm(LayoutAlgorithm.SINGLE_COLUMN);
        settings.setCacheMode(2);
        settings.setDomStorageEnabled(true);
        settings.setLoadsImagesAutomatically(true);
        settings.setSupportMultipleWindows(true);
        settings.setJavaScriptCanOpenWindowsAutomatically(true);
        this.mWebView.setWebChromeClient(new PanelWebChromeClient(this));
        WebView webView = this.mWebView;
        PopupBrowserWebViewJavaScript popupBrowserWebViewJavaScript = this.mInterface;
        webView.addJavascriptInterface(popupBrowserWebViewJavaScript, popupBrowserWebViewJavaScript.getName());
    }

    private void showToast(final String str) {
        runOnUiThread(new Runnable() {
            public void run() {
                Context baseContext = PopupBrowserActivity.this.getBaseContext();
                StringBuilder sb = new StringBuilder();
                sb.append(str);
                sb.append("");
                Toast.makeText(baseContext, sb.toString(), 0).show();
            }
        });
    }
}