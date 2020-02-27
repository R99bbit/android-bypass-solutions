package com.nuvent.shareat.fragment;

import android.app.AlertDialog.Builder;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.JsResult;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.StoreDetailActivity;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.CustomWebViewClient;
import com.nuvent.shareat.manager.CustomWebViewClient.OnPageStatus;
import com.nuvent.shareat.manager.CustomWebViewClient.OnSchemeListener;
import com.nuvent.shareat.model.store.StoreModel;
import net.xenix.android.widget.HorizontalProgressBar;

public class WebViewFragment extends Fragment {
    /* access modifiers changed from: private */
    public HorizontalProgressBar mProgressBar;
    private String mUrl;
    /* access modifiers changed from: private */
    public WebView mWebView;

    private class WebViewClientClass extends WebViewClient {
        private WebViewClientClass() {
        }

        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            if (!url.startsWith("shareat://psno=")) {
                return false;
            }
            if (url.contains("psno=")) {
                String psno = url.substring(url.indexOf("psno=") + "psno=".length(), url.length());
                Intent intent = new Intent(WebViewFragment.this.getActivity(), StoreDetailActivity.class);
                StoreModel storeModel = new StoreModel();
                storeModel.setPartnerName1("");
                storeModel.setPartnerSno(psno);
                intent.putExtra("model", storeModel);
                ((BaseActivity) WebViewFragment.this.getActivity()).animActivity(intent, R.anim.fade_in_activity, R.anim.fade_out_activity);
            }
            return true;
        }

        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
            WebViewFragment.this.mProgressBar.setMax(100);
            WebViewFragment.this.mProgressBar.setProgress(0);
            WebViewFragment.this.mProgressBar.setVisibility(0);
        }

        @JavascriptInterface
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            String userNum = ShareatApp.getInstance().getUserNum();
            if (userNum != null && !userNum.isEmpty()) {
                view.loadUrl("javascript:pop_up('" + userNum + "', '" + ShareatApp.getInstance().getAppVersionName() + "')");
            }
            WebViewFragment.this.mProgressBar.setMax(100);
            WebViewFragment.this.mProgressBar.setProgress(100);
            WebViewFragment.this.mProgressBar.postDelayed(new Runnable() {
                public void run() {
                    WebViewFragment.this.mProgressBar.setVisibility(8);
                }
            }, 200);
        }
    }

    public void setUrl(String url) {
        this.mUrl = url;
    }

    public void refresh() {
        this.mWebView.reload();
    }

    public void loadWebView() {
        this.mWebView.loadUrl(this.mUrl);
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_webview, null);
        this.mProgressBar = (HorizontalProgressBar) view.findViewById(R.id.webViewProgress);
        this.mWebView = (WebView) view.findViewById(R.id.webView);
        this.mWebView.getSettings().setJavaScriptEnabled(true);
        this.mWebView.getSettings().setDomStorageEnabled(true);
        this.mWebView.getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
        this.mWebView.getSettings().setAppCacheMaxSize(0);
        this.mWebView.getSettings().setAllowFileAccess(false);
        this.mWebView.getSettings().setAppCacheEnabled(false);
        this.mWebView.getSettings().setUserAgentString(this.mWebView.getSettings().getUserAgentString() + getResources().getString(R.string.shareat_user_agent));
        if (VERSION.SDK_INT >= 21) {
            this.mWebView.getSettings().setMixedContentMode(0);
        }
        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.setAcceptCookie(true);
        if (VERSION.SDK_INT >= 21) {
            cookieManager.setAcceptThirdPartyCookies(this.mWebView, true);
        }
        CustomWebViewClient client = new CustomWebViewClient(getActivity());
        client.setOnSchemeListener(new OnSchemeListener() {
            public void onSchemeClick(String url) {
                WebViewFragment.this.requestScheme(url);
            }
        });
        client.setOnPageStatusListener(new OnPageStatus() {
            public void onPageLoadStart() {
                WebViewFragment.this.mProgressBar.setMax(100);
                WebViewFragment.this.mProgressBar.setProgress(0);
                WebViewFragment.this.mProgressBar.setVisibility(0);
            }

            public void onPageLoadEnd() {
                WebViewFragment.this.mProgressBar.setMax(100);
                WebViewFragment.this.mProgressBar.setProgress(100);
                WebViewFragment.this.mProgressBar.postDelayed(new Runnable() {
                    public void run() {
                        WebViewFragment.this.mProgressBar.setVisibility(8);
                    }
                }, 200);
            }

            public void onReceivedError(int errorCode) {
                if (WebViewFragment.this.getActivity() != null) {
                    String errMsg = WebViewFragment.this.getResources().getString(R.string.COMMON_WEBVIEW_ETC_ERR);
                    if (errorCode == -8) {
                        errMsg = WebViewFragment.this.getResources().getString(R.string.COMMON_WEBVIEW_TIMEOUT_ERR);
                    }
                    ((BaseActivity) WebViewFragment.this.getActivity()).showConfirmDialog(errMsg, new Runnable() {
                        public void run() {
                            WebViewFragment.this.mWebView.reload();
                        }
                    });
                }
            }
        });
        this.mWebView.setWebViewClient(client);
        this.mWebView.setWebChromeClient(new WebChromeClient() {
            public void onProgressChanged(WebView view, int newProgress) {
                WebViewFragment.this.mProgressBar.setMax(100);
                WebViewFragment.this.mProgressBar.setProgress(newProgress);
            }

            public void onCloseWindow(WebView window) {
                super.onCloseWindow(window);
                window.clearCache(true);
            }

            public boolean onJsAlert(WebView view, String url, String message, final JsResult result) {
                new Builder(view.getContext()).setMessage(message).setPositiveButton(17039370, new OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        result.confirm();
                    }
                }).setCancelable(true).create().show();
                return true;
            }

            public boolean onJsConfirm(WebView view, String url, String message, final JsResult result) {
                new Builder(view.getContext()).setMessage(message).setPositiveButton(17039370, new OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        result.confirm();
                    }
                }).setNegativeButton(17039360, new OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        result.cancel();
                    }
                }).create().show();
                return true;
            }
        });
        this.mWebView.loadUrl(this.mUrl);
        return view;
    }

    /* access modifiers changed from: private */
    public void requestScheme(String url) {
        new CustomSchemeManager();
        CustomSchemeManager.postSchemeAction(getActivity(), url);
    }
}