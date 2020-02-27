package com.nuvent.shareat.activity.common;

import android.app.AlertDialog.Builder;
import android.content.ActivityNotFoundException;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.view.View;
import android.webkit.JsResult;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.util.ExternalApp;
import com.nuvent.shareat.util.GAEvent;
import net.xenix.android.widget.HorizontalProgressBar;

public class WebReviewActivity extends BaseActivity {
    private static final String INSTAGRAM_TITLE = "[\uc778\uc2a4\ud0c0\uadf8\ub7a8 : %s] %s - %s";
    /* access modifiers changed from: private */
    public HorizontalProgressBar mProgressBar;
    private WebView mWebView;

    private class WebViewClientClass extends WebViewClient {
        private WebViewClientClass() {
        }

        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            if (!url.contains("intent://instagram")) {
                return false;
            }
            if (WebReviewActivity.this.getPackageManager().getLaunchIntentForPackage(ExternalApp.INSTAGRAM) != null) {
                String instaUrl = url.split("#")[0].replace("intent", "http");
                Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(instaUrl));
                intent.setPackage(ExternalApp.INSTAGRAM);
                try {
                    WebReviewActivity.this.modalActivity(intent);
                } catch (ActivityNotFoundException e) {
                    WebReviewActivity.this.modalActivity(new Intent("android.intent.action.VIEW", Uri.parse(instaUrl)));
                }
            } else {
                Intent intent2 = new Intent("android.intent.action.VIEW");
                intent2.setData(Uri.parse("market://details?id=" + ExternalApp.INSTAGRAM));
                WebReviewActivity.this.startActivity(intent2);
            }
            return true;
        }

        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
            WebReviewActivity.this.mProgressBar.setMax(100);
            WebReviewActivity.this.mProgressBar.setProgress(0);
            WebReviewActivity.this.mProgressBar.setVisibility(0);
        }

        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            WebReviewActivity.this.mProgressBar.setMax(100);
            WebReviewActivity.this.mProgressBar.setProgress(100);
            WebReviewActivity.this.mProgressBar.postDelayed(new Runnable() {
                public void run() {
                    WebReviewActivity.this.mProgressBar.setVisibility(8);
                }
            }, 200);
        }
    }

    public void onBackPressed() {
        finish(R.anim.scale_up, R.anim.modal_exit_animation);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        this.mWebView.loadUrl("about:blank");
        this.mWebView.destroy();
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web_review);
        if (VERSION.SDK_INT >= 19) {
            findViewById(R.id.statusView).getLayoutParams().height = getStatusBarHeight();
        }
        if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_URL)) {
            Bundle bundle = getIntent().getBundleExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER);
            ((TextView) findViewById(R.id.titleLabel)).setText(bundle.getString("title"));
            getIntent().putExtra("url", bundle.getString("link_url"));
        } else if (getIntent().hasExtra("insta")) {
            GAEvent.onGAScreenView(this, R.string.ga_sns_detail_insta);
            ((TextView) findViewById(R.id.titleLabel)).setText(String.format(INSTAGRAM_TITLE, new Object[]{getIntent().getStringExtra("storeName"), getIntent().getStringExtra("userName"), getIntent().getStringExtra("date")}));
        } else {
            GAEvent.onGAScreenView(this, R.string.ga_sns_detail_blog);
            ((TextView) findViewById(R.id.titleLabel)).setText(getIntent().getStringExtra("title"));
        }
        this.mProgressBar = (HorizontalProgressBar) findViewById(R.id.webViewProgress);
        this.mWebView = (WebView) findViewById(R.id.webView);
        this.mWebView.getSettings().setJavaScriptEnabled(true);
        this.mWebView.getSettings().setDomStorageEnabled(true);
        this.mWebView.getSettings().setAppCacheMaxSize(0);
        this.mWebView.getSettings().setAllowFileAccess(false);
        this.mWebView.getSettings().setAppCacheEnabled(false);
        this.mWebView.getSettings().setUserAgentString(this.mWebView.getSettings().getUserAgentString() + getResources().getString(R.string.shareat_user_agent));
        this.mWebView.getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
        this.mWebView.setWebViewClient(new WebViewClientClass());
        this.mWebView.setWebChromeClient(new WebChromeClient() {
            public void onProgressChanged(WebView view, int newProgress) {
                WebReviewActivity.this.mProgressBar.setMax(100);
                WebReviewActivity.this.mProgressBar.setProgress(newProgress);
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
        this.mWebView.loadUrl(getIntent().getStringExtra("url"));
    }
}