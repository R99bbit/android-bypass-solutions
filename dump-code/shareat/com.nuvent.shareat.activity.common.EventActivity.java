package com.nuvent.shareat.activity.common;

import android.app.AlertDialog.Builder;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.view.View;
import android.webkit.ConsoleMessage;
import android.webkit.CookieManager;
import android.webkit.JsResult;
import android.webkit.WebBackForwardList;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.widget.CheckBox;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.event.MainActivityFinishEvent;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.CustomWebViewClient;
import com.nuvent.shareat.manager.CustomWebViewClient.OnPageStatus;
import com.nuvent.shareat.manager.CustomWebViewClient.OnSchemeListener;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.BoardModel;
import de.greenrobot.event.EventBus;
import net.xenix.android.widget.HorizontalProgressBar;

public class EventActivity extends MainActionBarActivity {
    private CustomWebViewClient client = null;
    /* access modifiers changed from: private */
    public HorizontalProgressBar mProgressBar;
    /* access modifiers changed from: private */
    public WebView webView = null;

    public void onBackPressed() {
        WebBackForwardList list = this.webView.copyBackForwardList();
        if (list == null || list.getCurrentIndex() > 0 || this.webView.canGoBack()) {
            this.webView.goBack();
            return;
        }
        finish(R.anim.fade_in_activity, R.anim.fade_out_activity);
        EventBus.getDefault().post(new MainActivityFinishEvent());
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
    }

    public void onClickEventClose(View view) {
        if (((CheckBox) findViewById(R.id.chkbox)).isChecked()) {
            AppSettingManager.getInstance().setEventViewingDate(System.currentTimeMillis() + 86400000);
        }
        finish();
        EventBus.getDefault().post(new MainActivityFinishEvent());
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_event, 2);
        this.mProgressBar = (HorizontalProgressBar) findViewById(R.id.webViewProgress);
        hideActionBar();
        if (VERSION.SDK_INT >= 19) {
            findViewById(R.id.statusView).getLayoutParams().height = getStatusBarHeight();
        }
        this.webView = (WebView) findViewById(R.id.web);
        this.webView.getSettings().setJavaScriptEnabled(true);
        this.webView.getSettings().setDomStorageEnabled(true);
        this.webView.getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
        this.webView.getSettings().setAppCacheMaxSize(0);
        this.webView.getSettings().setAllowFileAccess(false);
        this.webView.getSettings().setAppCacheEnabled(false);
        this.webView.getSettings().setUserAgentString(this.webView.getSettings().getUserAgentString() + getResources().getString(R.string.shareat_user_agent));
        if (VERSION.SDK_INT >= 19) {
            this.webView.getSettings().setCacheMode(1);
        }
        if (VERSION.SDK_INT >= 21) {
            this.webView.getSettings().setMixedContentMode(0);
        }
        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.setAcceptCookie(true);
        if (VERSION.SDK_INT >= 21) {
            cookieManager.setAcceptThirdPartyCookies(this.webView, true);
        }
        this.client = new CustomWebViewClient(this);
        this.webView.setWebViewClient(this.client);
        this.webView.setWebChromeClient(new WebChromeClient() {
            public boolean onConsoleMessage(ConsoleMessage consoleMessage) {
                return super.onConsoleMessage(consoleMessage);
            }

            public void onProgressChanged(WebView view, int newProgress) {
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
        this.client.setOnSchemeListener(new OnSchemeListener() {
            public void onSchemeClick(String url) {
                EventActivity.this.requestScheme(url);
            }
        });
        try {
            if (getIntent().hasExtra("link_url")) {
                findViewById(R.id.chkbox).setVisibility(8);
                this.webView.loadUrl(getIntent().getStringExtra("link_url"));
            } else if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_URL)) {
                this.client.setOnPageStatusListener(new OnPageStatus() {
                    public void onPageLoadStart() {
                        EventActivity.this.mProgressBar.setMax(100);
                        EventActivity.this.mProgressBar.setProgress(0);
                        EventActivity.this.mProgressBar.setVisibility(0);
                    }

                    public void onPageLoadEnd() {
                        EventActivity.this.mProgressBar.setMax(100);
                        EventActivity.this.mProgressBar.setProgress(100);
                        EventActivity.this.mProgressBar.postDelayed(new Runnable() {
                            public void run() {
                                EventActivity.this.mProgressBar.setVisibility(8);
                            }
                        }, 200);
                    }

                    public void onReceivedError(int errorCode) {
                        String errMsg = EventActivity.this.getResources().getString(R.string.COMMON_WEBVIEW_ETC_ERR);
                        if (errorCode == -8) {
                            errMsg = EventActivity.this.getResources().getString(R.string.COMMON_WEBVIEW_TIMEOUT_ERR);
                        }
                        EventActivity.this.webView.post(new Runnable() {
                            String errMsg;

                            public void run() {
                                EventActivity.this.showConfirmDialog(this.errMsg, (Runnable) new Runnable() {
                                    public void run() {
                                        EventActivity.this.webView.reload();
                                    }
                                }, (Runnable) new Runnable() {
                                    public void run() {
                                        EventActivity.this.webView.setEnabled(false);
                                    }
                                });
                            }

                            public Runnable init(String errMsg2) {
                                this.errMsg = errMsg2;
                                return this;
                            }
                        }.init(errMsg));
                    }
                });
                showActionBar();
                showFavoriteButton(false);
                findViewById(R.id.bottomBarLayout).setVisibility(8);
                Bundle bundle = getIntent().getBundleExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER);
                String executeBrowser = bundle.getString("execute", "");
                if (executeBrowser == null || !executeBrowser.equals("out")) {
                    setTitle(bundle.getString("title", ""));
                    this.webView.loadUrl(bundle.getString("link_url").replace("$user_sno", ShareatApp.getInstance().getUserNum()).replace("$auth_token", SessionManager.getInstance().getAuthToken()).replace("$version", ShareatApp.getInstance().getAppVersionName()));
                    return;
                }
                executeExternalBrowser(bundle.getString("link_url", ""));
                finish();
            } else {
                this.webView.loadData(((BoardModel) getIntent().getSerializableExtra("model")).contents, "text/html; charset=UTF-8", null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "URL \ud638\ucd9c \uc624\ub958 \uc785\ub2c8\ub2e4.", 0).show();
            finish();
        }
    }

    /* access modifiers changed from: private */
    public void requestScheme(String url) {
        new CustomSchemeManager();
        CustomSchemeManager.postSchemeAction(this, url);
    }

    private void executeExternalBrowser(String linkUrl) {
        if (linkUrl != null && true != linkUrl.isEmpty()) {
            startActivity(new Intent("android.intent.action.VIEW", Uri.parse(linkUrl.replace("$user_sno", ShareatApp.getInstance().getUserNum()).replace("$auth_token", SessionManager.getInstance().getAuthToken()).replace("$version", ShareatApp.getInstance().getAppVersionName()))));
        }
    }
}