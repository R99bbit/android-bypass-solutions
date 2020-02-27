package com.nuvent.shareat.dialog;

import android.content.Context;
import android.os.Handler;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import com.nuvent.shareat.R;

public class ZipCodeDialog extends BaseDialog {
    /* access modifiers changed from: private */
    public callback mListener;
    private WebView webview;

    private class AndroidBridge {
        private AndroidBridge() {
        }

        @JavascriptInterface
        public void setAddress(final String arg1, final String arg2, final String arg3) {
            new Handler().post(new Runnable() {
                public void run() {
                    if (ZipCodeDialog.this.mListener != null) {
                        ZipCodeDialog.this.mListener.callback(arg1, arg2, arg3);
                    }
                    ZipCodeDialog.this.dismiss();
                }
            });
        }
    }

    public interface callback {
        void callback(String str, String str2, String str3);
    }

    public ZipCodeDialog(Context context) {
        super(context);
        init();
    }

    private void init() {
        View view = View.inflate(getContext(), R.layout.activity_zipcode_webview, null);
        setContentView(view);
        this.webview = (WebView) view.findViewById(R.id.web_view);
        this.webview.getSettings().setJavaScriptEnabled(true);
        this.webview.getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
        this.webview.getSettings().setAppCacheMaxSize(0);
        this.webview.getSettings().setAllowFileAccess(false);
        this.webview.getSettings().setAppCacheEnabled(false);
        this.webview.addJavascriptInterface(new AndroidBridge(), "webView");
        this.webview.setWebChromeClient(new WebChromeClient());
        this.webview.loadUrl("http://shareat.me/zipcode.html");
    }

    public void setCallback(callback listener) {
        this.mListener = listener;
    }
}