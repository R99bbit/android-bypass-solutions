package com.embrain.panelpower.hybrid;

import android.webkit.JavascriptInterface;

public abstract class AgreeWebViewJavascript {
    public static String getName() {
        return "hybridInterface";
    }

    public abstract void onLocationAgree(boolean z);

    public abstract void onPayAgree(boolean z);

    public abstract void onPushAgree(boolean z);

    public abstract String onRequestDeviceInfo();

    public abstract void onUsageAgree(boolean z);

    public abstract void showDetail(String str);

    @JavascriptInterface
    public void payAgree(boolean z) {
        onPayAgree(z);
    }

    @JavascriptInterface
    public void usageAgree(boolean z) {
        onUsageAgree(z);
    }

    @JavascriptInterface
    public void locationAgree(boolean z) {
        onLocationAgree(z);
    }

    @JavascriptInterface
    public void pushAgree(boolean z) {
        onPushAgree(z);
    }

    @JavascriptInterface
    public void goDetail(String str) {
        showDetail(str);
    }

    @JavascriptInterface
    public String requestDeviceInfo() {
        return onRequestDeviceInfo();
    }
}