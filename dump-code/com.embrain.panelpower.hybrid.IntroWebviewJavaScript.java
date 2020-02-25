package com.embrain.panelpower.hybrid;

import android.webkit.JavascriptInterface;

public abstract class IntroWebviewJavaScript {
    public static String getName() {
        return "hybridInterface";
    }

    public abstract void onConfirmAccess();

    public abstract void onIntroFinish();

    public abstract void onPageLoadComplete();

    @JavascriptInterface
    public void pageLoadComplete() {
        onPageLoadComplete();
    }

    @JavascriptInterface
    public void confirmAccess() {
        onConfirmAccess();
    }

    @JavascriptInterface
    public void introFinish() {
        onIntroFinish();
    }
}