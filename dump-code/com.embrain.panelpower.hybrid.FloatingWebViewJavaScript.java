package com.embrain.panelpower.hybrid;

import android.webkit.JavascriptInterface;

public abstract class FloatingWebViewJavaScript {
    public String getName() {
        return "hybridInterface";
    }

    public abstract void onClickBody(int i);

    public abstract void onClickCancel(int i);

    public abstract void onPageLoadComplete();

    public abstract int requestAgreeType();

    @JavascriptInterface
    public void pageLoadComplete() {
        onPageLoadComplete();
    }

    @JavascriptInterface
    public int getAgreeType() {
        return requestAgreeType();
    }

    @JavascriptInterface
    public void clickBody(int i) {
        onClickBody(i);
    }

    @JavascriptInterface
    public void clickCancel(int i) {
        onClickCancel(i);
    }
}