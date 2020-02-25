package com.embrain.panelpower.hybrid;

import android.webkit.JavascriptInterface;

public abstract class SurveyWebViewJavaScript {
    public abstract void finishSurvey();

    public String getName() {
        return "hybridInterface";
    }

    public abstract void onPageLoadComplete();

    @JavascriptInterface
    public void pageLoadComplete() {
        onPageLoadComplete();
    }

    @JavascriptInterface
    public void surveyFinish() {
        finishSurvey();
    }
}