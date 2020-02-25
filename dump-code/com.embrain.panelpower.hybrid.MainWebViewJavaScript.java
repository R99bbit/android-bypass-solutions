package com.embrain.panelpower.hybrid;

import android.webkit.JavascriptInterface;
import com.embrain.panelpower.vo.ShareInfo;

public abstract class MainWebViewJavaScript {
    public abstract int clickShareBtn();

    public abstract void finishApp();

    public abstract void firebaseLogEvent(String str);

    public String getName() {
        return "hybridInterface";
    }

    public abstract void onCallOtherBrowser(String str);

    public abstract void onCallOtherPage(String str);

    public abstract void onCallSettings();

    public abstract void onCallSurvey(String str, String str2);

    public abstract void onCallSurveyWithUrl(String str);

    public abstract void onChangePassword(String str);

    public abstract boolean onLogin(String str);

    public abstract void onLogout();

    public abstract void onPageLoadComplete();

    public abstract String onRequestDeviceInfo();

    public abstract String onRequestLoginInfo();

    public abstract void onToast(String str);

    public abstract void showSharePopup(ShareInfo shareInfo);

    @JavascriptInterface
    public void pageLoadComplete() {
        onPageLoadComplete();
    }

    @JavascriptInterface
    public void callAppFinish() {
        finishApp();
    }

    @JavascriptInterface
    public void callPageSettings() {
        onCallSettings();
    }

    @JavascriptInterface
    public void callOtherPage(String str) {
        onCallOtherPage(str);
    }

    @JavascriptInterface
    public void callOtherBrowser(String str) {
        onCallOtherBrowser(str);
    }

    @JavascriptInterface
    public void callPageSurvey(String str, String str2) {
        onCallSurvey(str, str2);
    }

    @JavascriptInterface
    public void callPageSurveyWithUrl(String str) {
        onCallSurveyWithUrl(str);
    }

    @JavascriptInterface
    public boolean login(String str) {
        return onLogin(str);
    }

    @JavascriptInterface
    public void changePassword(String str) {
        onChangePassword(str);
    }

    @JavascriptInterface
    public void logout() {
        onLogout();
    }

    @JavascriptInterface
    public String requestLoginInfo() {
        return onRequestLoginInfo();
    }

    @JavascriptInterface
    public String requestDeviceInfo() {
        return onRequestDeviceInfo();
    }

    @JavascriptInterface
    public void callSharePopup(String str, String str2, String str3, String str4, String str5) {
        ShareInfo shareInfo = new ShareInfo(str5, str2, str4, str3, str);
        showSharePopup(shareInfo);
    }

    @JavascriptInterface
    public void firebaseLog(String str) {
        firebaseLogEvent(str);
    }

    @JavascriptInterface
    public int onClickShare() {
        return clickShareBtn();
    }

    @JavascriptInterface
    public void callToast(String str) {
        onToast(str);
    }
}