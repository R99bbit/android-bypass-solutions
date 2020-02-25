package com.embrain.panelpower.hybrid;

import android.webkit.JavascriptInterface;
import com.embrain.panelpower.vo.ShareInfo;

public abstract class PopupBrowserWebViewJavaScript {
    public String getName() {
        return "hybridInterface";
    }

    public abstract void goMap(String str);

    public abstract void onPageFinish();

    public abstract void onPageLoadComplete();

    public abstract void showSharePopup(ShareInfo shareInfo);

    @JavascriptInterface
    public void pageLoadComplete() {
        onPageLoadComplete();
    }

    @JavascriptInterface
    public void callSharePopup(String str, String str2, String str3, String str4, String str5) {
        ShareInfo shareInfo = new ShareInfo(str5, str2, str4, str3, str);
        showSharePopup(shareInfo);
    }

    @JavascriptInterface
    public void openMap(String str) {
        goMap(str);
    }

    @JavascriptInterface
    public void pageFinish() {
        onPageFinish();
    }
}