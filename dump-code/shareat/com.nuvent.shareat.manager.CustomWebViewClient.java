package com.nuvent.shareat.manager;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.activity.main.StoreDetailActivity;
import com.nuvent.shareat.model.store.StoreModel;
import java.net.URISyntaxException;

public class CustomWebViewClient extends WebViewClient {
    private Context context;
    private OnPageStatus mListener;
    private OnSchemeListener mSchemeListener;

    public interface OnPageStatus {
        void onPageLoadEnd();

        void onPageLoadStart();

        void onReceivedError(int i);
    }

    public interface OnSchemeListener {
        void onSchemeClick(String str);
    }

    public CustomWebViewClient(Context context2) {
        this.context = context2;
    }

    @TargetApi(23)
    public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
        super.onReceivedError(view, request, error);
        if (this.mListener != null) {
            this.mListener.onReceivedError(error.getErrorCode());
        }
    }

    public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
        super.onReceivedError(view, errorCode, description, failingUrl);
        if (this.mListener != null) {
            this.mListener.onReceivedError(errorCode);
        }
    }

    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        boolean bSuccess = true;
        if (url.startsWith("shareat://psno=")) {
            if (url.contains("psno=")) {
                String psno = url.substring(url.indexOf("psno=") + "psno=".length(), url.length());
                Intent intent = new Intent(this.context, StoreDetailActivity.class);
                StoreModel storeModel = new StoreModel();
                storeModel.setPartnerName1("");
                storeModel.setPartnerSno(psno);
                intent.putExtra("model", storeModel);
                ((BaseActivity) this.context).animActivity(intent, R.anim.fade_in_activity, R.anim.fade_out_activity);
                ((BaseActivity) this.context).finish();
            }
            return true;
        } else if (!url.startsWith("shareat://shareat.me/")) {
            if (url != null && url.startsWith("intent:")) {
                try {
                    Intent intent2 = Intent.parseUri(url, 1);
                    if (this.context.getPackageManager().getLaunchIntentForPackage(intent2.getPackage()) != null) {
                        this.context.startActivity(intent2);
                    } else {
                        Intent marketIntent = new Intent("android.intent.action.VIEW");
                        marketIntent.setData(Uri.parse("market://details?id=" + intent2.getPackage()));
                        this.context.startActivity(marketIntent);
                    }
                    return true;
                } catch (Exception e) {
                    e.printStackTrace();
                    bSuccess = false;
                    Toast.makeText(this.context, "\uc798\ubabb\ub41c URL \uc785\ub2c8\ub2e4.", 0).show();
                }
            } else if (url != null && url.startsWith("market://")) {
                try {
                    Intent intent3 = Intent.parseUri(url, 1);
                    if (intent3 != null) {
                        this.context.startActivity(intent3);
                    }
                    return true;
                } catch (URISyntaxException e2) {
                    e2.printStackTrace();
                    bSuccess = false;
                    Toast.makeText(this.context, "\uc798\ubabb\ub41c URL \uc785\ub2c8\ub2e4.", 0).show();
                }
            }
            if (true != bSuccess) {
                return true;
            }
            view.loadUrl(url);
            return false;
        } else if (!url.equals("shareat://shareat.me/mainlist")) {
            if (this.mSchemeListener != null) {
                this.mSchemeListener.onSchemeClick(url);
            }
            return true;
        } else {
            Intent intent4 = new Intent(this.context, MainActivity.class);
            intent4.setFlags(603979776);
            this.context.startActivity(intent4);
            return true;
        }
    }

    public void onPageStarted(WebView view, String url, Bitmap favicon) {
        super.onPageStarted(view, url, favicon);
        if (this.mListener != null) {
            this.mListener.onPageLoadStart();
        }
    }

    @JavascriptInterface
    public void onPageFinished(WebView view, String url) {
        super.onPageFinished(view, url);
        String userNum = ShareatApp.getInstance().getUserNum();
        if (userNum != null && !userNum.isEmpty()) {
            view.loadUrl("javascript:pop_up('" + userNum + "', '" + ShareatApp.getInstance().getAppVersionName() + "')");
        }
        if (this.mListener != null) {
            this.mListener.onPageLoadEnd();
        }
    }

    public void setOnPageStatusListener(OnPageStatus listener) {
        this.mListener = listener;
    }

    public void setOnSchemeListener(OnSchemeListener listener) {
        this.mSchemeListener = listener;
    }
}