package com.embrain.panelpower.hybrid;

import android.content.Context;
import android.webkit.JsResult;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import com.embrain.panelpower.R;
import com.embrain.panelpower.views.PanelDialog;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack.RESULT_CODE;

public class PanelWebChromeClient extends WebChromeClient {
    private Context mContext;

    /* renamed from: com.embrain.panelpower.hybrid.PanelWebChromeClient$3 reason: invalid class name */
    static /* synthetic */ class AnonymousClass3 {
        static final /* synthetic */ int[] $SwitchMap$com$embrain$panelpower$views$PanelDialog$IDialogCallBack$RESULT_CODE = new int[RESULT_CODE.values().length];

        /* JADX WARNING: Can't wrap try/catch for region: R(8:0|1|2|3|4|5|6|8) */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:3:0x0014 */
        /* JADX WARNING: Missing exception handler attribute for start block: B:5:0x001f */
        static {
            $SwitchMap$com$embrain$panelpower$views$PanelDialog$IDialogCallBack$RESULT_CODE[RESULT_CODE.LEFT_CLICK.ordinal()] = 1;
            $SwitchMap$com$embrain$panelpower$views$PanelDialog$IDialogCallBack$RESULT_CODE[RESULT_CODE.RIGHT_CLICK.ordinal()] = 2;
            try {
                $SwitchMap$com$embrain$panelpower$views$PanelDialog$IDialogCallBack$RESULT_CODE[RESULT_CODE.CANCEL.ordinal()] = 3;
            } catch (NoSuchFieldError unused) {
            }
        }
    }

    public PanelWebChromeClient(Context context) {
        this.mContext = context;
    }

    public boolean onJsAlert(WebView webView, String str, String str2, final JsResult jsResult) {
        Context context = this.mContext;
        PanelDialog panelDialog = new PanelDialog(context, context.getString(R.string.app_name), str2, (String) null, (String) "\ud655\uc778", (IDialogCallBack) new IDialogCallBack() {
            public void onCallBack(RESULT_CODE result_code) {
                jsResult.confirm();
            }
        });
        panelDialog.show();
        return true;
    }

    public boolean onJsConfirm(WebView webView, String str, String str2, final JsResult jsResult) {
        Context context = this.mContext;
        PanelDialog panelDialog = new PanelDialog(context, context.getString(R.string.app_name), str2, (String) "\ucde8\uc18c", (String) "\ud655\uc778", (IDialogCallBack) new IDialogCallBack() {
            public void onCallBack(RESULT_CODE result_code) {
                int i = AnonymousClass3.$SwitchMap$com$embrain$panelpower$views$PanelDialog$IDialogCallBack$RESULT_CODE[result_code.ordinal()];
                if (i == 1) {
                    jsResult.cancel();
                } else if (i == 2) {
                    jsResult.confirm();
                } else if (i == 3) {
                    jsResult.cancel();
                }
            }
        });
        panelDialog.show();
        return true;
    }
}