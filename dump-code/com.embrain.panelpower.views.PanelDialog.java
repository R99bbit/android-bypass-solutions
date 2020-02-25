package com.embrain.panelpower.views;

import android.app.AlertDialog;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.R;

public class PanelDialog extends AlertDialog {
    private String btnLeftText;
    private String btnRightText;
    /* access modifiers changed from: private */
    public IDialogCallBack callback;
    private boolean mCancelable;
    private String message;
    private String title;

    public interface IDialogCallBack {

        public enum RESULT_CODE {
            LEFT_CLICK,
            RIGHT_CLICK,
            CANCEL
        }

        void onCallBack(RESULT_CODE result_code);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.dialog_panel);
        initViews();
        setCancelable(this.mCancelable);
    }

    public PanelDialog(Context context, String str, String str2, String str3, String str4, IDialogCallBack iDialogCallBack) {
        this(context, str, str2, str3, str4, iDialogCallBack, true);
    }

    public PanelDialog(Context context, String str, String str2, String str3, String str4, IDialogCallBack iDialogCallBack, boolean z) {
        this(context, str2, str3, str4, iDialogCallBack, z);
        this.title = str;
    }

    public PanelDialog(Context context, String str, String str2, String str3, IDialogCallBack iDialogCallBack, boolean z) {
        super(context, 16973839);
        this.mCancelable = true;
        this.message = str;
        this.btnLeftText = str2;
        this.btnRightText = str3;
        this.callback = iDialogCallBack;
        this.mCancelable = z;
    }

    private void initViews() {
        findViewById(R.id.panel_dialog_bg).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                if (PanelDialog.this.callback != null) {
                    PanelDialog.this.callback.onCallBack(RESULT_CODE.CANCEL);
                }
                PanelDialog.this.dismiss();
            }
        });
        ((TextView) findViewById(R.id.tv_dialog_content)).setText(this.message);
        if (!StringUtils.isEmpty(this.btnLeftText)) {
            Button button = (Button) findViewById(R.id.btn_dialog_left);
            button.setVisibility(0);
            button.setText(this.btnLeftText);
            button.setOnClickListener(new OnClickListener() {
                public void onClick(View view) {
                    if (PanelDialog.this.callback != null) {
                        PanelDialog.this.callback.onCallBack(RESULT_CODE.LEFT_CLICK);
                    }
                    PanelDialog.this.dismiss();
                }
            });
        }
        Button button2 = (Button) findViewById(R.id.btn_dialog_right);
        button2.setText(this.btnRightText);
        button2.setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                if (PanelDialog.this.callback != null) {
                    PanelDialog.this.callback.onCallBack(RESULT_CODE.RIGHT_CLICK);
                }
                PanelDialog.this.dismiss();
            }
        });
    }

    public void onBackPressed() {
        IDialogCallBack iDialogCallBack = this.callback;
        if (iDialogCallBack != null) {
            iDialogCallBack.onCallBack(RESULT_CODE.CANCEL);
        }
        super.onBackPressed();
    }
}