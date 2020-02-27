package com.nuvent.shareat.dialog;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import com.nuvent.shareat.R;

public class LoadingDialog extends BaseDialog {
    public LoadingDialog(Context context) {
        super(context, false);
        View view = View.inflate(context, R.layout.dialog_loading, null);
        requestWindowFeature(1);
        setCanceledOnTouchOutside(false);
        setContentView(view);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
}