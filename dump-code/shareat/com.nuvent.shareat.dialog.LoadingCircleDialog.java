package com.nuvent.shareat.dialog;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import com.nuvent.shareat.R;

public class LoadingCircleDialog extends BaseDialog {
    public LoadingCircleDialog(Context context) {
        super(context);
        View view = View.inflate(context, R.layout.dialog_loading_circle, null);
        requestWindowFeature(1);
        setCanceledOnTouchOutside(false);
        setContentView(view);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
}