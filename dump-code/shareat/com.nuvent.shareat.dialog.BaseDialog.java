package com.nuvent.shareat.dialog;

import android.app.Dialog;
import android.content.Context;
import com.nuvent.shareat.R;

public abstract class BaseDialog extends Dialog {
    public BaseDialog(Context context) {
        super(context, R.style.DimDialog);
        setCanceledOnTouchOutside(false);
    }

    public BaseDialog(Context context, boolean isDim) {
        super(context, isDim ? R.style.DimDialog : R.style.Dialog);
        setCanceledOnTouchOutside(false);
    }
}