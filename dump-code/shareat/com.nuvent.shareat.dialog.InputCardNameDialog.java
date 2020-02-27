package com.nuvent.shareat.dialog;

import android.content.Context;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import com.nuvent.shareat.R;

public class InputCardNameDialog extends BaseDialog {
    /* access modifiers changed from: private */
    public onOkClickListener mListener;
    private String mMessage;

    public interface onOkClickListener {
        void onClick(InputCardNameDialog inputCardNameDialog, String str);
    }

    public InputCardNameDialog(Context context) {
        super(context);
        init();
    }

    public InputCardNameDialog(Context context, String message) {
        super(context);
        this.mMessage = message;
        init();
    }

    private void init() {
        final View view = View.inflate(getContext(), R.layout.view_input_card_name_confirm_popup, null);
        ((Button) view.findViewById(R.id.cancelButton)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                InputCardNameDialog.this.dismiss();
            }
        });
        ((Button) view.findViewById(R.id.okButton)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (InputCardNameDialog.this.mListener != null) {
                    InputCardNameDialog.this.mListener.onClick(InputCardNameDialog.this, ((EditText) view.findViewById(R.id.inputFlied)).getText().toString());
                }
            }
        });
        setContentView(view);
    }

    public void setOnOkClickListener(onOkClickListener listener) {
        this.mListener = listener;
    }
}