package com.nuvent.shareat.dialog;

import android.content.Context;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import com.nuvent.shareat.R;
import net.xenix.util.ValidUtil;

public class InputConfirmDialog extends BaseDialog {
    private String mHintText;
    /* access modifiers changed from: private */
    public onOkClickListener mListener;
    private String mMessage;

    public interface onOkClickListener {
        void onClick(InputConfirmDialog inputConfirmDialog, String str);
    }

    public InputConfirmDialog(Context context) {
        super(context);
        init();
    }

    public InputConfirmDialog(Context context, String message, String hintText) {
        super(context);
        this.mMessage = message;
        this.mHintText = hintText;
        init();
    }

    private void init() {
        final View view = View.inflate(getContext(), R.layout.view_input_confirm_popup, null);
        Button okButton = (Button) view.findViewById(R.id.okButton);
        ((Button) view.findViewById(R.id.cancelButton)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                InputConfirmDialog.this.dismiss();
            }
        });
        okButton.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (InputConfirmDialog.this.mListener != null) {
                    InputConfirmDialog.this.mListener.onClick(InputConfirmDialog.this, ((EditText) view.findViewById(R.id.cardNameFlied)).getText().toString());
                }
            }
        });
        if (this.mMessage != null) {
            ((TextView) view.findViewById(R.id.messageLabel)).setText(this.mMessage);
            ((EditText) view.findViewById(R.id.cardNameFlied)).setText(this.mHintText);
            ((EditText) view.findViewById(R.id.cardNameFlied)).setSelection(this.mHintText.length());
            okButton.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    if (InputConfirmDialog.this.mListener != null) {
                        String email = ((EditText) view.findViewById(R.id.cardNameFlied)).getText().toString().trim();
                        if (!ValidUtil.isValidEmail(email)) {
                            Toast.makeText(InputConfirmDialog.this.getContext(), "\uc62c\ubc14\ub978 \uc774\uba54\uc77c\uc744 \uc785\ub825\ud574\uc8fc\uc138\uc694.", 0).show();
                            return;
                        }
                        InputConfirmDialog.this.mListener.onClick(InputConfirmDialog.this, email);
                        InputConfirmDialog.this.dismiss();
                    }
                }
            });
        }
        setContentView(view);
    }

    public void setOnOkClickListener(onOkClickListener listener) {
        this.mListener = listener;
    }
}