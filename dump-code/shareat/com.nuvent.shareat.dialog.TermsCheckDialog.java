package com.nuvent.shareat.dialog;

import android.content.Context;
import android.view.View;
import android.view.View.OnClickListener;
import com.nuvent.shareat.R;
import com.nuvent.shareat.api.ApiUrl;

public class TermsCheckDialog extends BaseDialog implements OnClickListener {
    private boolean isAllCheck;
    private View mContentView;
    private Context mContext;
    private DialogClickListener mListener;

    public interface DialogClickListener {
        void onAgreed();

        void unCheck();
    }

    public TermsCheckDialog(Context context, boolean isAllCheck2) {
        super(context);
        this.mContext = context;
        setCanceledOnTouchOutside(true);
        this.isAllCheck = isAllCheck2;
        init();
    }

    private void init() {
        this.mContentView = View.inflate(getContext(), R.layout.dialog_terms_check, null);
        this.mContentView.findViewById(R.id.termsAgreedButton01).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsAgreedButton02).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsAgreedButton03).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsAgreedButton04).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsAgreedButton05).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsButton01).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsButton02).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsButton03).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsButton04).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsButton05).setOnClickListener(this);
        this.mContentView.findViewById(R.id.termsAllCheckButton).setOnClickListener(this);
        allCheckButton(this.isAllCheck);
        setContentView(this.mContentView);
    }

    public void onClick(View v) {
        boolean z;
        boolean z2 = true;
        switch (v.getId()) {
            case R.id.termsAgreedButton01 /*2131297383*/:
            case R.id.termsAgreedButton02 /*2131297384*/:
            case R.id.termsAgreedButton03 /*2131297385*/:
            case R.id.termsAgreedButton04 /*2131297386*/:
            case R.id.termsAgreedButton05 /*2131297387*/:
                if (!v.isSelected()) {
                    z = true;
                } else {
                    z = false;
                }
                v.setSelected(z);
                if (checkButton()) {
                    findViewById(R.id.termsAllCheckButton).setSelected(true);
                    this.mListener.onAgreed();
                    dismiss();
                    return;
                }
                findViewById(R.id.termsAllCheckButton).setSelected(false);
                this.mListener.unCheck();
                return;
            case R.id.termsAllCheckButton /*2131297391*/:
                if (v.isSelected()) {
                    z2 = false;
                }
                allCheckButton(z2);
                if (checkButton()) {
                    this.mListener.onAgreed();
                    dismiss();
                    return;
                }
                this.mListener.unCheck();
                return;
            case R.id.termsButton01 /*2131297393*/:
                new TermsDialog(getContext(), ApiUrl.TERMS_PAY_01, false).show();
                return;
            case R.id.termsButton02 /*2131297394*/:
                new TermsDialog(getContext(), ApiUrl.TERMS_PAY_02, false).show();
                return;
            case R.id.termsButton03 /*2131297395*/:
                new TermsDialog(getContext(), ApiUrl.TERMS_PAY_03, false).show();
                return;
            case R.id.termsButton04 /*2131297396*/:
                new TermsDialog(getContext(), ApiUrl.TERMS_PAY_04, false).show();
                return;
            case R.id.termsButton05 /*2131297397*/:
                new TermsDialog(getContext(), ApiUrl.TERMS_PAY_05, false).show();
                return;
            default:
                return;
        }
    }

    private void allCheckButton(boolean isAllCheck2) {
        this.mContentView.findViewById(R.id.termsAgreedButton01).setSelected(isAllCheck2);
        this.mContentView.findViewById(R.id.termsAgreedButton02).setSelected(isAllCheck2);
        this.mContentView.findViewById(R.id.termsAgreedButton03).setSelected(isAllCheck2);
        this.mContentView.findViewById(R.id.termsAgreedButton04).setSelected(isAllCheck2);
        this.mContentView.findViewById(R.id.termsAgreedButton05).setSelected(isAllCheck2);
        this.mContentView.findViewById(R.id.termsAllCheckButton).setSelected(isAllCheck2);
    }

    private boolean checkButton() {
        if (!this.mContentView.findViewById(R.id.termsAgreedButton01).isSelected() || !this.mContentView.findViewById(R.id.termsAgreedButton02).isSelected() || !this.mContentView.findViewById(R.id.termsAgreedButton03).isSelected() || !this.mContentView.findViewById(R.id.termsAgreedButton04).isSelected() || !this.mContentView.findViewById(R.id.termsAgreedButton05).isSelected()) {
            return false;
        }
        return true;
    }

    public void setOnDialogClickListener(DialogClickListener listener) {
        this.mListener = listener;
    }
}