package com.nuvent.shareat.dialog;

import android.content.Context;
import android.view.View;
import android.view.View.OnClickListener;
import android.webkit.WebView;
import android.widget.ImageButton;
import com.nuvent.shareat.R;

public class TermsDialog extends BaseDialog implements OnClickListener {
    private ImageButton mCloseButton;
    private String mUrl;

    public TermsDialog(Context context, String url, boolean isDim) {
        super(context, isDim);
        this.mUrl = url;
        init();
    }

    public TermsDialog(Context context, String url) {
        super(context);
        this.mUrl = url;
        init();
    }

    private void init() {
        View view = View.inflate(getContext(), R.layout.view_web_popup, null);
        this.mCloseButton = (ImageButton) view.findViewById(R.id.close);
        this.mCloseButton.setOnClickListener(this);
        this.mUrl = this.mUrl.replace("https://", "http://");
        ((WebView) view.findViewById(R.id.web)).loadUrl(this.mUrl);
        setContentView(view);
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.close /*2131296489*/:
                dismiss();
                return;
            default:
                return;
        }
    }
}