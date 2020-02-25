package com.embrain.panelpower.views;

import android.app.Dialog;
import android.content.Context;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import androidx.annotation.NonNull;
import com.embrain.panelpower.R;
import com.embrain.panelpower.utils.ShareUtils;
import com.embrain.panelpower.utils.ShareUtils.SNSInfo;
import com.embrain.panelpower.vo.ShareInfo;
import java.util.ArrayList;

public class SharePopup extends Dialog {
    private static final int MAX_ROW_CNT = 4;
    public static final String PKG_EMAIL = "email";
    public static final String PKG_SMS = "sms";
    private OnClickListener mClick = new OnClickListener() {
        public void onClick(View view) {
            try {
                String str = (String) view.getTag();
                if (!ShareInfo.TYPE_RECOMMAND.equals(SharePopup.this.mInfo.type) || (!SharePopup.PKG_SMS.equals(str) && !"email".equals(str))) {
                    ShareUtils.shareSNS(SharePopup.this.getContext(), str, SharePopup.this.mInfo);
                    SharePopup.this.dismiss();
                }
                if (SharePopup.this.mListener != null) {
                    SharePopup.this.mListener.onClickBtn(str);
                }
                SharePopup.this.dismiss();
            } catch (Exception e) {
                e.printStackTrace();
            } catch (Throwable th) {
                SharePopup.this.dismiss();
                throw th;
            }
        }
    };
    private LayoutInflater mInflater;
    /* access modifiers changed from: private */
    public ShareInfo mInfo;
    /* access modifiers changed from: private */
    public OnShareClickListener mListener;

    public interface OnShareClickListener {
        void onClickBtn(String str);
    }

    public SharePopup(@NonNull Context context, ShareInfo shareInfo, OnShareClickListener onShareClickListener) {
        super(context);
        this.mListener = onShareClickListener;
        this.mInfo = shareInfo;
        getWindow().setBackgroundDrawable(new ColorDrawable(0));
        setCancelable(true);
        this.mInflater = getWindow().getLayoutInflater();
        setContentView(R.layout.dialog_share);
        LinearLayout linearLayout = (LinearLayout) findViewById(R.id.body_dialog);
        linearLayout.setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                SharePopup.this.dismiss();
            }
        });
        disposeShareBtns(linearLayout);
    }

    private void disposeShareBtns(LinearLayout linearLayout) {
        ArrayList<SNSInfo> arrayList = new ArrayList<>();
        arrayList.add(new SNSInfo(PKG_SMS, getContext().getDrawable(R.drawable.btn_share_8)));
        if (ShareInfo.TYPE_RECOMMAND.equals(this.mInfo.type)) {
            arrayList.add(new SNSInfo("email", getContext().getDrawable(R.drawable.btn_share_7)));
        }
        arrayList.addAll(ShareUtils.installedSNSList(getContext(), this.mInfo.type));
        LinearLayout row = getRow(getContext());
        linearLayout.addView(row);
        LinearLayout linearLayout2 = row;
        int i = 0;
        for (SNSInfo sNSInfo : arrayList) {
            if (i >= 4) {
                LinearLayout row2 = getRow(getContext());
                linearLayout.addView(row2);
                linearLayout2 = row2;
                i = 0;
            }
            linearLayout2.addView(getShareButton(sNSInfo.getDrawable(), sNSInfo.getPackageName()));
            i++;
        }
    }

    private LinearLayout getRow(Context context) {
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setLayoutParams(new LayoutParams(-1, -2));
        linearLayout.setPadding(0, 15, 0, 15);
        linearLayout.setGravity(17);
        return linearLayout;
    }

    private View getShareButton(Drawable drawable, String str) {
        int applyDimension = (int) TypedValue.applyDimension(1, 80.0f, getContext().getResources().getDisplayMetrics());
        ImageButton imageButton = (ImageButton) this.mInflater.inflate(R.layout.view_share_btn, null);
        imageButton.setLayoutParams(new LayoutParams(applyDimension, applyDimension));
        imageButton.setImageDrawable(drawable);
        imageButton.setClipToOutline(true);
        imageButton.setTag(str);
        imageButton.setOnClickListener(this.mClick);
        return imageButton;
    }
}