package com.igaworks.adbrix.cpe;

import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.os.CountDownTimer;
import android.support.v4.view.ViewCompat;
import android.view.Display;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;
import com.igaworks.core.IgawConstant;
import com.igaworks.util.IgawStyler;

public class CPEProgressBarHandler {
    /* access modifiers changed from: private */
    public static Toast popupToast;

    public static void makeToastPopup(Context context, String popupTitle, String popupMessage, int max, int current, int duration) {
        int custom_width;
        int custom_x;
        int custom_y;
        int alpha;
        int toast_duration;
        int title_gravity;
        Display display = ((WindowManager) context.getSystemService("window")).getDefaultDisplay();
        int width = display.getWidth();
        int height = display.getHeight();
        if (IgawStyler.toastPopup.toast_width == 0) {
            custom_width = (int) (((double) width) * 0.8d);
        } else {
            custom_width = (int) (((double) width) * ((double) IgawStyler.toastPopup.toast_width) * 0.01d);
        }
        if (IgawStyler.toastPopup.positionX == 0) {
            custom_x = 0;
        } else {
            custom_x = IgawStyler.toastPopup.positionX;
        }
        if (IgawStyler.toastPopup.positionY == 0) {
            custom_y = 30;
        } else {
            custom_y = IgawStyler.toastPopup.positionY;
        }
        if (IgawStyler.toastPopup.alpha == -1) {
            alpha = 50;
        } else {
            alpha = IgawStyler.toastPopup.alpha;
        }
        if (IgawStyler.toastPopup.toast_duration == 0) {
            toast_duration = duration;
        } else {
            toast_duration = IgawStyler.toastPopup.toast_duration - 3000;
            if (toast_duration <= 0) {
                toast_duration = 0;
            }
        }
        if (IgawStyler.toastPopup.title_gravity == 0) {
            title_gravity = 3;
        } else {
            title_gravity = IgawStyler.toastPopup.title_gravity;
        }
        if (IgawStyler.toastPopup.popup_message_height == 0) {
            int i = (int) (((double) height) * 0.15d);
        } else {
            int i2 = (int) (((double) height) * ((double) IgawStyler.toastPopup.popup_message_height) * 0.01d);
        }
        GradientDrawable gd = new GradientDrawable();
        gd.setShape(0);
        gd.setColor(ViewCompat.MEASURED_STATE_MASK);
        gd.setAlpha(alpha);
        gd.setSize(custom_width, -2);
        gd.setCornerRadius(5.0f);
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(1);
        LayoutParams layoutParams = new LayoutParams(custom_width, -2);
        linearLayout.setLayoutParams(layoutParams);
        linearLayout.setPadding(5, 5, 5, 5);
        GradientDrawable gd_toastLayout = new GradientDrawable();
        gd_toastLayout.setShape(0);
        gd_toastLayout.setColor(ViewCompat.MEASURED_STATE_MASK);
        gd_toastLayout.setAlpha(100);
        gd_toastLayout.setSize(custom_width, -2);
        gd_toastLayout.setCornerRadius(5.0f);
        linearLayout.setBackgroundDrawable(gd_toastLayout);
        if (popupTitle != null && popupTitle.length() > 0 && !popupTitle.equals("null")) {
            LinearLayout linearLayout2 = new LinearLayout(context);
            linearLayout2.setOrientation(1);
            LayoutParams layoutParams2 = new LayoutParams(custom_width, -2);
            linearLayout2.setPadding(3, 3, 3, 0);
            linearLayout2.setLayoutParams(layoutParams2);
            linearLayout2.setBackgroundDrawable(gd);
            LayoutParams layoutParams3 = new LayoutParams(custom_width, -2);
            TextView textView = new TextView(context);
            textView.setLayoutParams(layoutParams3);
            textView.setTextColor(-1);
            textView.setText(popupTitle);
            textView.setGravity(title_gravity | 16);
            textView.setPadding(5, 3, 5, 3);
            linearLayout2.addView(textView);
            ImageView border = new ImageView(context);
            border.setLayoutParams(new LayoutParams(custom_width, 1));
            border.setBackgroundColor(-7829368);
            linearLayout2.addView(border);
            linearLayout.addView(linearLayout2);
        }
        LinearLayout FirstLayer = new LinearLayout(context);
        FirstLayer.setOrientation(0);
        LayoutParams layoutParams4 = new LayoutParams(custom_width, -2);
        FirstLayer.setPadding(3, 3, 3, 3);
        FirstLayer.setLayoutParams(layoutParams4);
        FirstLayer.setBackgroundDrawable(gd);
        TextView ToastMessage = new TextView(context);
        LayoutParams layoutParams5 = new LayoutParams(-1, -2);
        ToastMessage.setBackgroundDrawable(gd);
        ToastMessage.setGravity(51);
        ToastMessage.setLayoutParams(layoutParams5);
        ToastMessage.setPadding(10, 10, 10, 10);
        ToastMessage.setTextColor(-1);
        ToastMessage.setText(popupMessage);
        FirstLayer.addView(ToastMessage);
        linearLayout.addView(FirstLayer);
        if (max > 1) {
            LinearLayout SecondLayer = new LinearLayout(context);
            LayoutParams layoutParams6 = new LayoutParams(custom_width, -2);
            SecondLayer.setLayoutParams(layoutParams6);
            SecondLayer.setPadding(0, 7, 0, 0);
            ProgressBar progressBar = new ProgressBar(context, null, 16842872);
            progressBar.setLayoutParams(layoutParams6);
            progressBar.setMax(max);
            progressBar.setProgress(current);
            SecondLayer.addView(progressBar);
            SecondLayer.setBackgroundDrawable(gd);
            linearLayout.addView(SecondLayer);
            IgawConstant atc = new IgawConstant();
            LayoutParams layoutParams7 = new LayoutParams(custom_width, -2);
            TextView textView2 = new TextView(context);
            textView2.setLayoutParams(layoutParams7);
            textView2.setPadding(0, 3, 0, 0);
            textView2.setTextColor(ViewCompat.MEASURED_STATE_MASK);
            textView2.setText(atc.process + ((current * 100) / max) + " %" + atc.complete);
            textView2.setGravity(5);
            linearLayout.addView(textView2);
        }
        if (popupToast == null) {
            Toast toast = new Toast(context);
            popupToast = toast;
            popupToast.setGravity(80, custom_x, custom_y);
        }
        popupToast.setView(linearLayout);
        popupToast.show();
        AnonymousClass1 r0 = new CountDownTimer((long) toast_duration, 100) {
            public void onTick(long millisUntilFinished) {
                CPEProgressBarHandler.popupToast.show();
            }

            public void onFinish() {
                CPEProgressBarHandler.popupToast.show();
            }
        };
        r0.start();
    }

    public static void setNotification(Context context, String title, String message) {
    }
}