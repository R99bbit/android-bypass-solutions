package com.nuvent.shareat.widget.view;

import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.view.View;

public class CustomClickableSpan extends ClickableSpan {
    private OnSpanClick onSpanClick;
    private String text;

    public interface OnSpanClick {
        void onClick(String str);
    }

    public CustomClickableSpan(String text2, OnSpanClick onSpanClick2) {
        this.onSpanClick = onSpanClick2;
        this.text = text2;
    }

    public void onClick(View widget) {
        this.onSpanClick.onClick(this.text);
    }

    public void updateDrawState(TextPaint ds) {
        ds.setUnderlineText(false);
    }
}