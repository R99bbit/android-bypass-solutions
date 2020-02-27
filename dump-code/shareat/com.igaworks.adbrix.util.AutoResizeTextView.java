package com.igaworks.adbrix.util;

import android.content.Context;
import android.graphics.Paint.FontMetrics;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.View.MeasureSpec;
import android.widget.TextView;

public class AutoResizeTextView extends TextView {
    private float maxTextSize;
    private float minTextSize;

    public AutoResizeTextView(Context context) {
        super(context);
        init();
    }

    public AutoResizeTextView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    private void init() {
        this.maxTextSize = getTextSize();
        if (this.maxTextSize < 50.0f) {
            this.maxTextSize = 50.0f;
        }
        this.minTextSize = 10.0f;
    }

    private void refitText(String text, int textWidth, int textHeight) {
        if (textWidth > 0) {
            String[] splitted = text.split("\n");
            if (splitted == null || splitted.length <= 0) {
                int availableWidth = (textWidth - getPaddingLeft()) - getPaddingRight();
                float trySize = this.maxTextSize;
                setTextSize(0, trySize);
                while (true) {
                    if (trySize <= this.minTextSize || getPaint().measureText(text) <= ((float) availableWidth)) {
                        break;
                    }
                    trySize -= 1.0f;
                    if (trySize <= this.minTextSize) {
                        trySize = this.minTextSize;
                        break;
                    }
                    setTextSize(0, trySize);
                }
                setTextSize(0, trySize);
                return;
            }
            String maxLenStr = splitted[0];
            for (String item : splitted) {
                if (maxLenStr.length() < item.length()) {
                    maxLenStr = item;
                }
            }
            int availableWidth2 = (textWidth - getPaddingLeft()) - getPaddingRight();
            int availableHeight = (textHeight - getPaddingBottom()) - getPaddingTop();
            float trySize2 = this.maxTextSize;
            setTextSize(0, trySize2);
            getPaint().getTextBounds(text, 0, text.length(), new Rect());
            FontMetrics fm = getPaint().getFontMetrics();
            float abs = Math.abs((fm.top - fm.bottom) * ((float) splitted.length));
            while (true) {
                int h = (int) abs;
                if (trySize2 <= this.minTextSize || (getPaint().measureText(maxLenStr) <= ((float) availableWidth2) && h <= availableHeight)) {
                    break;
                }
                trySize2 -= 1.0f;
                if (trySize2 <= this.minTextSize) {
                    trySize2 = this.minTextSize;
                    break;
                }
                setTextSize(0, trySize2);
                FontMetrics fm2 = getPaint().getFontMetrics();
                abs = Math.abs((fm2.top - fm2.bottom) * ((float) splitted.length));
            }
            setTextSize(0, trySize2);
        }
    }

    /* access modifiers changed from: protected */
    public void onTextChanged(CharSequence text, int start, int before, int after) {
        refitText(text.toString(), getWidth(), getHeight());
    }

    /* access modifiers changed from: protected */
    public void onSizeChanged(int w, int h, int oldw, int oldh) {
        if (w != oldw) {
            refitText(getText().toString(), w, h);
        }
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        refitText(getText().toString(), MeasureSpec.getSize(widthMeasureSpec), MeasureSpec.getSize(heightMeasureSpec));
    }

    public float getMinTextSize() {
        return this.minTextSize;
    }

    public void setMinTextSize(int minTextSize2) {
        this.minTextSize = (float) minTextSize2;
    }

    public float getMaxTextSize() {
        return this.maxTextSize;
    }

    public void setMaxTextSize(int minTextSize2) {
        this.maxTextSize = (float) minTextSize2;
    }
}