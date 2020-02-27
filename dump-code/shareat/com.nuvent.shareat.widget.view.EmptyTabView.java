package com.nuvent.shareat.widget.view;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup.LayoutParams;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import com.nuvent.shareat.R;

public class EmptyTabView extends FrameLayout {
    public EmptyTabView(Context context) {
        super(context);
        init(context);
    }

    public EmptyTabView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public EmptyTabView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        View.inflate(context, R.layout.view_tab_empty, this);
    }

    public void setSize(int size) {
        LinearLayout footerLayout = (LinearLayout) findViewById(R.id.footerLayout);
        LayoutParams params = footerLayout.getLayoutParams();
        params.height = size;
        footerLayout.setLayoutParams(params);
    }
}