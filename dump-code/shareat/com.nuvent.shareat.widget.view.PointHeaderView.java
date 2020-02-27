package com.nuvent.shareat.widget.view;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.nuvent.shareat.R;

public class PointHeaderView extends FrameLayout {
    private Context mContext;

    public PointHeaderView(Context context) {
        super(context);
        init(context);
    }

    public PointHeaderView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public PointHeaderView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        this.mContext = context;
        View.inflate(context, R.layout.view_point_header, this);
    }

    public void setPointToBeExpired(String pointToBeExpired) {
        ((TextView) findViewById(R.id.pointToBeExpired)).setText(pointToBeExpired);
    }

    public void setPointTotalRemained(String pointTotalRemained) {
        ((TextView) findViewById(R.id.pointTotalRemained)).setText(pointTotalRemained);
    }
}