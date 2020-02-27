package com.nuvent.shareat.widget.view;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.store.ChartModel;
import java.util.ArrayList;

public class GraphView extends FrameLayout {
    private ChartModel mModel;

    public GraphView(Context context) {
        super(context);
        init();
    }

    public GraphView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public GraphView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        View.inflate(getContext(), R.layout.view_graph, this);
    }

    public void setModel(ChartModel model, int position) {
        this.mModel = model;
        ((TextView) findViewById(R.id.menuNameLabel)).setText(this.mModel.getMenu_name());
        ((TextView) findViewById(R.id.rankLabel)).setText(String.valueOf(position + 1));
        ArrayList<Integer> sizeList = new ArrayList<>();
        sizeList.add(Integer.valueOf(model.getMenu_per()));
        sizeList.add(Integer.valueOf(100 - model.getMenu_per()));
        ((ViewGroup) findViewById(R.id.graphLayout)).addView(new DrawGraph(getContext(), sizeList, getResources().getDimensionPixelOffset(R.dimen.GRAPH_MARGIN)));
    }
}