package com.nuvent.shareat.widget.view;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Paint.Style;
import android.graphics.RectF;
import android.view.View;
import com.naver.maps.map.NaverMap;
import java.util.ArrayList;

public class DrawGraph extends View {
    private static final int[] GRAPH_COLOR = {Color.parseColor("#ff648be9"), Color.parseColor("#ffE7E8ED")};
    private final int MAX_GRAPH_SIZE = 100;
    private ArrayList<Integer> graphList = new ArrayList<>();
    private int mCircleMargin = 0;
    private Paint mPaint = new Paint();

    public DrawGraph(Context context, ArrayList<Integer> data, int margin) {
        super(context);
        this.graphList = data;
        this.mCircleMargin = margin;
    }

    /* access modifiers changed from: protected */
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int x = getWidth();
        int y = getHeight();
        int n = this.graphList.size();
        float position = 90.0f;
        this.mPaint.setStyle(Style.FILL);
        this.mPaint.setFlags(1);
        RectF rect = new RectF(0.0f, 0.0f, (float) (x + 0), (float) (y + 0));
        for (int i = 0; i < n; i++) {
            this.mPaint.setColor(GRAPH_COLOR[i]);
            float graphValue = (float) ((this.graphList.get(i).intValue() * NaverMap.MAXIMUM_BEARING) / 100);
            canvas.drawArc(rect, position, graphValue, true, this.mPaint);
            position += graphValue;
        }
        this.mPaint.setColor(Color.parseColor("#ffffffff"));
        canvas.drawCircle((float) (x / 2), (float) (x / 2), (float) ((x / 2) - this.mCircleMargin), this.mPaint);
    }
}