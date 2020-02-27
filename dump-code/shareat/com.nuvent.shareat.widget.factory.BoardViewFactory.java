package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.view.View;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.BoardModel;

public class BoardViewFactory {
    public static View createView(Context context, BoardModel model) {
        return View.inflate(context, R.layout.cell_search_hash, null);
    }
}